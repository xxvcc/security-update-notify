// Package releasepkg builds the signed, reproducible release set used by the
// security-update-notify bootstrap installer.
package releasepkg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/xxvcc/security-update-notify/internal/assets"
	versionpkg "github.com/xxvcc/security-update-notify/internal/version"
)

const (
	productName                    = "security-update-notify"
	bootstrapSignatureName         = "sun.sh.asc"
	bootstrapVersionNotation       = "release-version@xxv.cc"
	maxBootstrapSize         int64 = 1 << 20
	maxUncompressedSize      int64 = 256 << 20
	maxVersionFileSize       int64 = 256
)

var (
	versionPattern     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[._-][0-9A-Za-z]+)?$`)
	versionFilePattern = regexp.MustCompile(`\AVERSION="([^"\r\n]{1,64})"\n\z`)
	officialArches     = [...]string{"amd64", "arm64", "386", "ppc64le", "s390x"}
)

// SignMode controls detached GPG signature creation.
type SignMode string

const (
	// SignAuto signs when the pinned secret key exists and requires a signature
	// for an explicit release or an existing version tag.
	SignAuto SignMode = "auto"
	// SignRequired fails unless the pinned secret key can sign and verify.
	SignRequired SignMode = "required"
	// SignOff deliberately produces an unsigned, non-official local release set.
	SignOff SignMode = "off"
)

// Options describes one release build. SourceDateEpoch must be set when a
// dirty worktree is explicitly allowed.
type Options struct {
	Root    string
	DistDir string
	// Version is an optional compatibility assertion. The canonical version is
	// always read from Root/VERSION and a non-empty assertion must match it.
	Version         string
	SourceDateEpoch *int64
	AllowDirty      bool
	Release         bool
	Sign            SignMode
	GPGKeyID        string
	GPGHome         string
	Stdout          io.Writer
	Stderr          io.Writer
}

// Result is the committed release asset set.
type Result struct {
	Tarball            string
	Checksum           string
	Signature          string
	BootstrapSignature string
	SHA256             string
	Version            string
	Epoch              int64
	Signed             bool
	Official           bool
	Architectures      []string
}

// Architectures returns a copy of the non-overridable official architecture
// set. Release packages always contain exactly these five Linux binaries.
func Architectures() []string {
	return append([]string(nil), officialArches[:]...)
}

// ParseSignMode accepts the historical shell spellings while exposing only
// three well-defined states to the packager.
func ParseSignMode(v string) (SignMode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return SignAuto, nil
	case "required", "1", "true", "yes":
		return SignRequired, nil
	case "off", "0", "false", "no":
		return SignOff, nil
	default:
		return "", fmt.Errorf("invalid signing mode %q", v)
	}
}

// ValidateVersion applies the release filename and tag grammar. It is stricter
// than the update-check grammar because release assets must be unambiguous.
func ValidateVersion(version string) error {
	if len(version) == 0 || len(version) > 64 || !versionPattern.MatchString(version) {
		return fmt.Errorf("invalid version %q", version)
	}
	if _, err := versionpkg.Compare(version, version); err != nil {
		return fmt.Errorf("invalid version %q", version)
	}
	return nil
}

// ReadVersion reads the canonical repository VERSION file. The file must be a
// regular, non-symlink file containing exactly VERSION="X.Y.Z" plus one final
// newline; no whitespace, comments, or additional lines are accepted.
func ReadVersion(root string) (string, error) {
	if root == "" {
		root = "."
	}
	path := filepath.Join(root, "VERSION")
	file, info, err := openBoundedRegular(path, maxVersionFileSize, true)
	if err != nil {
		return "", fmt.Errorf("canonical VERSION: %w", err)
	}
	defer file.Close()
	b, err := readOpenedRegular(file, info, maxVersionFileSize)
	if err != nil {
		return "", fmt.Errorf("read canonical VERSION: %w", err)
	}
	if err := validateOpenedRegularPath(path, info); err != nil {
		return "", fmt.Errorf("canonical VERSION: %w", err)
	}
	match := versionFilePattern.FindSubmatch(b)
	if match == nil {
		return "", errors.New(`canonical VERSION must contain exactly one line in the form VERSION="X.Y.Z" with a final newline`)
	}
	version := string(match[1])
	if err := ValidateVersion(version); err != nil {
		return "", fmt.Errorf("canonical VERSION: %w", err)
	}
	return version, nil
}

// Build validates the source tree, builds all official binaries, creates a
// deterministic archive and checksum, optionally signs it, then commits the
// complete asset set to DistDir. Work is staged under DistDir so failures do
// not expose partially generated release assets.
func Build(ctx context.Context, opts Options) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	mode, err := ParseSignMode(string(opts.Sign))
	if err != nil {
		return Result{}, err
	}

	root := opts.Root
	if root == "" {
		root = "."
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return Result{}, fmt.Errorf("resolve repository root: %w", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil || !rootInfo.IsDir() {
		if err == nil {
			err = errors.New("not a directory")
		}
		return Result{}, fmt.Errorf("repository root %q: %w", root, err)
	}
	canonicalVersion, err := ReadVersion(root)
	if err != nil {
		return Result{}, err
	}
	if opts.Version != "" {
		if err := ValidateVersion(opts.Version); err != nil {
			return Result{}, fmt.Errorf("version assertion: %w", err)
		}
		if opts.Version != canonicalVersion {
			return Result{}, fmt.Errorf("version assertion %q does not match canonical VERSION %q", opts.Version, canonicalVersion)
		}
	}
	opts.Version = canonicalVersion

	distDir := opts.DistDir
	if distDir == "" {
		distDir = filepath.Join(root, "dist")
	} else if !filepath.IsAbs(distDir) {
		distDir = filepath.Join(root, distDir)
	}
	distDir, err = filepath.Abs(distDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve dist directory: %w", err)
	}

	stdout := opts.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = io.Discard
	}

	sourceState, err := captureReleaseSourceState(ctx, root, opts.Version)
	if err != nil {
		return Result{}, err
	}
	if err := validateSources(root, opts.Version); err != nil {
		return Result{}, err
	}
	if err := checkSunSyntax(ctx, root); err != nil {
		return Result{}, err
	}

	repo := sourceState.repository
	official := opts.Release || repo.TagExists
	if official && mode == SignOff {
		return Result{}, errors.New("official releases cannot disable signing")
	}
	if repo.Dirty && (!opts.AllowDirty || opts.SourceDateEpoch == nil) {
		return Result{}, fmt.Errorf("release sources have uncommitted or untracked changes (%q); allow-dirty also requires an explicit source-date-epoch", repo.DirtyFiles)
	}
	if repo.Dirty {
		fmt.Fprintln(stderr, "WARNING: packaging dirty release sources with an explicit SOURCE_DATE_EPOCH")
	}

	epoch, err := resolveEpoch(ctx, root, opts.Version, opts.SourceDateEpoch, repo)
	if err != nil {
		return Result{}, err
	}
	if mode == SignAuto && official {
		mode = SignRequired
	}

	if err := os.MkdirAll(distDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create dist directory: %w", err)
	}
	pkgName := productName + "-" + opts.Version
	tarName := pkgName + ".tar.gz"
	finalTar := filepath.Join(distDir, tarName)
	finalSHA := finalTar + ".sha256"
	finalSig := finalTar + ".asc"
	finalBootstrapSig := filepath.Join(distDir, bootstrapSignatureName)
	stage, err := os.MkdirTemp(distDir, ".sun-release-")
	if err != nil {
		return Result{}, fmt.Errorf("create release staging directory: %w", err)
	}
	defer os.RemoveAll(stage)

	pkgDir := filepath.Join(stage, pkgName)
	if err := preparePackageTree(root, pkgDir, opts.Version); err != nil {
		return Result{}, err
	}
	if err := buildAllBinaries(ctx, root, pkgDir, opts.Version, stdout, stderr); err != nil {
		return Result{}, err
	}
	if err := validatePackageTree(pkgDir, opts.Version); err != nil {
		return Result{}, err
	}

	stageTar := filepath.Join(stage, tarName)
	if err := writeDeterministicArchive(stageTar, pkgDir, pkgName, epoch); err != nil {
		return Result{}, err
	}
	digest, err := fileSHA256(stageTar)
	if err != nil {
		return Result{}, err
	}
	stageSHA := stageTar + ".sha256"
	if err := writeExclusiveRegular(stageSHA, []byte(digest+"  "+tarName+"\n"), 0o644); err != nil {
		return Result{}, fmt.Errorf("write checksum: %w", err)
	}
	if err := verifyReleaseSourceState(ctx, root, opts.Version, sourceState); err != nil {
		return Result{}, err
	}

	stageSig := stageTar + ".asc"
	signed, err := maybeSign(ctx, signOptions{
		Mode: mode, GPGKeyID: opts.GPGKeyID, GPGHome: opts.GPGHome,
		PinnedFingerprint: assets.ReleaseSigningFingerprint,
		TrustedPublicKey:  assets.ReleaseSigningPublicKey(),
	}, stageTar, stageSig)
	if err != nil {
		return Result{}, err
	}
	stageBootstrapSig := filepath.Join(stage, bootstrapSignatureName)
	if signed {
		if err := validateStagedArchiveAndChecksum(stageTar, stageSHA, tarName, digest); err != nil {
			return Result{}, err
		}
		bootstrapMember := pkgName + "/sun.sh"
		bootstrapBytes, err := readArchiveRegularFile(stageTar, bootstrapMember, maxBootstrapSize)
		if err != nil {
			return Result{}, fmt.Errorf("read archived first-install bootstrap: %w", err)
		}
		archivedBootstrap := filepath.Join(stage, ".archived-sun.sh")
		if err := writeExclusiveRegular(archivedBootstrap, bootstrapBytes, 0o600); err != nil {
			return Result{}, fmt.Errorf("stage archived first-install bootstrap: %w", err)
		}
		bootstrapSigned, err := maybeSign(ctx, signOptions{
			Mode: SignRequired, GPGKeyID: opts.GPGKeyID, GPGHome: opts.GPGHome,
			PinnedFingerprint: assets.ReleaseSigningFingerprint,
			TrustedPublicKey:  assets.ReleaseSigningPublicKey(),
			NotationName:      bootstrapVersionNotation,
			NotationValue:     opts.Version,
		}, archivedBootstrap, stageBootstrapSig)
		if err != nil {
			return Result{}, fmt.Errorf("sign first-install bootstrap: %w", err)
		}
		if !bootstrapSigned {
			return Result{}, errors.New("sign first-install bootstrap: required signature was not created")
		}
	}
	artifactSpecs := []stagedArtifactSpec{
		{path: stageTar, maxSize: maxUncompressedSize},
		{path: stageSHA, maxSize: maxReleaseSignatureBytes},
	}
	if signed {
		artifactSpecs = append(artifactSpecs,
			stagedArtifactSpec{path: stageSig, maxSize: maxReleaseSignatureBytes},
			stagedArtifactSpec{path: stageBootstrapSig, maxSize: maxReleaseSignatureBytes},
		)
	}
	artifactStates, err := captureStagedArtifactStates(artifactSpecs)
	if err != nil {
		return Result{}, err
	}
	if err := validateStagedArchiveAndChecksum(stageTar, stageSHA, tarName, digest); err != nil {
		return Result{}, err
	}

	if err := commitArtifacts(
		ctx,
		stageTar, stageSHA, stageSig, stageBootstrapSig,
		finalTar, finalSHA, finalSig, finalBootstrapSig,
		signed,
		func() error {
			// Signing reads only staged bytes. Revalidating after the commit lock is
			// acquired also rejects source or Git drift during signing or lock wait.
			if err := verifyReleaseSourceState(ctx, root, opts.Version, sourceState); err != nil {
				return err
			}
			if err := verifyStagedArtifactStates(artifactStates); err != nil {
				return err
			}
			return validateStagedArchiveAndChecksum(stageTar, stageSHA, tarName, digest)
		},
	); err != nil {
		return Result{}, err
	}

	result := Result{
		Tarball:       finalTar,
		Checksum:      finalSHA,
		SHA256:        digest,
		Version:       opts.Version,
		Epoch:         epoch,
		Signed:        signed,
		Official:      official,
		Architectures: Architectures(),
	}
	if signed {
		result.Signature = finalSig
		result.BootstrapSignature = finalBootstrapSig
	}
	return result, nil
}

type stagedArtifactSpec struct {
	path    string
	maxSize int64
}

type stagedArtifactState struct {
	stagedArtifactSpec
	state regularFileState
}

func captureStagedArtifactStates(specs []stagedArtifactSpec) ([]stagedArtifactState, error) {
	states := make([]stagedArtifactState, 0, len(specs))
	for _, spec := range specs {
		state, err := captureRegularFileState(spec.path, spec.maxSize)
		if err != nil {
			return nil, fmt.Errorf("capture staged artifact %s: %w", filepath.Base(spec.path), err)
		}
		states = append(states, stagedArtifactState{stagedArtifactSpec: spec, state: state})
	}
	return states, nil
}

func verifyStagedArtifactStates(states []stagedArtifactState) error {
	for _, artifact := range states {
		if err := verifyRegularFileState(artifact.path, artifact.state, artifact.maxSize); err != nil {
			return fmt.Errorf("staged artifact %s changed before commit: %w", filepath.Base(artifact.path), err)
		}
	}
	return nil
}

func validateStagedArchiveAndChecksum(archive, checksum, archiveName, digest string) error {
	state, err := captureRegularFileState(archive, maxUncompressedSize)
	if err != nil {
		return fmt.Errorf("validate staged archive: %w", err)
	}
	if got := hex.EncodeToString(state.digest[:]); got != digest {
		return fmt.Errorf("staged archive changed after checksum creation")
	}
	checksumBytes, err := readBoundedRegularPath(checksum, maxReleaseSignatureBytes, true)
	if err != nil {
		return fmt.Errorf("validate staged checksum: %w", err)
	}
	if string(checksumBytes) != digest+"  "+archiveName+"\n" {
		return fmt.Errorf("staged checksum changed after creation")
	}
	return nil
}

func validateSources(root, version string) error {
	for _, spec := range releaseFiles {
		if err := validateRegularSource(filepath.Join(root, filepath.FromSlash(spec.Source))); err != nil {
			return fmt.Errorf("required release source %s: %w", spec.Source, err)
		}
	}

	changelog, err := readBoundedRegularPath(filepath.Join(root, "CHANGELOG.md"), maxUncompressedSize, true)
	if err != nil {
		return fmt.Errorf("read CHANGELOG.md: %w", err)
	}
	want := "## " + version
	count := 0
	s := bufio.NewScanner(bytes.NewReader(changelog))
	for s.Scan() {
		if s.Text() == want {
			count++
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read CHANGELOG.md: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("CHANGELOG.md must contain exactly one %q heading (found %d)", want, count)
	}
	if err := validateEmbeddedAssetCopies(root); err != nil {
		return err
	}
	if err := validateBootstrapFingerprint(root); err != nil {
		return err
	}
	return nil
}

func validateEmbeddedAssetCopies(root string) error {
	checks := []struct {
		path string
		want []byte
	}{
		{"files/release-signing.pub.asc", assets.ReleaseSigningPublicKey()},
		{"files/security-update-notify.service", assets.SystemdServiceUnit()},
		{"files/needrestart-report-only.conf", assets.NeedrestartConf()},
		{"files/security-update-notify.logrotate", assets.LogrotateConf()},
	}
	for _, check := range checks {
		got, err := readBoundedRegularPath(filepath.Join(root, filepath.FromSlash(check.path)), maxUncompressedSize, true)
		if err != nil {
			return fmt.Errorf("read managed asset %s: %w", check.path, err)
		}
		if !bytes.Equal(got, check.want) {
			return fmt.Errorf("managed asset %s differs from its Go-embedded copy", check.path)
		}
	}
	return nil
}

func validateBootstrapFingerprint(root string) error {
	b, err := readBoundedRegularPath(filepath.Join(root, "sun.sh"), maxUncompressedSize, true)
	if err != nil {
		return fmt.Errorf("read sun.sh: %w", err)
	}
	prefix := `RELEASE_SIGNING_FINGERPRINT="`
	var fingerprints []string
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, `"`) {
			fingerprints = append(fingerprints, strings.TrimSuffix(strings.TrimPrefix(line, prefix), `"`))
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read sun.sh fingerprint: %w", err)
	}
	if len(fingerprints) != 1 || fingerprints[0] != assets.ReleaseSigningFingerprint {
		return fmt.Errorf("sun.sh must contain exactly one pinned release fingerprint %s", assets.ReleaseSigningFingerprint)
	}
	signatureAssets, err := bootstrapMetadataValues(b, "BOOTSTRAP_SIGNATURE_ASSET")
	if err != nil {
		return err
	}
	if len(signatureAssets) != 1 || signatureAssets[0] != bootstrapSignatureName {
		return fmt.Errorf("sun.sh must declare exactly one bootstrap signature asset %s", bootstrapSignatureName)
	}
	versionNotations, err := bootstrapMetadataValues(b, "BOOTSTRAP_VERSION_NOTATION")
	if err != nil {
		return err
	}
	if len(versionNotations) != 1 || versionNotations[0] != bootstrapVersionNotation {
		return fmt.Errorf("sun.sh must declare exactly one bootstrap version notation %s", bootstrapVersionNotation)
	}
	const keyStart = "release_signing_public_key() {\n  cat <<'EOF'\n"
	const keyEnd = "EOF\n}\n"
	if bytes.Count(b, []byte(keyStart)) != 1 {
		return errors.New("sun.sh must contain exactly one structured release public-key block")
	}
	start := bytes.Index(b, []byte(keyStart)) + len(keyStart)
	relativeEnd := bytes.Index(b[start:], []byte(keyEnd))
	if relativeEnd < 0 {
		return errors.New("sun.sh release public-key block is unterminated")
	}
	end := start + relativeEnd
	if !bytes.Equal(b[start:end], assets.ReleaseSigningPublicKey()) {
		return errors.New("sun.sh release public key differs from its Go-embedded copy")
	}
	return nil
}

func bootstrapMetadataValues(script []byte, name string) ([]string, error) {
	prefix := name + `="`
	var values []string
	s := bufio.NewScanner(bytes.NewReader(script))
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, `"`) {
			values = append(values, strings.TrimSuffix(strings.TrimPrefix(line, prefix), `"`))
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read sun.sh %s: %w", name, err)
	}
	return values, nil
}

func fileSHA256(path string) (string, error) {
	state, err := captureRegularFileState(path, maxUncompressedSize)
	if err != nil {
		return "", fmt.Errorf("open archive for checksum: %w", err)
	}
	return hex.EncodeToString(state.digest[:]), nil
}

func commitArtifacts(
	ctx context.Context,
	stageTar, stageSHA, stageSig, stageBootstrapSig string,
	finalTar, finalSHA, finalSig, finalBootstrapSig string,
	signed bool,
	beforeCommit func() error,
) error {
	if err := validateArtifactCommitPaths(
		stageTar, stageSHA, stageSig, stageBootstrapSig,
		finalTar, finalSHA, finalSig, finalBootstrapSig,
		signed,
	); err != nil {
		return err
	}
	distDir := filepath.Clean(filepath.Dir(finalTar))
	for _, target := range []string{finalSHA, finalSig, finalBootstrapSig} {
		if filepath.Clean(filepath.Dir(target)) != distDir {
			return errors.New("release artifact targets must share one output directory")
		}
	}
	return withReleaseCommitLock(ctx, distDir, func(directory *os.File) error {
		if beforeCommit != nil {
			if err := beforeCommit(); err != nil {
				return err
			}
		}
		return commitArtifactsUnlockedAt(
			directory,
			stageTar, stageSHA, stageSig, stageBootstrapSig,
			finalTar, finalSHA, finalSig, finalBootstrapSig,
			signed,
		)
	})
}

type stagedCommitFile struct {
	parent      *os.File
	name        string
	destination string
	state       regularFileState
}

func commitArtifactsUnlockedAt(
	directory *os.File,
	stageTar, stageSHA, stageSig, stageBootstrapSig string,
	finalTar, finalSHA, finalSig, finalBootstrapSig string,
	signed bool,
) (returnErr error) {
	if err := validateArtifactCommitPaths(
		stageTar, stageSHA, stageSig, stageBootstrapSig,
		finalTar, finalSHA, finalSig, finalBootstrapSig,
		signed,
	); err != nil {
		return err
	}
	pairs := [][2]string{{stageTar, finalTar}, {stageSHA, finalSHA}}
	if signed {
		pairs = append(pairs, [2]string{stageSig, finalSig}, [2]string{stageBootstrapSig, finalBootstrapSig})
	}
	staged := make([]stagedCommitFile, 0, len(pairs))
	for _, pair := range pairs {
		parent, err := openPackageDirectory(filepath.Dir(pair[0]))
		if err != nil {
			return fmt.Errorf("preflight release artifact %s: %w", filepath.Base(pair[1]), err)
		}
		path := directoryEntryPathForRelease(parent, filepath.Base(pair[0]))
		state, err := captureRegularFileState(path, 0)
		if err != nil {
			_ = parent.Close()
			for _, file := range staged {
				_ = file.parent.Close()
			}
			return fmt.Errorf("preflight release artifact %s: %w", filepath.Base(pair[1]), err)
		}
		staged = append(staged, stagedCommitFile{
			parent: parent, name: filepath.Base(pair[0]), destination: filepath.Base(pair[1]), state: state,
		})
	}
	defer func() {
		for _, file := range staged {
			_ = file.parent.Close()
		}
	}()

	distDir := filepath.Dir(finalTar)
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("inspect release recovery directories: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sun-commit-backup-") {
			return fmt.Errorf("unfinished release commit requires manual recovery: %s", entry.Name())
		}
	}
	// Keep recovery data outside the per-build staging directory. Build removes
	// staging on every ordinary return, including a failed rollback.
	backupDir, err := os.MkdirTemp(directoryDescriptorPath(directory), ".sun-commit-backup-")
	if err != nil {
		return fmt.Errorf("create release commit backup: %w", err)
	}
	backupName := filepath.Base(backupDir)
	backupDirectory, err := openPackageDirectory(backupDir)
	if err != nil {
		_ = os.RemoveAll(backupDir)
		return fmt.Errorf("open release commit backup: %w", err)
	}
	defer backupDirectory.Close()
	removeBackup := true
	defer func() {
		if !removeBackup {
			return
		}
		if err := os.RemoveAll(directoryEntryPathForRelease(directory, backupName)); err != nil {
			cleanupErr := fmt.Errorf("remove release commit backup %s: %w", backupName, err)
			if returnErr == nil {
				returnErr = cleanupErr
			} else {
				returnErr = errors.Join(returnErr, cleanupErr)
			}
		}
	}()
	targets := []string{finalTar, finalSHA, finalSig, finalBootstrapSig}
	backups := make([][2]string, 0, len(targets))
	committed := make([]string, 0, len(pairs))
	rollback := func(cause error) error {
		errs := []error{cause}
		recoveryIncomplete := false
		for i := len(committed) - 1; i >= 0; i-- {
			if removeErr := syscall.Unlinkat(int(directory.Fd()), committed[i]); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				recoveryIncomplete = true
				errs = append(errs, fmt.Errorf("remove partial artifact %s: %w", committed[i], removeErr))
			}
		}
		for i := len(backups) - 1; i >= 0; i-- {
			if restoreErr := syscall.Renameat(
				int(backupDirectory.Fd()), backups[i][0], int(directory.Fd()), backups[i][1],
			); restoreErr != nil {
				recoveryIncomplete = true
				errs = append(errs, fmt.Errorf("restore previous artifact %s: %w", backups[i][1], restoreErr))
			}
		}
		if recoveryIncomplete {
			removeBackup = false
			errs = append(errs, fmt.Errorf("release recovery data retained in %s", filepath.Join(distDir, backupName)))
		}
		return errors.Join(errs...)
	}
	for i, target := range targets {
		targetName := filepath.Base(target)
		info, statErr := os.Lstat(directoryEntryPathForRelease(directory, targetName))
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return rollback(fmt.Errorf("inspect previous release artifact %s: %w", targetName, statErr))
		}
		if info.IsDir() {
			return rollback(fmt.Errorf("previous release artifact %s is a directory", targetName))
		}
		backup := fmt.Sprintf("%d-%s", i, targetName)
		if renameErr := syscall.Renameat(int(directory.Fd()), targetName, int(backupDirectory.Fd()), backup); renameErr != nil {
			return rollback(fmt.Errorf("back up previous release artifact %s: %w", targetName, renameErr))
		}
		backups = append(backups, [2]string{backup, targetName})
	}
	for _, file := range staged {
		path := directoryEntryPathForRelease(file.parent, file.name)
		if err := verifyRegularFileState(path, file.state, 0); err != nil {
			return rollback(fmt.Errorf("staged release artifact %s changed before rename: %w", file.destination, err))
		}
		if err := syscall.Renameat(int(file.parent.Fd()), file.name, int(directory.Fd()), file.destination); err != nil {
			return rollback(fmt.Errorf("commit release artifact %s: %w", file.destination, err))
		}
		committed = append(committed, file.destination)
	}
	return nil
}

func directoryDescriptorPath(directory *os.File) string {
	return fmt.Sprintf("/proc/self/fd/%d", directory.Fd())
}

func directoryEntryPathForRelease(directory *os.File, name string) string {
	return directoryDescriptorPath(directory) + "/" + name
}

func validateArtifactCommitPaths(
	stageTar, stageSHA, stageSig, stageBootstrapSig string,
	finalTar, finalSHA, finalSig, finalBootstrapSig string,
	signed bool,
) error {
	paths := []struct {
		label string
		path  string
	}{
		{"staged archive", stageTar},
		{"staged checksum", stageSHA},
		{"final archive", finalTar},
		{"final checksum", finalSHA},
		{"final archive signature", finalSig},
		{"final bootstrap signature", finalBootstrapSig},
	}
	if signed {
		paths = append(paths,
			struct{ label, path string }{"staged archive signature", stageSig},
			struct{ label, path string }{"staged bootstrap signature", stageBootstrapSig},
		)
	}
	seen := make(map[string]string, len(paths))
	for _, item := range paths {
		if item.path == "" {
			return fmt.Errorf("%s path is required", item.label)
		}
		absolute, err := filepath.Abs(item.path)
		if err != nil {
			return fmt.Errorf("resolve %s path: %w", item.label, err)
		}
		absolute = filepath.Clean(absolute)
		if previous, exists := seen[absolute]; exists {
			return fmt.Errorf("release artifact paths must be distinct: %s and %s", previous, item.label)
		}
		seen[absolute] = item.label
	}
	return nil
}

func checkSunSyntax(ctx context.Context, root string) error {
	bash, err := findExecutable("bash")
	if err != nil {
		return fmt.Errorf("validate sun.sh: %w", err)
	}
	if _, err := runCombined(ctx, root, nil, bash, "-n", "sun.sh"); err != nil {
		return fmt.Errorf("sun.sh syntax check failed: %w", err)
	}
	return nil
}

func nativeArchitectureSupported() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, arch := range officialArches {
		if arch == runtime.GOARCH {
			return true
		}
	}
	return false
}
