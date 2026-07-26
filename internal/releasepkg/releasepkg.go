// Package releasepkg builds the signed, reproducible release set used by the
// security-update-notify bootstrap installer.
package releasepkg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/assets"
)

const (
	productName               = "security-update-notify"
	maxUncompressedSize int64 = 256 << 20
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
	// SignOff deliberately produces an unsigned local release set.
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
	Tarball       string
	Checksum      string
	Signature     string
	SHA256        string
	Version       string
	Epoch         int64
	Signed        bool
	Official      bool
	Architectures []string
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
	if err := validateRegularSource(path); err != nil {
		return "", fmt.Errorf("canonical VERSION: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read canonical VERSION: %w", err)
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

	if err := validateSources(root, opts.Version); err != nil {
		return Result{}, err
	}
	if err := checkSunSyntax(ctx, root); err != nil {
		return Result{}, err
	}

	repo, err := inspectRepository(ctx, root, opts.Version)
	if err != nil {
		return Result{}, err
	}
	if repo.Dirty && (!opts.AllowDirty || opts.SourceDateEpoch == nil) {
		return Result{}, fmt.Errorf("release sources have uncommitted or untracked changes (%s); allow-dirty also requires an explicit source-date-epoch", strings.Join(repo.DirtyFiles, ", "))
	}
	if repo.Dirty {
		fmt.Fprintln(stderr, "WARNING: packaging dirty release sources with an explicit SOURCE_DATE_EPOCH")
	}

	epoch, err := resolveEpoch(ctx, root, opts.Version, opts.SourceDateEpoch, repo)
	if err != nil {
		return Result{}, err
	}
	official := opts.Release || repo.TagExists
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
	if err := clearTargetArtifacts(finalTar, finalSHA, finalSig); err != nil {
		return Result{}, err
	}
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
	if err := os.WriteFile(stageSHA, []byte(digest+"  "+tarName+"\n"), 0o644); err != nil {
		return Result{}, fmt.Errorf("write checksum: %w", err)
	}
	if err := os.Chmod(stageSHA, 0o644); err != nil {
		return Result{}, fmt.Errorf("normalize checksum mode: %w", err)
	}

	stageSig := stageTar + ".asc"
	signed, err := maybeSign(ctx, signOptions{
		Mode: mode, GPGKeyID: opts.GPGKeyID, GPGHome: opts.GPGHome,
		PinnedFingerprint: assets.ReleaseSigningFingerprint,
	}, stageTar, stageSig)
	if err != nil {
		return Result{}, err
	}

	if err := commitArtifacts(stageTar, stageSHA, stageSig, finalTar, finalSHA, finalSig, signed); err != nil {
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
	}
	return result, nil
}

func validateSources(root, version string) error {
	for _, spec := range releaseFiles {
		if err := validateRegularSource(filepath.Join(root, filepath.FromSlash(spec.Source))); err != nil {
			return fmt.Errorf("required release source %s: %w", spec.Source, err)
		}
	}

	f, err := os.Open(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		return fmt.Errorf("open CHANGELOG.md: %w", err)
	}
	defer f.Close()
	want := "## " + version
	count := 0
	s := bufio.NewScanner(f)
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
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.path)))
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
	b, err := os.ReadFile(filepath.Join(root, "sun.sh"))
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

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open archive for checksum: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash archive: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func commitArtifacts(stageTar, stageSHA, stageSig, finalTar, finalSHA, finalSig string, signed bool) (err error) {
	committed := make([]string, 0, 3)
	defer func() {
		if err != nil {
			for _, path := range committed {
				_ = os.Remove(path)
			}
		}
	}()
	for _, pair := range [][2]string{{stageTar, finalTar}, {stageSHA, finalSHA}} {
		if err = os.Rename(pair[0], pair[1]); err != nil {
			return fmt.Errorf("commit release artifact %s: %w", filepath.Base(pair[1]), err)
		}
		committed = append(committed, pair[1])
	}
	if signed {
		if err = os.Rename(stageSig, finalSig); err != nil {
			return fmt.Errorf("commit release signature: %w", err)
		}
		committed = append(committed, finalSig)
	} else if err = os.Remove(finalSig); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale release signature: %w", err)
	}
	return nil
}

func clearTargetArtifacts(paths ...string) error {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove previous release artifact %s: %w", filepath.Base(path), err)
		}
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
