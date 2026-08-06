// Package dist 承载发布产物的信任与传输核心：sha256 校验、pin 指纹的 GPG 验签、tar 安全检查。
// 它与 sun.sh 引导器共享同一信任契约；除系统 gpg 外仅使用 Go 标准库。
//
// Package dist carries the release trust+transport core: sha256 verification, pinned-fingerprint GPG
// verification, and tar safety checks. It shares the trust contract used by sun.sh; only signature
// verification is delegated to the system gpg.
package dist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
)

const (
	gpgCommandTimeout    = 30 * time.Second
	maxGPGOutputBytes    = 1 << 20
	maxGPGErrorBytes     = 4 << 10
	trustedSystemPath    = "/usr/sbin:/usr/bin:/sbin:/bin"
	verificationTempBase = "/var/tmp"
)

var trustedGPGPaths = [...]string{"/usr/bin/gpg", "/bin/gpg"}

// GPGAvailable reports whether a GPG executable exists in a fixed system
// location. Privileged verification deliberately does not trust the caller's
// PATH, because the selected executable is part of the release trust boundary.
func GPGAvailable() bool {
	_, err := trustedGPGExecutable()
	return err == nil
}

// VerifyRelease 复刻自升级的信任校验，顺序 fail-closed：sha256 → 指纹 pin → GPG 验签。
// 任何一步失败都以错误返回（而非 Bash 里一堆 `|| exit 1` 守卫），绝不被静默吞掉。
//
// VerifyRelease reproduces the self-upgrade trust check in fail-closed order: sha256 → fingerprint pin
// → GPG verify. Every step surfaces as a returned error (instead of Bash's `|| exit 1` guards), so no
// failure is silently swallowed.
func VerifyRelease(tarball, sha256File, ascFile, pubKeyFile, wantFpr string) error {
	if len(wantFpr) != 40 || !isHex(wantFpr) {
		return fmt.Errorf("invalid pinned signing-key fingerprint")
	}
	inputs, err := openReleaseInputs(tarball, sha256File, ascFile, pubKeyFile)
	if err != nil {
		return err
	}
	defer inputs.close()

	// 1) sha256：读期望值并与实算比对
	want, err := readExpectedSHAFile(inputs.sha256, filepath.Base(tarball))
	if err != nil {
		return fmt.Errorf("read sha256 file: %w", err)
	}
	got, err := fileSHA256File(inputs.tarball)
	if err != nil {
		return fmt.Errorf("hash tarball: %w", err)
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}

	// 2) 隔离 keyring 导入公钥，取指纹，与 pin 比对
	home, err := createVerificationTempDir(verificationTempBase, "sun-verify-gpg-", 0)
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	if err := rewindFile(inputs.publicKey); err != nil {
		return fmt.Errorf("rewind public key: %w", err)
	}
	if err := runGPGFiles(home, []*os.File{inputs.publicKey}, "--import", "--", inheritedFilePath(0)); err != nil {
		return fmt.Errorf("import public key: %w", err)
	}
	fpr, err := gpgFingerprint(home)
	if err != nil {
		return fmt.Errorf("read key fingerprint: %w", err)
	}
	if !strings.EqualFold(fpr, wantFpr) {
		return fmt.Errorf("signing key fingerprint mismatch: got %s want %s", fpr, wantFpr)
	}

	// 3) 验签
	if err := rewindFile(inputs.signature); err != nil {
		return fmt.Errorf("rewind signature: %w", err)
	}
	if err := rewindFile(inputs.tarball); err != nil {
		return fmt.Errorf("rewind tarball: %w", err)
	}
	status, err := runGPGOutputFiles(home, []*os.File{inputs.signature, inputs.tarball},
		"--no-tty", "--status-fd=1", "--verify", inheritedFilePath(0), inheritedFilePath(1))
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	if !gpgStatusHasPinnedSignature(status, wantFpr) {
		return fmt.Errorf("signature verification did not return exactly one signature bound to the pinned primary fingerprint")
	}
	// Re-hash the same opened inode after GPG returns. This catches ordinary
	// in-place mutation in addition to pathname replacement; GPG and SHA-256
	// are never allowed to authenticate two different path resolutions.
	after, err := fileSHA256File(inputs.tarball)
	if err != nil {
		return fmt.Errorf("rehash tarball after signature verification: %w", err)
	}
	if !strings.EqualFold(after, want) {
		return fmt.Errorf("tarball changed during signature verification")
	}
	if err := inputs.validatePaths(); err != nil {
		return err
	}
	return nil
}

// VerifySHA256 performs an integrity-only check for non-upgrade callers. Self-upgrade authentication
// always requires VerifyReleaseKey and never accepts this function as a signature substitute.
func VerifySHA256(tarball, sha256File string) error {
	tarFile, tarInfo, err := openRegularInput(tarball, maxArchiveBytes)
	if err != nil {
		return fmt.Errorf("open tarball: %w", err)
	}
	defer tarFile.Close()
	shaFile, shaInfo, err := openRegularInput(sha256File, maxReleaseMetadataBytes)
	if err != nil {
		return fmt.Errorf("open sha256 file: %w", err)
	}
	defer shaFile.Close()
	want, err := readExpectedSHAFile(shaFile, filepath.Base(tarball))
	if err != nil {
		return fmt.Errorf("read sha256 file: %w", err)
	}
	got, err := fileSHA256File(tarFile)
	if err != nil {
		return fmt.Errorf("hash tarball: %w", err)
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}
	if err := validateOpenedInput("tarball", tarball, tarFile, tarInfo); err != nil {
		return err
	}
	if err := validateOpenedInput("sha256 file", sha256File, shaFile, shaInfo); err != nil {
		return err
	}
	return nil
}

// VerifyReleaseKey 与 VerifyRelease 相同，但公钥以字节传入（内置 go:embed 公钥用）：写入临时文件后
// 复用文件版校验（sha256 → 指纹 pin → GPG 验签，fail-closed）。
func VerifyReleaseKey(tarball, sha256File, ascFile string, pubKey []byte, wantFpr string) error {
	workspace, err := createVerificationTempDir(verificationTempBase, "sun-pubkey-", 0)
	if err != nil {
		return err
	}
	defer os.RemoveAll(workspace)
	tmpPath := filepath.Join(workspace, "release-signing-key.asc")
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := tmp.Write(pubKey); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return VerifyRelease(tarball, sha256File, ascFile, tmpPath, wantFpr)
}

// createVerificationTempDir uses an explicit base and never consults TMPDIR. Production callers
// require the fixed system base to be root-owned. A shared base is safe only with the sticky bit,
// which prevents other users from replacing a verifier-owned keyring directory.
func createVerificationTempDir(base, prefix string, ownerUID int) (string, error) {
	return filetrust.MkdirTemp(base, prefix, ownerUID)
}

func readExpectedSHAFile(f *os.File, archiveName string) (string, error) {
	if archiveName == "" || archiveName == "." || archiveName == ".." || filepath.Base(archiveName) != archiveName {
		return "", fmt.Errorf("invalid archive name %q", archiveName)
	}
	if err := rewindFile(f); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReleaseMetadataBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxReleaseMetadataBytes {
		return "", fmt.Errorf("sha256 file exceeds size limit")
	}
	const digestLength = sha256.Size * 2
	if len(b) < digestLength {
		return "", fmt.Errorf("invalid sha256 file (expected exactly one record for %q)", archiveName)
	}
	h := string(b[:digestLength])
	if len(h) != 64 || !isHex(h) {
		return "", fmt.Errorf("not a sha256 hex digest: %q", h)
	}
	wantRecord := h + "  " + archiveName + "\n"
	if string(b) != wantRecord {
		return "", fmt.Errorf("invalid sha256 file (expected exactly one record for %q)", archiveName)
	}
	return h, nil
}

func fileSHA256File(f *os.File) (string, error) {
	if err := rewindFile(f); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func runGPGFiles(home string, files []*os.File, args ...string) error {
	out, err := runGPGOutputFiles(home, files, append([]string{"--no-tty"}, args...)...)
	if err != nil {
		if message := summarizeGPGOutput(out); message != "" {
			return fmt.Errorf("gpg failed: %w: %s", err, message)
		}
		return fmt.Errorf("gpg failed: %w", err)
	}
	return nil
}

func summarizeGPGOutput(out []byte) string {
	s := strings.TrimSpace(textsafe.SingleLine(string(out)))
	if len(s) <= maxGPGErrorBytes {
		return s
	}
	limit := maxGPGErrorBytes
	for limit > 0 && !utf8.ValidString(s[:limit]) {
		limit--
	}
	return strings.TrimSpace(s[:limit])
}

func gpgFingerprint(home string) (string, error) {
	out, err := runGPGOutput(home, "--with-colons", "--list-keys")
	if err != nil {
		return "", err
	}
	// keyring 必须恰好含一个公钥。否则一个 “真key 在前 + 攻击者 key 在后” 的多 key 文件会让
	// 指纹 pin（只匹配第一个 key）通过，而随后的 `gpg --verify` 接受 keyring 中任一 key 的签名——
	// 即指纹 pin 被绕过。恰好一个主 key 时，pin 与验签指向同一把钥匙。
	pubCount := 0
	fpr := ""
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ":")
		if len(f) > 0 && f[0] == "pub" {
			pubCount++
		}
		if fpr == "" && len(f) > 9 && f[0] == "fpr" {
			fpr = f[9]
		}
	}
	if pubCount != 1 {
		return "", fmt.Errorf("expected exactly one signing key in keyring, got %d", pubCount)
	}
	if fpr == "" {
		return "", fmt.Errorf("no fingerprint found in keyring")
	}
	return fpr, nil
}

func gpgStatusHasPinnedSignature(status []byte, pinned string) bool {
	goodCount, outcomeCount := 0, 0
	validCount, pinnedCount := 0, 0
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "[GNUPG:]" {
			continue
		}
		switch fields[1] {
		case "GOODSIG":
			outcomeCount++
			goodCount++
		case "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG", "ERRSIG":
			// VALIDSIG only means the signature is cryptographically valid. GPG
			// also emits it for expired and revoked signing keys, often with a
			// zero exit status, so the corresponding outcome must be GOODSIG.
			outcomeCount++
		case "VALIDSIG":
			if len(fields) < 3 {
				continue
			}
			validCount++
			if strings.EqualFold(fields[2], pinned) || strings.EqualFold(fields[len(fields)-1], pinned) {
				pinnedCount++
			}
		}
	}
	return outcomeCount == 1 && goodCount == 1 && validCount == 1 && pinnedCount == 1
}

type boundedGPGOutput struct {
	buf      bytes.Buffer
	overflow bool
}

func (w *boundedGPGOutput) Write(p []byte) (int, error) {
	if remaining := maxGPGOutputBytes + 1 - w.buf.Len(); remaining > 0 {
		if len(p) < remaining {
			remaining = len(p)
		}
		_, _ = w.buf.Write(p[:remaining])
	}
	if w.buf.Len() > maxGPGOutputBytes {
		w.overflow = true
	}
	return len(p), nil
}

func runGPGOutput(home string, args ...string) ([]byte, error) {
	return runGPGOutputFiles(home, nil, args...)
}

func runGPGOutputFiles(home string, files []*os.File, args ...string) ([]byte, error) {
	gpg, err := trustedGPGExecutable()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gpgCommandTimeout)
	defer cancel()
	baseArgs := []string{"--no-options", "--batch", "--homedir", home}
	cmd := sysexec.CommandContext(ctx, gpg, append(baseArgs, args...)...)
	cmd.Env = []string{"HOME=" + home, "GNUPGHOME=" + home, "PATH=" + trustedSystemPath, "LC_ALL=C"}
	cmd.ExtraFiles = append([]*os.File(nil), files...)
	stdout := &boundedGPGOutput{}
	stderr := &boundedGPGOutput{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return stdout.buf.Bytes(), fmt.Errorf("timed out")
	}
	if stdout.overflow || stderr.overflow {
		return stdout.buf.Bytes()[:min(stdout.buf.Len(), maxGPGOutputBytes)], fmt.Errorf("output exceeds size limit")
	}
	if err != nil {
		message := summarizeGPGOutput(stderr.buf.Bytes())
		if message != "" {
			return stdout.buf.Bytes(), fmt.Errorf("%w: %s", err, message)
		}
	}
	return stdout.buf.Bytes(), err
}

type releaseInputs struct {
	tarballPath, sha256Path, signaturePath, publicKeyPath string
	tarball, sha256, signature, publicKey                 *os.File
	tarballInfo, sha256Info, signatureInfo, publicKeyInfo os.FileInfo
}

func openReleaseInputs(tarball, sha256File, ascFile, pubKeyFile string) (releaseInputs, error) {
	var inputs releaseInputs
	inputs.tarballPath, inputs.sha256Path = tarball, sha256File
	inputs.signaturePath, inputs.publicKeyPath = ascFile, pubKeyFile
	var err error
	if inputs.tarball, inputs.tarballInfo, err = openRegularInput(tarball, maxArchiveBytes); err != nil {
		return releaseInputs{}, fmt.Errorf("open tarball: %w", err)
	}
	if inputs.sha256, inputs.sha256Info, err = openRegularInput(sha256File, maxReleaseMetadataBytes); err != nil {
		inputs.close()
		return releaseInputs{}, fmt.Errorf("open sha256 file: %w", err)
	}
	if inputs.signature, inputs.signatureInfo, err = openRegularInput(ascFile, maxReleaseMetadataBytes); err != nil {
		inputs.close()
		return releaseInputs{}, fmt.Errorf("open signature: %w", err)
	}
	if inputs.publicKey, inputs.publicKeyInfo, err = openRegularInput(pubKeyFile, maxReleaseMetadataBytes); err != nil {
		inputs.close()
		return releaseInputs{}, fmt.Errorf("open public key: %w", err)
	}
	return inputs, nil
}

func (inputs *releaseInputs) close() {
	for _, file := range []*os.File{inputs.tarball, inputs.sha256, inputs.signature, inputs.publicKey} {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (inputs releaseInputs) validatePaths() error {
	checks := []struct {
		label string
		path  string
		file  *os.File
		info  os.FileInfo
	}{
		{"tarball", inputs.tarballPath, inputs.tarball, inputs.tarballInfo},
		{"sha256 file", inputs.sha256Path, inputs.sha256, inputs.sha256Info},
		{"signature", inputs.signaturePath, inputs.signature, inputs.signatureInfo},
		{"public key", inputs.publicKeyPath, inputs.publicKey, inputs.publicKeyInfo},
	}
	for _, check := range checks {
		if err := validateOpenedInput(check.label, check.path, check.file, check.info); err != nil {
			return err
		}
	}
	return nil
}

func validateOpenedInput(label, path string, file *os.File, initial os.FileInfo) error {
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect opened %s: %w", label, err)
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) ||
		opened.Size() != initial.Size() || !opened.ModTime().Equal(initial.ModTime()) {
		return fmt.Errorf("%s changed during release verification", label)
	}
	return nil
}

func openRegularInput(path string, maxSize int64) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, fmt.Errorf("create file handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || maxSize < 1 || info.Size() > maxSize {
		_ = file.Close()
		return nil, nil, fmt.Errorf("must be a regular file no larger than %d bytes", maxSize)
	}
	return file, info, nil
}

func rewindFile(file *os.File) error {
	if file == nil {
		return errors.New("missing opened file")
	}
	_, err := file.Seek(0, io.SeekStart)
	return err
}

func inheritedFilePath(index int) string {
	return fmt.Sprintf("/proc/self/fd/%d", 3+index)
}

func trustedGPGExecutable() (string, error) {
	for _, candidate := range trustedGPGPaths {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}
