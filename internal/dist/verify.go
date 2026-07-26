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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

const (
	gpgCommandTimeout = 30 * time.Second
	maxGPGOutputBytes = 1 << 20
	maxGPGErrorBytes  = 4 << 10
	trustedSystemPath = "/usr/sbin:/usr/bin:/sbin:/bin"
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
	// 1) sha256：读期望值并与实算比对
	want, err := readExpectedSHA(sha256File, filepath.Base(tarball))
	if err != nil {
		return fmt.Errorf("read sha256 file: %w", err)
	}
	got, err := fileSHA256(tarball)
	if err != nil {
		return fmt.Errorf("hash tarball: %w", err)
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}

	// 2) 隔离 keyring 导入公钥，取指纹，与 pin 比对
	home, err := os.MkdirTemp("", "sun-verify-gpg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	if err := runGPG(home, "--import", pubKeyFile); err != nil {
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
	if err := runGPG(home, "--verify", ascFile, tarball); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// VerifySHA256 只做 sha256 校验（sha256-only 分支用；gpg 缺失且显式 opt-in 时）。
func VerifySHA256(tarball, sha256File string) error {
	want, err := readExpectedSHA(sha256File, filepath.Base(tarball))
	if err != nil {
		return fmt.Errorf("read sha256 file: %w", err)
	}
	got, err := fileSHA256(tarball)
	if err != nil {
		return fmt.Errorf("hash tarball: %w", err)
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}
	return nil
}

// VerifyReleaseKey 与 VerifyRelease 相同，但公钥以字节传入（内置 go:embed 公钥用）：写入临时文件后
// 复用文件版校验（sha256 → 指纹 pin → GPG 验签，fail-closed）。
func VerifyReleaseKey(tarball, sha256File, ascFile string, pubKey []byte, wantFpr string) error {
	tmp, err := os.CreateTemp("", "sun-pubkey-*.asc")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(pubKey); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return VerifyRelease(tarball, sha256File, ascFile, tmp.Name(), wantFpr)
}

func readExpectedSHA(path, archiveName string) (string, error) {
	if archiveName == "" || archiveName == "." || archiveName == ".." || filepath.Base(archiveName) != archiveName {
		return "", fmt.Errorf("invalid archive name %q", archiveName)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
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

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
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

func runGPG(home string, args ...string) error {
	out, err := runGPGOutput(home, append([]string{"--no-tty"}, args...)...)
	if err != nil {
		return fmt.Errorf("gpg failed: %v: %s", err, summarizeGPGOutput(out))
	}
	return nil
}

func summarizeGPGOutput(out []byte) string {
	if len(out) > maxGPGErrorBytes {
		out = out[:maxGPGErrorBytes]
	}
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 && r != 0x7f {
			return r
		}
		return ' '
	}, string(out))
	return strings.TrimSpace(s)
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
	gpg, err := trustedGPGExecutable()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gpgCommandTimeout)
	defer cancel()
	baseArgs := []string{"--batch", "--homedir", home}
	cmd := sysexec.CommandContext(ctx, gpg, append(baseArgs, args...)...)
	cmd.Env = []string{"HOME=" + home, "GNUPGHOME=" + home, "PATH=" + trustedSystemPath, "LC_ALL=C"}
	out := &boundedGPGOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	err = cmd.Run()
	if ctx.Err() != nil {
		return out.buf.Bytes(), fmt.Errorf("timed out")
	}
	if out.overflow {
		return out.buf.Bytes()[:maxGPGOutputBytes], fmt.Errorf("output exceeds size limit")
	}
	return out.buf.Bytes(), err
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
