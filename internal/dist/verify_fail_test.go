package dist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// gpgHome 在临时 GNUPGHOME 里跑 gpg（loopback pinentry，无 passphrase），返回合并输出。
func gpgHome(t *testing.T, home string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("gpg", append([]string{"--batch", "--no-tty", "--homedir", home, "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
	return cmd.CombinedOutput()
}

func fprOf(t *testing.T, home string) string {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--homedir", home, "--with-colons", "--list-keys")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Split(ln, ":")
		if len(f) > 9 && f[0] == "fpr" {
			return f[9]
		}
	}
	t.Fatal("no fingerprint")
	return ""
}

// TestVerifyReleaseFailClosed 用两把临时密钥验证发布验签的 fail-closed 保证：
// 只有 pin 指纹对应的那把密钥所签、且 sha256 正确的包才被接受；换密钥、换指纹、篡改 sha256 一律拒绝。
// 这守护自升级信任链最关键的“不可替换签名”性质。gpg 缺失则跳过。
func TestVerifyReleaseFailClosed(t *testing.T) {
	if !GPGAvailable() {
		t.Skip("gpg not available")
	}
	dir := t.TempDir()
	h1 := filepath.Join(dir, "gh1")
	h2 := filepath.Join(dir, "gh2")
	for _, h := range []string{h1, h2} {
		if err := os.MkdirAll(h, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := gpgHome(t, h1, "--quick-generate-key", "key-one <one@example.com>", "ed25519", "sign", "0"); err != nil {
		t.Skipf("cannot generate gpg key (sandboxed env?): %v: %s", err, out)
	}
	if out, err := gpgHome(t, h2, "--quick-generate-key", "key-two <two@example.com>", "ed25519", "sign", "0"); err != nil {
		t.Fatalf("gen key2: %v: %s", err, out)
	}
	fpr1 := fprOf(t, h1)
	fpr2 := fprOf(t, h2)

	// 包 + 正确 sha256
	tarball := filepath.Join(dir, "pkg.tar.gz")
	if err := os.WriteFile(tarball, []byte("release payload bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("release payload bytes"))
	shaFile := tarball + ".sha256"
	os.WriteFile(shaFile, []byte(hex.EncodeToString(sum[:])+"  pkg.tar.gz\n"), 0o644)

	// key1 签名 + 导出两把公钥
	asc1 := tarball + ".asc"
	if out, err := gpgHome(t, h1, "--armor", "--detach-sign", "-o", asc1, tarball); err != nil {
		t.Fatalf("sign: %v: %s", err, out)
	}
	pub1 := filepath.Join(dir, "pub1.asc")
	pub2 := filepath.Join(dir, "pub2.asc")
	if b, err := gpgArmorExport(t, h1, fpr1); err == nil {
		os.WriteFile(pub1, b, 0o644)
	}
	if b, err := gpgArmorExport(t, h2, fpr2); err == nil {
		os.WriteFile(pub2, b, 0o644)
	}

	// a) 正确：key1 签、pin=fpr1、sha 正确 -> 接受
	if err := VerifyRelease(tarball, shaFile, asc1, pub1, fpr1); err != nil {
		t.Errorf("good signature rejected: %v", err)
	}
	// A caller-supplied GNUPGHOME must not override the verifier's isolated keyring.
	t.Setenv("GNUPGHOME", h2)
	if err := VerifyRelease(tarball, shaFile, asc1, pub1, fpr1); err != nil {
		t.Errorf("hostile GNUPGHOME overrode isolated verifier: %v", err)
	}
	// b) 换指纹：pin 一个不同的指纹 -> 拒绝（指纹 pin 门）
	if err := VerifyRelease(tarball, shaFile, asc1, pub1, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"); err == nil {
		t.Error("wrong pinned fingerprint was accepted")
	}
	// c) 换密钥：用 key2 的公钥/指纹验 key1 的签名 -> 拒绝（gpg verify 找不到签名者）
	if err := VerifyRelease(tarball, shaFile, asc1, pub2, fpr2); err == nil {
		t.Error("signature from a different key was accepted (substitution attack)")
	}
	// d) 篡改 sha256 -> 在碰 gpg 之前就拒绝（fail-closed 顺序）
	badSha := filepath.Join(dir, "bad.sha256")
	os.WriteFile(badSha, []byte(strings.Repeat("0", 64)+"  pkg.tar.gz\n"), 0o644)
	if err := VerifyRelease(tarball, badSha, asc1, pub1, fpr1); err == nil {
		t.Error("corrupted sha256 was accepted")
	}
	// e) VerifyReleaseKey（内置公钥字节版，自升级实际用的入口）同样接受正确签名
	if b, err := os.ReadFile(pub1); err == nil {
		if err := VerifyReleaseKey(tarball, shaFile, asc1, b, fpr1); err != nil {
			t.Errorf("VerifyReleaseKey rejected a good signature: %v", err)
		}
	}
	// f) 多 key 绕过：公钥文件 = pin key（在前）+ 攻击者 key（在后），签名由攻击者 key 生成，pin=fpr1。
	//    指纹 pin 只查第一个 key（=fpr1，匹配），而 gpg --verify 接受 keyring 中任一 key 的签名——
	//    若不校验“keyring 恰好一把钥匙”，攻击者包会被接受。必须拒绝。
	asc2 := tarball + ".asc2"
	if out, err := gpgHome(t, h2, "--armor", "--detach-sign", "-o", asc2, tarball); err != nil {
		t.Fatalf("sign key2: %v: %s", err, out)
	}
	b1, err1 := os.ReadFile(pub1)
	b2, err2 := os.ReadFile(pub2)
	if err1 == nil && err2 == nil {
		multiPub := filepath.Join(dir, "multi.asc")
		os.WriteFile(multiPub, append(append(append([]byte{}, b1...), '\n'), b2...), 0o644)
		if err := VerifyRelease(tarball, shaFile, asc2, multiPub, fpr1); err == nil {
			t.Error("multi-key pubkey file with attacker signature accepted (fingerprint-pin bypass)")
		}
	}
}

func TestVerifyReleaseRejectsExpiredSigningKey(t *testing.T) {
	if !GPGAvailable() {
		t.Skip("gpg not available")
	}
	dir := t.TempDir()
	home := filepath.Join(dir, "gpg-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := gpgHome(t, home,
		"--faked-system-time", "20200101T000000",
		"--quick-generate-key", "expired-key <expired@example.invalid>", "ed25519", "sign", "1d"); err != nil {
		t.Skipf("cannot generate expiring gpg key: %v: %s", err, out)
	}
	fingerprint := fprOf(t, home)

	tarball := filepath.Join(dir, "pkg.tar.gz")
	const payload = "release payload signed before key expiry"
	if err := os.WriteFile(tarball, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(payload))
	checksum := tarball + ".sha256"
	if err := os.WriteFile(checksum, []byte(hex.EncodeToString(digest[:])+"  pkg.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signature := tarball + ".asc"
	if out, err := gpgHome(t, home,
		"--faked-system-time", "20200101T010000",
		"--armor", "--detach-sign", "-o", signature, tarball); err != nil {
		t.Fatalf("sign with expiring key: %v: %s", err, out)
	}
	publicKeyBytes, err := gpgArmorExport(t, home, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := filepath.Join(dir, "public-key.asc")
	if err := os.WriteFile(publicKey, publicKeyBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// GnuPG 2.2 emits EXPKEYSIG plus VALIDSIG and exits zero here. VALIDSIG
	// alone is therefore insufficient for a fail-closed release verifier.
	if err := VerifyRelease(tarball, checksum, signature, publicKey, fingerprint); err == nil {
		t.Fatal("signature from an expired signing key was accepted")
	}
}

func TestTrustedGPGExecutableIgnoresCallerPATH(t *testing.T) {
	if !GPGAvailable() {
		t.Skip("gpg not available")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "gpg")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	got, err := trustedGPGExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if got == fake || !filepath.IsAbs(got) {
		t.Fatalf("trusted GPG resolved to %q", got)
	}
}

func TestVerifyReleaseBindsHashAndGPGToOpenedTarball(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "verify-started")
	release := filepath.Join(dir, "continue-verify")
	captured := filepath.Join(dir, "gpg-artifact")
	const fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fakeGPG := filepath.Join(dir, "gpg")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
case " $* " in
  *" --list-keys "*)
    printf 'pub:::::::::\nfpr:::::::::%s:\n'
    ;;
  *" --verify "*)
    : > %q
    while [ ! -e %q ]; do /bin/sleep 0.01; done
    for artifact in "$@"; do :; done
    /bin/cat "$artifact" > %q
	printf '[GNUPG:] GOODSIG %s signer\n[GNUPG:] VALIDSIG %s 2026 0 0 0 0 0 0 0 %s\n'
    ;;
esac
`, fingerprint, marker, release, captured, fingerprint, fingerprint, fingerprint)
	if err := os.WriteFile(fakeGPG, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPaths := trustedGPGPaths
	trustedGPGPaths = [...]string{fakeGPG, fakeGPG}
	defer func() { trustedGPGPaths = previousPaths }()

	tarball := filepath.Join(dir, "pkg.tar.gz")
	const original = "release payload bytes"
	if err := os.WriteFile(tarball, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(original))
	shaFile := tarball + ".sha256"
	if err := os.WriteFile(shaFile, []byte(hex.EncodeToString(sum[:])+"  pkg.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signature := tarball + ".asc"
	publicKey := filepath.Join(dir, "release.pub")
	for _, path := range []string{signature, publicKey} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result := make(chan error, 1)
	go func() {
		result <- VerifyRelease(tarball, shaFile, signature, publicKey, fingerprint)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("fake GPG did not reach verification")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Rename(tarball, tarball+".opened"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tarball, []byte("replacement payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := <-result
	if err == nil || !strings.Contains(err.Error(), "tarball changed during release verification") {
		t.Fatalf("path replacement error=%v", err)
	}
	got, readErr := os.ReadFile(captured)
	if readErr != nil || string(got) != original {
		t.Fatalf("GPG received %q err=%v, want bytes from the hashed inode", got, readErr)
	}
}

func TestVerifyReleaseRejectsMultipleValidSignatures(t *testing.T) {
	dir := t.TempDir()
	const fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fakeGPG := filepath.Join(dir, "gpg")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
case " $* " in
  *" --list-keys "*)
    printf 'pub:::::::::\nfpr:::::::::%s:\n'
    ;;
  *" --verify "*)
    printf '[GNUPG:] VALIDSIG %s 2026 0 0 0 0 0 0 0 %s\n'
    printf '[GNUPG:] VALIDSIG %s 2026 0 0 0 0 0 0 0 %s\n'
    ;;
esac
`, fingerprint, fingerprint, fingerprint, fingerprint, fingerprint)
	if err := os.WriteFile(fakeGPG, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	previousPaths := trustedGPGPaths
	trustedGPGPaths = [...]string{fakeGPG, fakeGPG}
	defer func() { trustedGPGPaths = previousPaths }()

	tarball := filepath.Join(dir, "pkg.tar.gz")
	payload := []byte("release payload bytes")
	if err := os.WriteFile(tarball, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	shaFile := tarball + ".sha256"
	if err := os.WriteFile(shaFile, []byte(hex.EncodeToString(sum[:])+"  pkg.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signature := tarball + ".asc"
	publicKey := filepath.Join(dir, "release.pub")
	for _, path := range []string{signature, publicKey} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyRelease(tarball, shaFile, signature, publicKey, fingerprint); err == nil ||
		!strings.Contains(err.Error(), "exactly one signature") {
		t.Fatalf("multiple valid signatures error=%v", err)
	}
}

func TestGPGStatusHasPinnedSignatureRequiresUniquePrimaryBinding(t *testing.T) {
	const primary = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const subkey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	const other = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	status := func(signing, primaryField string) string {
		return "[GNUPG:] GOODSIG " + signing + " signer\n" +
			"[GNUPG:] VALIDSIG " + signing + " 2026 0 0 0 0 0 0 0 " + primaryField + "\n"
	}
	disqualified := func(outcome string) string {
		return "[GNUPG:] " + outcome + " " + primary + " signer\n" +
			"[GNUPG:] VALIDSIG " + primary + " 2026 0 0 0 0 0 0 0 " + primary + "\n"
	}
	for name, test := range map[string]struct {
		status string
		want   bool
	}{
		"primary-direct":    {status(primary, primary), true},
		"signing-subkey":    {status(subkey, primary), true},
		"wrong-key":         {status(other, other), false},
		"missing":           {"[GNUPG:] GOODSIG ignored\n", false},
		"multiple":          {status(primary, primary) + status(primary, primary), false},
		"expired-signature": {disqualified("EXPSIG"), false},
		"expired-key":       {disqualified("EXPKEYSIG"), false},
		"revoked-key":       {disqualified("REVKEYSIG"), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := gpgStatusHasPinnedSignature([]byte(test.status), primary); got != test.want {
				t.Fatalf("gpgStatusHasPinnedSignature()=%v want %v for %q", got, test.want, test.status)
			}
		})
	}
}

func TestVerifyReleaseRejectsInvalidPinnedFingerprintBeforeFileAccess(t *testing.T) {
	for _, fingerprint := range []string{"", "DEADBEEF", strings.Repeat("Z", 40), "\x1b[31m" + strings.Repeat("A", 35)} {
		if err := VerifyRelease("missing", "missing", "missing", "missing", fingerprint); err == nil ||
			!strings.Contains(err.Error(), "invalid pinned") {
			t.Fatalf("fingerprint %q error=%v", fingerprint, err)
		}
	}
}

func TestSummarizeGPGOutputIsTerminalSafeAndValidUTF8(t *testing.T) {
	prefix := strings.Repeat("界", maxGPGErrorBytes/3)
	got := summarizeGPGOutput([]byte(prefix + "\nforged\r\x1b[31mred\u202eevil\u2028tail\xff"))
	if !utf8.ValidString(got) {
		t.Fatalf("summary is invalid UTF-8: %q", got)
	}
	if len(got) > maxGPGErrorBytes {
		t.Fatalf("summary length=%d want <= %d", len(got), maxGPGErrorBytes)
	}
	for _, forbidden := range []string{"\n", "\r", "\x1b", "\u202e", "\u2028"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("summary retained display control %q: %q", forbidden, got)
		}
	}
}

func gpgArmorExport(t *testing.T, home, fpr string) ([]byte, error) {
	cmd := exec.Command("gpg", "--batch", "--homedir", home, "--armor", "--export", fpr)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}
