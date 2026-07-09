package dist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gpgHome 在临时 GNUPGHOME 里跑 gpg（loopback pinentry，无 passphrase），返回合并输出。
func gpgHome(t *testing.T, home string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("gpg", append([]string{"--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	return cmd.CombinedOutput()
}

func fprOf(t *testing.T, home string) string {
	t.Helper()
	cmd := exec.Command("gpg", "--batch", "--with-colons", "--list-keys")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
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
	if _, err := exec.LookPath("gpg"); err != nil {
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

func gpgArmorExport(t *testing.T, home, fpr string) ([]byte, error) {
	cmd := exec.Command("gpg", "--batch", "--armor", "--export", fpr)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}
