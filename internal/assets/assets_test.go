package assets

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestEmbeddedAssetsNonEmpty(t *testing.T) {
	for name, b := range map[string][]byte{
		"pubkey":      ReleaseSigningPublicKey(),
		"service":     SystemdServiceUnit(),
		"needrestart": NeedrestartConf(),
		"logrotate":   LogrotateConf(),
	} {
		if len(b) == 0 {
			t.Errorf("embedded asset %q is empty", name)
		}
	}
	if !bytes.Contains(ReleaseSigningPublicKey(), []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
		t.Error("pubkey does not look like an armored PGP key")
	}
	if len(ReleaseSigningFingerprint) != 40 {
		t.Errorf("fingerprint is not 40 hex chars: %q", ReleaseSigningFingerprint)
	}
}

// 内置公钥的实际指纹必须等于 pin 常量（复刻 Bash CI 的 hardening 校验，Go 侧对齐）。gpg 缺失则跳过。
func TestEmbeddedKeyFingerprintMatchesPin(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not available")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	imp := exec.Command("gpg", "--batch", "--no-tty", "--import")
	imp.Env = append(os.Environ(), "GNUPGHOME="+home)
	imp.Stdin = bytes.NewReader(ReleaseSigningPublicKey())
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("import failed: %v: %s", err, out)
	}
	list := exec.Command("gpg", "--batch", "--with-colons", "--list-keys")
	list.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err := list.Output()
	if err != nil {
		t.Fatal(err)
	}
	var fpr string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ":")
		if len(f) > 9 && f[0] == "fpr" {
			fpr = f[9]
			break
		}
	}
	if !strings.EqualFold(fpr, ReleaseSigningFingerprint) {
		t.Errorf("embedded key fingerprint %q != pinned %q", fpr, ReleaseSigningFingerprint)
	}
}
