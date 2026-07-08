package osrel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	os.WriteFile(p, []byte("NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID_LIKE='x'\n"), 0o644)
	o := Read(p)
	if o.ID != "debian" || o.VersionID != "12" || o.PrettyName != "Debian GNU/Linux 12 (bookworm)" || o.IDLike != "x" {
		t.Errorf("Read = %+v", o)
	}
	if got := Read(filepath.Join(dir, "absent")); got != (OSRelease{}) {
		t.Errorf("absent file: %+v", got)
	}
}

func TestAutoBackend(t *testing.T) {
	cases := []struct {
		o    OSRelease
		want string
	}{
		{OSRelease{ID: "debian"}, "apt"},
		{OSRelease{ID: "ubuntu"}, "apt"},
		{OSRelease{ID: "rocky"}, "dnf"},
		{OSRelease{ID: "fedora"}, "dnf"},
		{OSRelease{ID: "amzn"}, "dnf"},
		{OSRelease{ID: "centos"}, "dnf"},
		{OSRelease{ID: "arch"}, "unknown"},
		{OSRelease{ID: "linuxmint", IDLike: "ubuntu debian"}, "apt"}, // ID_LIKE 兜底
		{OSRelease{ID: "ol", IDLike: "fedora"}, "dnf"},               // Oracle Linux 兜底
		{OSRelease{ID: "weird", IDLike: "suse"}, "unknown"},
	}
	for _, c := range cases {
		if got := AutoBackend(c.o); got != c.want {
			t.Errorf("AutoBackend(%+v)=%q want %q", c.o, got, c.want)
		}
	}
}

func TestSupportTier(t *testing.T) {
	cases := []struct {
		o           OSRelease
		wantBackend string
		wantTier    string
	}{
		{OSRelease{ID: "debian", VersionID: "12"}, "apt", Supported},
		{OSRelease{ID: "debian", VersionID: "11"}, "apt", BestEffort},
		{OSRelease{ID: "ubuntu", VersionID: "24.04"}, "apt", Supported},
		{OSRelease{ID: "ubuntu", VersionID: "20.04"}, "apt", BestEffort},
		{OSRelease{ID: "rocky", VersionID: "9.3"}, "dnf", Supported},
		{OSRelease{ID: "fedora", VersionID: "40"}, "dnf", Supported},
		{OSRelease{ID: "centos", VersionID: "9"}, "dnf", BestEffort},
		{OSRelease{ID: "amzn", VersionID: "2023"}, "dnf", BestEffort},
		{OSRelease{ID: "debian", VersionID: "9"}, "apt", Unsupported}, // 太旧
		{OSRelease{ID: "arch"}, "unknown", Unsupported},
	}
	for _, c := range cases {
		b, tier := SupportTier(c.o)
		if b != c.wantBackend || tier != c.wantTier {
			t.Errorf("SupportTier(%+v)=%q,%q want %q,%q", c.o, b, tier, c.wantBackend, c.wantTier)
		}
	}
}
