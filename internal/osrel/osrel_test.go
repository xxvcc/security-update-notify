package osrel

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	if err := os.WriteFile(p, []byte("NAME=\"Debian GNU/Linux\"\r\nID=debian\r\nVERSION_ID=\"12\"\r\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\r\nID_LIKE='x'\r\nSUPPORT_END=\"2028-06-30\"\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := readTrusted(p, os.Geteuid())
	if o.ID != "debian" || o.VersionID != "12" || o.PrettyName != "Debian GNU/Linux 12 (bookworm)" || o.IDLike != "x" || o.SupportEnd != "2028-06-30" {
		t.Errorf("Read = %+v", o)
	}
	if got := readTrusted(filepath.Join(dir, "absent"), os.Geteuid()); got != (OSRelease{}) {
		t.Errorf("absent file: %+v", got)
	}
}

func TestReadFirstUsesFallbackOnlyWhenPrimaryIsMissing(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "etc-os-release")
	fallback := filepath.Join(dir, "usr-lib-os-release")
	if err := os.WriteFile(fallback, []byte("ID=debian\nVERSION_ID=13\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readFirstTrusted(primary, fallback, os.Geteuid()); got.ID != "debian" || got.VersionID != "13" {
		t.Fatalf("missing-primary fallback = %+v", got)
	}
	if err := os.WriteFile(primary, []byte("ID=ubuntu\nVERSION_ID=24.04\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readFirstTrusted(primary, fallback, os.Geteuid()); got.ID != "ubuntu" || got.VersionID != "24.04" {
		t.Fatalf("primary precedence = %+v", got)
	}
	if err := os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(primary, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := readFirstTrusted(primary, fallback, os.Geteuid()); got != (OSRelease{}) {
		t.Fatalf("primary read failure was hidden by fallback: %+v", got)
	}
	if err := os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing-target"), primary); err != nil {
		t.Fatal(err)
	}
	if got := readFirstTrusted(primary, fallback, os.Geteuid()); got != (OSRelease{}) {
		t.Fatalf("broken primary symlink was hidden by fallback: %+v", got)
	}
}

func TestReadAcceptsTrustedRegularSymlinkButRejectsSpecialAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "os-release.target")
	if err := os.WriteFile(target, []byte("ID=debian\nVERSION_ID=12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "os-release.link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got := readTrusted(link, os.Geteuid()); got.ID != "debian" || got.VersionID != "12" {
		t.Fatalf("regular symlink was not parsed: %+v", got)
	}

	oversized := filepath.Join(dir, "os-release.oversized")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, maxOSReleaseBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readTrusted(oversized, os.Geteuid()); got != (OSRelease{}) {
		t.Fatalf("oversized os-release was accepted: %+v", got)
	}

	fifo := filepath.Join(dir, "os-release.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan OSRelease, 1)
	go func() { done <- readTrusted(fifo, os.Geteuid()) }()
	select {
	case got := <-done:
		if got != (OSRelease{}) {
			t.Fatalf("FIFO os-release was accepted: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("reading a FIFO os-release blocked")
	}
}

func TestReadRequiresTrustedOwnerAndProtectedPermissionsButAllowsHardlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	if err := os.WriteFile(path, []byte("ID=debian\nVERSION_ID=12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ownerUID := os.Geteuid()
	if got := readTrusted(path, ownerUID+1); got != (OSRelease{}) {
		t.Fatalf("wrong-owner os-release was accepted: %+v", got)
	}

	for _, mode := range []os.FileMode{0o664, 0o646} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if got := readTrusted(path, ownerUID); got != (OSRelease{}) {
			t.Fatalf("writable os-release mode %#o was accepted: %+v", mode, got)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "os-release.alias")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if got := readTrusted(path, ownerUID); got.ID != "debian" || got.VersionID != "12" {
		t.Fatalf("protected hard-linked os-release was rejected: %+v", got)
	}
}

func TestSupportEndDate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "valid", in: "2026-12-02", want: "2026-12-02"},
		{name: "leap day", in: "2028-02-29", want: "2028-02-29"},
		{name: "empty"},
		{name: "not zero padded", in: "2026-2-02"},
		{name: "invalid leap day", in: "2027-02-29"},
		{name: "trailing data", in: "2026-12-02T00:00:00Z"},
		{name: "surrounding whitespace", in: " 2026-12-02 "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupportEndDate(OSRelease{SupportEnd: tc.in}); got != tc.want {
				t.Fatalf("SupportEndDate(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
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
		{OSRelease{ID: "ol"}, "dnf"},
		{OSRelease{ID: "cloudlinux"}, "dnf"},
		{OSRelease{ID: "arch"}, "unknown"},
		{OSRelease{ID: "linuxmint", IDLike: "ubuntu debian"}, "apt"}, // ID_LIKE 兜底
		{OSRelease{ID: "unknown-el", IDLike: "rhel fedora"}, "dnf"},
		{OSRelease{ID: "conflicting", IDLike: "debian rhel"}, "unknown"},
		{OSRelease{ID: "conflicting", IDLike: "ubuntu fedora"}, "unknown"},
		{OSRelease{ID: "near-match", IDLike: "notdebian"}, "unknown"},
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
		name        string
		o           OSRelease
		wantBackend string
		wantTier    string
	}{
		{name: "debian 12", o: OSRelease{ID: "debian", VersionID: "12"}, wantBackend: "apt", wantTier: Supported},
		{name: "debian 13", o: OSRelease{ID: "debian", VersionID: "13"}, wantBackend: "apt", wantTier: Supported},
		{name: "debian 11", o: OSRelease{ID: "debian", VersionID: "11"}, wantBackend: "apt", wantTier: BestEffort},
		{name: "ubuntu 20.04", o: OSRelease{ID: "ubuntu", VersionID: "20.04"}, wantBackend: "apt", wantTier: BestEffort},
		{name: "ubuntu 22.04", o: OSRelease{ID: "ubuntu", VersionID: "22.04"}, wantBackend: "apt", wantTier: Supported},
		{name: "ubuntu 24.04", o: OSRelease{ID: "ubuntu", VersionID: "24.04"}, wantBackend: "apt", wantTier: Supported},
		{name: "ubuntu 26.04", o: OSRelease{ID: "ubuntu", VersionID: "26.04"}, wantBackend: "apt", wantTier: Supported},
		{name: "rhel 10", o: OSRelease{ID: "rhel", VersionID: "10.0"}, wantBackend: "dnf", wantTier: Supported},
		{name: "rocky 8", o: OSRelease{ID: "rocky", VersionID: "8.10"}, wantBackend: "dnf", wantTier: Supported},
		{name: "rocky 9", o: OSRelease{ID: "rocky", VersionID: "9.6"}, wantBackend: "dnf", wantTier: Supported},
		{name: "rocky 10", o: OSRelease{ID: "rocky", VersionID: "10.0"}, wantBackend: "dnf", wantTier: Supported},
		{name: "alma 10", o: OSRelease{ID: "almalinux", VersionID: "10.2"}, wantBackend: "dnf", wantTier: Supported},
		{name: "fedora 43", o: OSRelease{ID: "fedora", VersionID: "43"}, wantBackend: "dnf", wantTier: Supported},
		{name: "fedora 44", o: OSRelease{ID: "fedora", VersionID: "44"}, wantBackend: "dnf", wantTier: Supported},
		{name: "fedora old", o: OSRelease{ID: "fedora", VersionID: "42"}, wantBackend: "dnf", wantTier: Unsupported},
		{name: "fedora future", o: OSRelease{ID: "fedora", VersionID: "45"}, wantBackend: "dnf", wantTier: Unsupported},
		{name: "oracle 8", o: OSRelease{ID: "ol", VersionID: "8.10"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "oracle 9", o: OSRelease{ID: "ol", VersionID: "9.6"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "oracle 10", o: OSRelease{ID: "ol", VersionID: "10.0"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "cloudlinux 8", o: OSRelease{ID: "cloudlinux", VersionID: "8.10"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "cloudlinux 9", o: OSRelease{ID: "cloudlinux", VersionID: "9.6"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "cloudlinux 10", o: OSRelease{ID: "cloudlinux", VersionID: "10.0"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "centos stream 8 EOL", o: OSRelease{ID: "centos", VersionID: "8"}, wantBackend: "dnf", wantTier: Unsupported},
		{name: "centos stream 9", o: OSRelease{ID: "centos", VersionID: "9"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "centos stream 10", o: OSRelease{ID: "centos", VersionID: "10"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "amazon 2023", o: OSRelease{ID: "amzn", VersionID: "2023"}, wantBackend: "dnf", wantTier: BestEffort},
		{name: "debian too old", o: OSRelease{ID: "debian", VersionID: "9"}, wantBackend: "apt", wantTier: Unsupported},
		{name: "malformed el version", o: OSRelease{ID: "rocky", VersionID: "10.preview"}, wantBackend: "dnf", wantTier: Unsupported},
		{name: "empty el version", o: OSRelease{ID: "rhel"}, wantBackend: "dnf", wantTier: Unsupported},
		{name: "unknown derivative", o: OSRelease{ID: "custom", VersionID: "10", IDLike: "rhel fedora"}, wantBackend: "dnf", wantTier: Unsupported},
		{name: "arch", o: OSRelease{ID: "arch"}, wantBackend: "unknown", wantTier: Unsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, tier := SupportTier(c.o)
			if b != c.wantBackend || tier != c.wantTier {
				t.Errorf("SupportTier(%+v)=%q,%q want %q,%q", c.o, b, tier, c.wantBackend, c.wantTier)
			}
		})
	}
}

func TestProfileForAPT(t *testing.T) {
	p := ProfileFor(OSRelease{ID: "ubuntu", VersionID: "26.04"})
	if p.Backend != "apt" || p.Engine != EngineAPT || p.Tier != Supported {
		t.Fatalf("identity = backend %q, engine %q, tier %q", p.Backend, p.Engine, p.Tier)
	}
	if want := []string{"unattended-upgrades", "needrestart", "apt-listchanges", "ca-certificates"}; !reflect.DeepEqual(p.Packages, want) {
		t.Fatalf("Packages = %v, want %v", p.Packages, want)
	}
	if p.PackageProbe.Name != "dpkg" || !reflect.DeepEqual(p.PackageProbe.Args, []string{"-s"}) {
		t.Fatalf("PackageProbe = %+v", p.PackageProbe)
	}
	if !reflect.DeepEqual(p.PackageManagers, []string{"apt-get"}) || !reflect.DeepEqual(p.RequiredCommands, []string{"apt-get", "dpkg", "needrestart"}) {
		t.Fatalf("command metadata = managers %v, required %v", p.PackageManagers, p.RequiredCommands)
	}
	if p.AutomaticConfig != "/etc/apt/apt.conf.d/20auto-upgrades" || p.AutomaticTimer != "apt-daily-upgrade.timer" || p.AutomaticService != "apt-daily-upgrade.service" {
		t.Fatalf("automatic metadata = config %q timer %q service %q", p.AutomaticConfig, p.AutomaticTimer, p.AutomaticService)
	}
	if p.AutomaticProbe.Name != "unattended-upgrade" || p.RestartServicesProbe.Name != "needrestart" {
		t.Fatalf("probes = automatic %+v restart %+v", p.AutomaticProbe, p.RestartServicesProbe)
	}
}

func TestProfileForDNF4(t *testing.T) {
	el10 := ProfileFor(OSRelease{ID: "almalinux", VersionID: "10.2"})
	if el10.Backend != "dnf" || el10.Engine != EngineDNF4 || el10.Tier != Supported {
		t.Fatalf("EL10 identity = %+v", el10)
	}
	if want := []string{"dnf", "dnf-automatic", "ca-certificates", "yum-utils"}; !reflect.DeepEqual(el10.Packages, want) {
		t.Fatalf("EL10 Packages = %v, want %v", el10.Packages, want)
	}
	if el10.PackageProbe.Name != "rpm" || !reflect.DeepEqual(el10.PackageProbe.Args, []string{"-q"}) {
		t.Fatalf("PackageProbe = %+v", el10.PackageProbe)
	}
	if !reflect.DeepEqual(el10.PackageManagers, []string{"dnf", "microdnf", "yum"}) || !reflect.DeepEqual(el10.RequiredCommands, []string{"dnf", "rpm", "needs-restarting"}) {
		t.Fatalf("command metadata = managers %v, required %v", el10.PackageManagers, el10.RequiredCommands)
	}
	if el10.AutomaticConfig != "/etc/dnf/automatic.conf" || el10.AutomaticTimer != "dnf-automatic.timer" || el10.AutomaticService != "dnf-automatic.service" {
		t.Fatalf("automatic metadata = config %q timer %q service %q", el10.AutomaticConfig, el10.AutomaticTimer, el10.AutomaticService)
	}
	if want := []string{"dnf-automatic-notifyonly.timer", "dnf-automatic-download.timer", "dnf-automatic-install.timer"}; !reflect.DeepEqual(el10.AutomaticTimerVariants, want) {
		t.Fatalf("AutomaticTimerVariants = %v, want %v", el10.AutomaticTimerVariants, want)
	}
	if got := el10.RestartHintProbe; got.Name != "needs-restarting" || !reflect.DeepEqual(got.Args, []string{"-r"}) {
		t.Fatalf("RestartHintProbe = %+v", got)
	}
	if got := ProfileFor(OSRelease{ID: "rocky", VersionID: "9.6"}).Packages; !reflect.DeepEqual(got, []string{"dnf-automatic", "ca-certificates", "yum-utils"}) {
		t.Fatalf("EL9 Packages = %v", got)
	}
	if got := ProfileFor(OSRelease{ID: "custom", VersionID: "10", IDLike: "rhel fedora"}); got.Engine != EngineUnknown || len(got.Packages) != 0 {
		t.Fatalf("unprobed EL10 profile = %+v", got)
	}
	if got, ok := ProfileForDetectedEngine(OSRelease{ID: "custom", VersionID: "10", IDLike: "rhel fedora"}, EngineDNF4); !ok || !reflect.DeepEqual(got.Packages, []string{"dnf", "dnf-automatic", "ca-certificates", "yum-utils"}) {
		t.Fatalf("detected EL10 DNF4 profile = %+v ok=%t", got, ok)
	}
	if got := ProfileFor(OSRelease{ID: "fedora", VersionID: "40"}); got.Engine != EngineDNF4 || !reflect.DeepEqual(got.Packages, []string{"dnf-automatic", "ca-certificates", "dnf-utils"}) {
		t.Fatalf("Fedora 40 profile = %+v", got)
	}
}

func TestProfileForAmazonLinux2023UsesDNFUtils(t *testing.T) {
	p := ProfileFor(OSRelease{ID: "amzn", VersionID: "2023"})
	if p.Backend != "dnf" || p.Engine != EngineDNF4 || p.Tier != BestEffort {
		t.Fatalf("identity = backend %q, engine %q, tier %q", p.Backend, p.Engine, p.Tier)
	}
	want := []string{"dnf-automatic", "ca-certificates", "dnf-utils"}
	if !reflect.DeepEqual(p.Packages, want) {
		t.Fatalf("Packages = %v, want %v", p.Packages, want)
	}
	if got := ProfileFor(OSRelease{ID: "rocky", VersionID: "9.6"}).Packages; !reflect.DeepEqual(got, []string{"dnf-automatic", "ca-certificates", "yum-utils"}) {
		t.Fatalf("Rocky Packages = %v; Amazon-specific dependency leaked into EL", got)
	}
}

func TestProfileForDNF5(t *testing.T) {
	p := ProfileFor(OSRelease{ID: "fedora", VersionID: "43"})
	if p.Backend != "dnf" || p.Engine != EngineDNF5 || p.Tier != Supported {
		t.Fatalf("identity = backend %q, engine %q, tier %q", p.Backend, p.Engine, p.Tier)
	}
	if want := []string{"dnf5-plugin-automatic", "ca-certificates", "dnf5-plugins"}; !reflect.DeepEqual(p.Packages, want) {
		t.Fatalf("Packages = %v, want %v", p.Packages, want)
	}
	if !reflect.DeepEqual(p.PackageManagers, []string{"dnf", "dnf5", "microdnf"}) || !reflect.DeepEqual(p.RequiredCommands, []string{"dnf", "rpm"}) {
		t.Fatalf("command metadata = managers %v, required %v", p.PackageManagers, p.RequiredCommands)
	}
	if p.AutomaticConfig != "/etc/dnf/automatic.conf" || p.AutomaticTimer != "dnf5-automatic.timer" || p.AutomaticService != "dnf5-automatic.service" {
		t.Fatalf("automatic metadata = config %q timer %q service %q", p.AutomaticConfig, p.AutomaticTimer, p.AutomaticService)
	}
	if !reflect.DeepEqual(p.AutomaticTimerVariants, []string{"dnf-automatic.timer"}) {
		t.Fatalf("AutomaticTimerVariants = %v", p.AutomaticTimerVariants)
	}
	if got := p.AutomaticProbe; got.Name != "dnf" || !reflect.DeepEqual(got.Args, []string{"automatic", "--help"}) {
		t.Fatalf("AutomaticProbe = %+v", got)
	}
	if got := p.RestartHintProbe; got.Name != "dnf" || !reflect.DeepEqual(got.Args, []string{"needs-restarting"}) {
		t.Fatalf("RestartHintProbe = %+v", got)
	}
	if got := p.RestartServicesProbe; got.Name != "dnf" || !reflect.DeepEqual(got.Args, []string{"needs-restarting", "-s"}) {
		t.Fatalf("RestartServicesProbe = %+v", got)
	}
}

func TestProfileEngineBoundaries(t *testing.T) {
	cases := []struct {
		name string
		o    OSRelease
		want string
	}{
		{name: "Fedora 40 DNF4", o: OSRelease{ID: "fedora", VersionID: "40"}, want: EngineDNF4},
		{name: "Fedora 41 DNF5", o: OSRelease{ID: "fedora", VersionID: "41"}, want: EngineDNF5},
		{name: "Fedora 44 DNF5", o: OSRelease{ID: "fedora", VersionID: "44"}, want: EngineDNF5},
		{name: "malformed Fedora", o: OSRelease{ID: "fedora", VersionID: "43.rawhide"}, want: EngineUnknown},
		{name: "overflowing Fedora", o: OSRelease{ID: "fedora", VersionID: "999999999999999999999999"}, want: EngineUnknown},
		{name: "RHEL derivative requires probe", o: OSRelease{ID: "custom", VersionID: "10", IDLike: "rhel fedora"}, want: EngineUnknown},
		{name: "conflicting derivative", o: OSRelease{ID: "custom", VersionID: "10", IDLike: "debian rhel"}, want: EngineUnknown},
		{name: "Fedora-only derivative unknown", o: OSRelease{ID: "custom", VersionID: "43", IDLike: "fedora"}, want: EngineUnknown},
		{name: "Ubuntu derivative", o: OSRelease{ID: "linuxmint", VersionID: "22", IDLike: "ubuntu debian"}, want: EngineAPT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProfileFor(tc.o).Engine; got != tc.want {
				t.Fatalf("Engine = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProfileMarksOnlyReliablyInferredDerivatives(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    OSRelease
		want bool
	}{
		{name: "known release", o: OSRelease{ID: "rocky", VersionID: "10", IDLike: "rhel"}},
		{name: "RHEL derivative", o: OSRelease{ID: "custom", VersionID: "10", IDLike: "rhel fedora"}, want: true},
		{name: "conflicting derivative", o: OSRelease{ID: "custom", VersionID: "10", IDLike: "debian rhel"}},
		{name: "Ubuntu derivative", o: OSRelease{ID: "custom", VersionID: "24", IDLike: "ubuntu debian"}, want: true},
		{name: "Fedora derivative requires probe", o: OSRelease{ID: "custom", VersionID: "43", IDLike: "fedora"}, want: true},
		{name: "unknown family", o: OSRelease{ID: "custom", VersionID: "1", IDLike: "suse"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProfileFor(tc.o).Inferred; got != tc.want {
				t.Fatalf("Inferred=%v want %v", got, tc.want)
			}
		})
	}
}

func TestProfileForDetectedEngineIsLimitedToInferredDNFDerivatives(t *testing.T) {
	for _, test := range []struct {
		name       string
		release    OSRelease
		engine     string
		wantOK     bool
		wantEngine string
		wantTools  string
	}{
		{
			name: "EL derivative DNF4", release: OSRelease{ID: "custom", VersionID: "10", IDLike: "rhel fedora"},
			engine: EngineDNF4, wantOK: true, wantEngine: EngineDNF4, wantTools: "yum-utils",
		},
		{
			name: "Fedora derivative DNF4", release: OSRelease{ID: "custom", VersionID: "40", IDLike: "fedora"},
			engine: EngineDNF4, wantOK: true, wantEngine: EngineDNF4, wantTools: "dnf-utils",
		},
		{
			name: "Fedora derivative DNF5", release: OSRelease{ID: "custom", VersionID: "43", IDLike: "fedora"},
			engine: EngineDNF5, wantOK: true, wantEngine: EngineDNF5, wantTools: "dnf5-plugins",
		},
		{
			name: "known Fedora cannot be overridden", release: OSRelease{ID: "fedora", VersionID: "43"},
			engine: EngineDNF4, wantEngine: EngineDNF5, wantTools: "dnf5-plugins",
		},
		{
			name: "APT derivative cannot be overridden", release: OSRelease{ID: "custom", VersionID: "1", IDLike: "debian"},
			engine: EngineDNF5, wantEngine: EngineAPT,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile, ok := ProfileForDetectedEngine(test.release, test.engine)
			if ok != test.wantOK || profile.Engine != test.wantEngine {
				t.Fatalf("ProfileForDetectedEngine = %+v ok=%t", profile, ok)
			}
			if test.wantTools != "" && !containsString(profile.Packages, test.wantTools) {
				t.Fatalf("packages %v do not contain %q", profile.Packages, test.wantTools)
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestProfileForReturnsIndependentSlices(t *testing.T) {
	first := ProfileFor(OSRelease{ID: "fedora", VersionID: "43"})
	first.Packages[0] = "changed"
	first.PackageProbe.Args[0] = "changed"
	first.PackageManagers[0] = "changed"
	first.RequiredCommands[0] = "changed"
	first.AutomaticProbe.Args[0] = "changed"

	second := ProfileFor(OSRelease{ID: "fedora", VersionID: "43"})
	if second.Packages[0] != "dnf5-plugin-automatic" || second.PackageProbe.Args[0] != "-q" || second.PackageManagers[0] != "dnf" || second.RequiredCommands[0] != "dnf" || second.AutomaticProbe.Args[0] != "automatic" {
		t.Fatalf("ProfileFor reused mutable slices: %+v", second)
	}

	dnf4First := ProfileFor(OSRelease{ID: "rocky", VersionID: "10"})
	dnf4First.AutomaticTimerVariants[0] = "changed"
	dnf4Second := ProfileFor(OSRelease{ID: "rocky", VersionID: "10"})
	if dnf4Second.AutomaticTimerVariants[0] != "dnf-automatic-notifyonly.timer" {
		t.Fatalf("ProfileFor reused automatic timer variants: %+v", dnf4Second)
	}
}
