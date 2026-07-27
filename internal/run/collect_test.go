package run

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/osrel"
)

func TestUbuntu2004ESMSupportEndRequiresEnabledInfraService(t *testing.T) {
	status := func(services string) string {
		return `{"_schema_version":"v1","data":{"attributes":{"enabled_services":` + services + `},"type":"EnabledServices"},"errors":[],"result":"success"}`
	}
	for _, test := range []struct {
		name   string
		output string
		code   int
		want   string
	}{
		{name: "esm infra enabled", output: status(`[{"name":"esm-apps"},{"name":"esm-infra"}]`), want: ubuntu2004ESMSupportEnd},
		{name: "unattached", output: status(`[]`), want: "2025-05-31"},
		{name: "only esm apps", output: status(`[{"name":"esm-apps"}]`), want: "2025-05-31"},
		{name: "command failure", output: status(`[{"name":"esm-infra"}]`), code: 1, want: "2025-05-31"},
		{name: "schema drift", output: `{"_schema_version":"v2","data":{"attributes":{"enabled_services":[{"name":"esm-infra"}]},"type":"EnabledServices"},"errors":[],"result":"success"}`, want: "2025-05-31"},
		{name: "missing errors", output: `{"_schema_version":"v1","data":{"attributes":{"enabled_services":[{"name":"esm-infra"}]},"type":"EnabledServices"},"result":"success"}`, want: "2025-05-31"},
		{name: "null services", output: `{"_schema_version":"v1","data":{"attributes":{"enabled_services":null},"type":"EnabledServices"},"errors":[],"result":"success"}`, want: "2025-05-31"},
		{name: "malformed", output: `{`, want: "2025-05-31"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestCommand(t, dir, "pro", fmt.Sprintf("printf '%%s\\n' '%s'\nexit %d\n", test.output, test.code))
			t.Setenv("PATH", dir)
			got := effectiveSupportEnd(osrel.OSRelease{ID: "ubuntu", VersionID: "20.04", PrettyName: "Ubuntu 20.04 LTS"})
			if got != test.want {
				t.Fatalf("effectiveSupportEnd()=%q want %q", got, test.want)
			}
		})
	}
}

func TestEffectiveSupportEndPreservesOSReleaseOverride(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	o := osrel.OSRelease{ID: "custom", VersionID: "1", SupportEnd: "2032-06-30"}
	if got := effectiveSupportEnd(o); got != o.SupportEnd {
		t.Fatalf("effectiveSupportEnd()=%q want %q", got, o.SupportEnd)
	}
}

func TestUbuntu2004IgnoresGenericSupportEndWithoutESM(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	o := osrel.OSRelease{
		ID: "ubuntu", VersionID: "20.04", PrettyName: "Ubuntu 20.04 LTS", SupportEnd: ubuntu2004ESMSupportEnd,
	}
	if got := effectiveSupportEnd(o); got != "2025-05-31" {
		t.Fatalf("effectiveSupportEnd()=%q want standard-maintenance end", got)
	}
}

func TestCollectTestModeOrchestratesPackageCollection(t *testing.T) {
	t.Run("dnf truncates reboot package details", func(t *testing.T) {
		dir := t.TempDir()
		var output strings.Builder
		output.WriteString("if [ \"$1\" = \"--version\" ]; then printf '%s\\n' '4.14.0'; exit 0; fi\n")
		for i := 0; i < 45; i++ {
			fmt.Fprintf(&output, "printf 'RHSA-2026:%04d Important/Sec. package%02d.x86_64\\n'\n", i, i)
		}
		writeTestCommand(t, dir, "dnf", output.String())
		writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-test'\n")
		t.Setenv("PATH", dir)

		cfg := patchTestConfig(t, strings.Join([]string{
			"BACKEND=dnf",
			"HOST_LABEL=fixture-host",
			"PUBLIC_IP=203.0.113.9",
			"INCLUDE_PUBLIC_IP=1",
			"NOTIFY_LANG=en",
			"CHECK_UPDATE_HEALTH=0",
			"CHECK_EOL=0",
			"CHECK_SELF_UPDATE=0",
		}, "\n")+"\n")
		in := Collect(cfg, Flags{TestReboot: true, TestOK: true, Version: "2.7.3"})

		if in.Backend != "dnf" || in.Host != "fixture-host" || in.Kernel != "6.12-test" {
			t.Fatalf("identity fields: backend=%q host=%q kernel=%q", in.Backend, in.Host, in.Kernel)
		}
		if !in.IncludePublicIP || in.PublicIP != "203.0.113.9" || in.NotifyLang != "en" {
			t.Fatalf("notification fields: includeIP=%v ip=%q lang=%q", in.IncludePublicIP, in.PublicIP, in.NotifyLang)
		}
		if in.Pending.Count != 45 || len(in.Pending.Packages) != 45 {
			t.Fatalf("pending=%d packages=%d", in.Pending.Count, len(in.Pending.Packages))
		}
		pkgs := strings.Split(in.Restart.RebootPkgs, "\n")
		if len(pkgs) != 40 || pkgs[0] != "package00.x86_64" || pkgs[39] != "package39.x86_64" {
			t.Fatalf("truncated reboot packages (%d): first=%q last=%q", len(pkgs), pkgs[0], pkgs[len(pkgs)-1])
		}
		if !in.Restart.RebootRequired || !in.Restart.RestartAttention || !in.SendOK {
			t.Fatalf("test flags were not preserved: restart=%+v sendOK=%v", in.Restart, in.SendOK)
		}
	})

	t.Run("apt keeps fixture reboot details", func(t *testing.T) {
		dir := t.TempDir()
		writeTestCommand(t, dir, "apt-get", "printf '%s\\n' 'Inst openssl [1] (2 Debian-Security:stable-security [amd64])'\n")
		writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.1-test'\n")
		t.Setenv("PATH", dir)

		cfg := patchTestConfig(t, "BACKEND=apt\nHOST_LABEL=apt-host\nINCLUDE_PUBLIC_IP=0\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n")
		in := Collect(cfg, Flags{TestReboot: true})
		if in.Pending.Count != 1 || in.Restart.RebootPkgs != "linux-image-amd64\nTEST-MODE-no-real-reboot" {
			t.Fatalf("pending=%d restart packages=%q", in.Pending.Count, in.Restart.RebootPkgs)
		}
		if in.IncludePublicIP || in.PublicIP != "" {
			t.Fatalf("disabled public IP was included: include=%v ip=%q", in.IncludePublicIP, in.PublicIP)
		}
	})
}

func TestCollectHealthUsesSystemdCommandResults(t *testing.T) {
	dir := t.TempDir()
	epoch := time.Now().Unix()
	callLog := filepath.Join(t.TempDir(), "systemctl.calls")
	writeTestCommand(t, dir, "systemctl", `
printf '%s\n' "$*" >> "$SUN_SYSTEMCTL_CALL_LOG"
case "$1:$4" in
  is-enabled:*) printf '%s\n' enabled ;;
  show:ExecMainExitTimestamp) printf '%s\n' 'fixture timestamp' ;;
  show:LastTriggerUSec) printf '%s\n' 'fixture timestamp' ;;
  show:Result) printf '%s\n' 'success' ;;
  *) exit 2 ;;
esac
`)
	writeTestCommand(t, dir, "date", fmt.Sprintf("printf '%%s\\n' '%d'\n", epoch))
	t.Setenv("PATH", dir)
	t.Setenv("SUN_SYSTEMCTL_CALL_LOG", callLog)

	health := collectHealth("apt", 7)
	for _, unexpected := range []string{"disabled", "failed", "stale", "never-success"} {
		if strings.Contains(health.Sig, unexpected) {
			t.Fatalf("health signal %q contains %q", health.Sig, unexpected)
		}
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	callText := string(calls)
	for _, want := range []string{
		"show apt-daily-upgrade.service -p ExecMainExitTimestamp --value",
		"show apt-daily-upgrade.timer -p LastTriggerUSec --value",
		"is-enabled apt-daily-upgrade.timer",
		"show apt-daily-upgrade.service -p Result --value",
	} {
		if strings.Count(callText, want+"\n") != 1 {
			t.Fatalf("systemctl calls missing or repeated %q:\n%s", want, callText)
		}
	}
	if got := collectHealth("unsupported", 7); got.Attention || got.Sig != "" {
		t.Fatalf("unsupported backend health=%+v", got)
	}
}

func TestIdentityCommandErrorFallbacks(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "date", "printf '%s\\n' not-an-epoch\n")
	writeTestCommand(t, dir, "hostname", `
if [ "$1" = "-f" ]; then
  exit 1
fi
printf '%s\n' short-host
`)
	writeTestCommand(t, dir, "uname", "printf '\\n'\n")
	t.Setenv("PATH", dir)

	if got := parseSystemdTime("bad timestamp"); got != 0 {
		t.Fatalf("invalid epoch=%d", got)
	}
	if got := hostLabel(loadEmptyConfig(t)); got != "short-host" {
		t.Fatalf("fallback hostname=%q", got)
	}
	if got := kernelRelease(); got != "unknown" {
		t.Fatalf("empty kernel release=%q", got)
	}
}

func TestReadFilePrefixIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reboot-required.pkgs")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readFilePrefix(path, 7); got != "xxxxxxx" {
		t.Fatalf("got %q", got)
	}
	if got := readFilePrefix(filepath.Join(t.TempDir(), "missing"), 7); got != "" {
		t.Fatalf("missing file returned %q", got)
	}
}

func TestDiskAvailableKBSaturatesWithoutOverflow(t *testing.T) {
	tests := []struct {
		name      string
		blocks    uint64
		blockSize int64
		want      int64
	}{
		{name: "ordinary", blocks: 1000, blockSize: 4096, want: 4000},
		{name: "fractional kilobyte", blocks: 3, blockSize: 512, want: 1},
		{name: "zero block size", blocks: 1000, blockSize: 0, want: 0},
		{name: "negative block size", blocks: 1000, blockSize: -1, want: 0},
		{name: "int64 boundary", blocks: uint64(math.MaxInt64), blockSize: 1024, want: math.MaxInt64},
		{name: "saturates above int64", blocks: math.MaxUint64, blockSize: math.MaxInt64, want: math.MaxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := diskAvailableKB(tt.blocks, tt.blockSize); got != tt.want {
				t.Fatalf("diskAvailableKB(%d, %d) = %d, want %d", tt.blocks, tt.blockSize, got, tt.want)
			}
		})
	}
}

func TestBoundedCommandCollectionPreservesParsing(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "needrestart", `
[ "$1" = "-b" ] || exit 2
printf '%s\n' \
  'NEEDRESTART-KCUR: 6.1-old' \
  'NEEDRESTART-KEXP: 6.1-new' \
  'NEEDRESTART-KSTA: 3' \
  'NEEDRESTART-SVC: ssh.service'
`)
	writeTestCommand(t, dir, "dnf", `
[ "$1" = "--version" ] || exit 2
printf '%s\n' '4.14.0'
`)
	writeTestCommand(t, dir, "needs-restarting", `
case "$1" in
  -r) printf '%s\n' 'Reboot is required to fully utilize these updates.'; exit 1 ;;
  --help) printf '%s\n' 'usage: needs-restarting [-r] [-s]' ;;
  -s) printf '%s\n' 'sshd.service' 'crond.service' ;;
  *) exit 2 ;;
esac
`)
	writeTestCommand(t, dir, "date", `
[ "$1" = "-d" ] || exit 2
printf '%s\n' '1700000000'
`)
	writeTestCommand(t, dir, "hostname", `
if [ "$1" = "-f" ]; then
  printf '%s\n' 'host.example.test'
else
  printf '%s\n' 'host'
fi
`)
	writeTestCommand(t, dir, "uname", `
[ "$1" = "-r" ] || exit 2
printf '%s\n' '6.12-test'
`)
	t.Setenv("PATH", dir)

	apt := collectAPTWithTimeout(time.Second)
	if !apt.RestartAttention {
		t.Fatal("collectAPTWithTimeout() lost needrestart attention state")
	}
	wantAPTSignal := "KCUR=6.1-old\nKEXP=6.1-new\nKSTA=3\nssh.service"
	if apt.RestartSignal != wantAPTSignal {
		t.Fatalf("APT restart signal = %q, want %q", apt.RestartSignal, wantAPTSignal)
	}

	dnf := collectDNFWithTimeout(time.Second)
	if !dnf.RebootRequired || !dnf.RestartAttention {
		t.Fatalf("DNF state lost parsed output: reboot=%v attention=%v", dnf.RebootRequired, dnf.RestartAttention)
	}
	if dnf.RestartSignal != "crond.service\nsshd.service" {
		t.Fatalf("DNF restart signal = %q", dnf.RestartSignal)
	}
	if !strings.Contains(dnf.RestartSummary, "Reboot is required to fully utilize these updates.") {
		t.Fatalf("DNF stdout was not preserved in restart summary: %q", dnf.RestartSummary)
	}

	if got := parseSystemdTimeWithTimeout("ignored fixture", time.Second); got != 1700000000 {
		t.Fatalf("parseSystemdTimeWithTimeout() = %d", got)
	}
	cfg := loadEmptyConfig(t)
	if got := hostLabelWithTimeout(cfg, time.Second); got != "host.example.test" {
		t.Fatalf("hostLabelWithTimeout() = %q", got)
	}
	if got := kernelReleaseWithTimeout(time.Second); got != "6.12-test" {
		t.Fatalf("kernelReleaseWithTimeout() = %q", got)
	}
}

func TestBoundedCommandCollectionTimesOut(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"needrestart", "needs-restarting", "date", "hostname", "uname"} {
		writeTestCommand(t, dir, name, "\nexec /bin/sleep 1\n")
	}
	writeTestCommand(t, dir, "dnf", "printf '%s\\n' '4.14.0'\n")
	t.Setenv("PATH", dir)
	cfg := loadEmptyConfig(t)
	const timeout = 25 * time.Millisecond

	started := time.Now()
	apt := collectAPTWithTimeout(timeout)
	dnf := collectDNFWithTimeout(timeout)
	epoch := parseSystemdTimeWithTimeout("will time out", timeout)
	host := hostLabelWithTimeout(cfg, timeout)
	kernel := kernelReleaseWithTimeout(timeout)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("bounded collectors took %s; a command likely escaped its timeout", elapsed)
	}

	if apt.RestartAttention {
		t.Fatal("timed-out needrestart produced an attention signal")
	}
	if dnf.RebootRequired || dnf.RestartAttention {
		t.Fatalf("timed-out needs-restarting produced a signal: %+v", dnf)
	}
	if epoch != 0 || host != "unknown" || kernel != "unknown" {
		t.Fatalf("timeout fallbacks: epoch=%d host=%q kernel=%q", epoch, host, kernel)
	}
}

func writeTestCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func loadEmptyConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join(t.TempDir(), "missing.env"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
