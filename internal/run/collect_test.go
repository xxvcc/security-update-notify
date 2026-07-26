package run

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
)

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
	writeTestCommand(t, dir, "needs-restarting", `
case "$1" in
  -r) printf '%s\n' 'Reboot is required to apply updates.' >&2; exit 1 ;;
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
	if !strings.Contains(dnf.RestartSummary, "Reboot is required to apply updates.") {
		t.Fatalf("DNF stderr was not preserved in merged -r output: %q", dnf.RestartSummary)
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
