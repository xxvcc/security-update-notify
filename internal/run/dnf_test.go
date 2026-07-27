package run

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
)

func TestDNF5CommandPlan(t *testing.T) {
	runtime := dnfRuntime{Command: "dnf", Generation: backend.DNF5, GenerationKnown: true, Available: true}
	if got, want := runtime.advisoryArgs(false), []string{"-q", "advisory", "list", "--security", "--updates", "--json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("regular advisory args=%q want %q", got, want)
	}
	if got, want := runtime.advisoryArgs(true), []string{"-q", "--setopt=exclude=", "--setopt=excludepkgs=", "--setopt=*.excludepkgs=", "advisory", "list", "--security", "--updates", "--json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unrestricted advisory args=%q want %q", got, want)
	}
	if got, want := runtime.checkUpgradeArgs(false), []string{"-q", "check-upgrade", "--security"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("check-upgrade args=%q want %q", got, want)
	}
	if got, want := runtime.checkUpgradeArgs(true), []string{"-q", "--setopt=disable_excludes=*", "check-upgrade", "--security"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unrestricted check-upgrade args=%q want %q", got, want)
	}
}

func TestDetectDNFRuntimeAcceptsExplicitDNF5Binary(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf5", "printf '%s\\n' 'dnf5 version 5.4.2.1'\n")
	t.Setenv("PATH", dir)
	runtime := detectDNFRuntime(time.Second)
	if !runtime.Available || !runtime.GenerationKnown || runtime.Command != "dnf5" || runtime.Generation != backend.DNF5 {
		t.Fatalf("runtime=%+v", runtime)
	}
}

func TestDetectDNFRuntimeFallsThroughAmbiguousDNFToExplicitDNF5(t *testing.T) {
	dir := t.TempDir()
	callLog := filepath.Join(t.TempDir(), "dnf.calls")
	writeTestCommand(t, dir, "dnf", `
printf '%s\n' "dnf:$*" >> "$SUN_DNF_CALL_LOG"
printf '%s\n' 'dnf version future'
`)
	writeTestCommand(t, dir, "dnf5", `printf '%s\n' "dnf5:$*" >> "$SUN_DNF_CALL_LOG"`)
	t.Setenv("PATH", dir)
	t.Setenv("SUN_DNF_CALL_LOG", callLog)

	runtime := detectDNFRuntime(time.Second)
	if !runtime.Available || !runtime.GenerationKnown || runtime.Command != "dnf5" || runtime.Generation != backend.DNF5 {
		t.Fatalf("runtime=%+v", runtime)
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(calls); got != "dnf:--version\n" {
		t.Fatalf("calls=%q", got)
	}
}

func TestDetectDNFRuntimeRejectsFailedOrUnknownVersionProbe(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown output", body: "printf '%s\\n' 'dnf version future'\n"},
		{name: "failed despite recognizable output", body: "printf '%s\\n' '4.14.0'\nexit 2\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			callLog := filepath.Join(t.TempDir(), "dnf.calls")
			writeTestCommand(t, dir, "dnf", "printf '%s\\n' \"$*\" >> \"$SUN_DNF_CALL_LOG\"\n"+test.body)
			t.Setenv("PATH", dir)
			t.Setenv("SUN_DNF_CALL_LOG", callLog)

			runtime := detectDNFRuntime(time.Second)
			if !runtime.Available || runtime.GenerationKnown || runtime.Command != "dnf" {
				t.Fatalf("runtime=%+v", runtime)
			}
			calls, err := os.ReadFile(callLog)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(calls); got != "--version\n" {
				t.Fatalf("calls=%q want only generation probe", got)
			}
		})
	}
}

func TestUnknownDNFGenerationSkipsRestartAndHealthFallbacks(t *testing.T) {
	dir := t.TempDir()
	callLog := filepath.Join(t.TempDir(), "commands.calls")
	writeTestCommand(t, dir, "dnf", `
printf '%s\n' "dnf:$*" >> "$SUN_DNF_CALL_LOG"
printf '%s\n' 'dnf version future'
`)
	writeTestCommand(t, dir, "needs-restarting", `printf '%s\n' "needs-restarting:$*" >> "$SUN_DNF_CALL_LOG"`)
	writeTestCommand(t, dir, "systemctl", `printf '%s\n' "systemctl:$*" >> "$SUN_DNF_CALL_LOG"`)
	t.Setenv("PATH", dir)
	t.Setenv("SUN_DNF_CALL_LOG", callLog)

	state := collectDNFWithTimeout(time.Second)
	if state.RebootRequired || state.RestartAttention || state.ProbeIssue != "dnf-restart-probe-failed" || !strings.Contains(state.RestartSummary, "generation probe failed") {
		t.Fatalf("state=%+v", state)
	}
	if health := collectHealth("dnf", 7); health.Attention || health.Sig != "" || health.TxtEN != "" || health.TxtZH != "" {
		t.Fatalf("health=%+v", health)
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(calls); got != "dnf:--version\ndnf:--version\n" {
		t.Fatalf("calls=%q; DNF4 fallback command executed", got)
	}
}

func TestCollectDNF5UsesNativeNeedsRestartingSubcommand(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.2.18.0' ;;
  "needs-restarting --help") printf '%s\n' 'usage: dnf5 needs-restarting [-r] [-s]' ;;
  "-q needs-restarting") printf '%s\n' 'Reboot is required to fully utilize these updates.'; exit 1 ;;
  "-q needs-restarting -s") printf '%s\n' 'sshd.service' 'crond.service'; exit 1 ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)

	state := collectDNFWithTimeout(time.Second)
	if !state.RebootRequired || !state.RestartAttention || state.RestartSignal != "crond.service\nsshd.service" {
		t.Fatalf("state=%+v", state)
	}
	if !strings.Contains(state.RestartSummary, "dnf needs-restarting:\\n") || strings.Contains(state.RestartSummary, "needs-restarting -r:\\n") {
		t.Fatalf("summary=%q", state.RestartSummary)
	}
}

func TestCollectDNF5ReportsServicesProbeFailure(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  "needs-restarting --help") printf '%s\n' 'usage: dnf5 needs-restarting [-s]' ;;
  "-q needs-restarting") printf '%s\n' 'Reboot should not be necessary.' ;;
  "-q needs-restarting -s") printf '%s\n' 'D-Bus unavailable' >&2; exit 1 ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)

	state := collectDNFWithTimeout(time.Second)
	if state.ProbeIssue != "dnf-restart-probe-failed" || state.RestartAttention || state.RestartSignal != "" {
		t.Fatalf("state=%+v", state)
	}
}

func TestCollectDNF5RequiresDocumentedRebootTextStatusPairs(t *testing.T) {
	for _, test := range []struct {
		name       string
		output     string
		rc         string
		wantReboot bool
		wantIssue  bool
	}{
		{name: "no reboot", output: "Reboot should not be necessary.", rc: "0"},
		{name: "reboot required", output: "Reboot is required to fully utilize these updates.", rc: "1", wantReboot: true},
		{name: "required with success status", output: "Reboot is required.", rc: "0", wantIssue: true},
		{name: "unsupported required wording", output: "Reboot is required to apply updates.", rc: "1", wantIssue: true},
		{name: "not needed with reboot status", output: "Reboot should not be necessary.", rc: "1", wantIssue: true},
		{name: "empty success", output: "", rc: "0", wantIssue: true},
		{name: "generic error with reboot status", output: "metadata load failed", rc: "1", wantIssue: true},
		{name: "conflicting text", output: "Reboot is required to fully utilize these updates.\nReboot should not be necessary.", rc: "1", wantIssue: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  "needs-restarting --help") printf '%s\n' 'usage: dnf5 needs-restarting [-s]' ;;
  "-q needs-restarting") printf '%s\n' "$SUN_DNF_REBOOT_OUTPUT"; exit "$SUN_DNF_REBOOT_RC" ;;
  "-q needs-restarting -s") exit 0 ;;
  *) exit 2 ;;
esac
`)
			t.Setenv("PATH", dir)
			t.Setenv("SUN_DNF_REBOOT_OUTPUT", test.output)
			t.Setenv("SUN_DNF_REBOOT_RC", test.rc)

			state := collectDNFWithTimeout(time.Second)
			if state.RebootRequired != test.wantReboot || state.RestartAttention || (state.ProbeIssue != "") != test.wantIssue {
				t.Fatalf("state=%+v wantIssue=%v", state, test.wantIssue)
			}
		})
	}
}

func TestCollectDNF5DoesNotTrustRebootStatusOnStderr(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  "needs-restarting --help") printf '%s\n' 'usage: dnf5 needs-restarting [-s]' ;;
  "-q needs-restarting") printf '%s\n' 'Reboot is required to fully utilize these updates.' >&2; exit 1 ;;
  "-q needs-restarting -s") exit 0 ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)

	state := collectDNFWithTimeout(time.Second)
	if state.ProbeIssue != "dnf-restart-probe-failed" || state.RebootRequired || state.RestartAttention {
		t.Fatalf("state=%+v", state)
	}
}

func TestCollectDNF4DoesNotTrustRebootStatusOnStderr(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", "printf '%s\\n' '4.14.0'\n")
	writeTestCommand(t, dir, "needs-restarting", `
case "$*" in
  "-r") printf '%s\n' 'Reboot is required to fully utilize these updates.' >&2; exit 1 ;;
  "--help") printf '%s\n' 'usage: needs-restarting [-r] [-s]' ;;
  "-s") exit 0 ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)

	state := collectDNFWithTimeout(time.Second)
	if state.ProbeIssue != "dnf-restart-probe-failed" || state.RebootRequired || state.RestartAttention {
		t.Fatalf("state=%+v", state)
	}
}

func TestCollectDNF5RejectsUnknownRebootOutputAndMissingServicesCapability(t *testing.T) {
	for _, test := range []struct {
		name string
		help string
	}{
		{name: "unknown reboot output", help: "usage: dnf5 needs-restarting [-s]"},
		{name: "missing services capability", help: "usage: dnf5 needs-restarting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  "needs-restarting --help") printf '%s\n' "$SUN_DNF_HELP" ;;
  "-q needs-restarting") printf '%s\n' 'future reboot status' ;;
  "-q needs-restarting -s") exit 0 ;;
  *) exit 2 ;;
esac
`)
			t.Setenv("PATH", dir)
			t.Setenv("SUN_DNF_HELP", test.help)

			state := collectDNFWithTimeout(time.Second)
			if state.ProbeIssue != "dnf-restart-probe-failed" || state.RebootRequired || state.RestartAttention {
				t.Fatalf("state=%+v", state)
			}
		})
	}
}

func TestSelectDNFAutomaticUnit(t *testing.T) {
	tests := []struct {
		name       string
		generation backend.DNFGeneration
		enabled    map[string]bool
		want       dnfAutomaticUnit
		wantCalls  []string
	}{
		{
			name:       "dnf5 native",
			generation: backend.DNF5,
			enabled:    map[string]bool{"dnf5-automatic.timer": true},
			want:       dnfAutomaticUnit{Timer: "dnf5-automatic.timer", Service: "dnf5-automatic.service", Enabled: true},
			wantCalls:  []string{"dnf5-automatic.timer"},
		},
		{
			name:       "dnf5 compatibility alias",
			generation: backend.DNF5,
			enabled:    map[string]bool{"dnf-automatic.timer": true},
			want:       dnfAutomaticUnit{Timer: "dnf-automatic.timer", Service: "dnf-automatic.service", Enabled: true},
			wantCalls:  []string{"dnf5-automatic.timer", "dnf-automatic.timer"},
		},
		{
			name:       "dnf5 disabled reports native",
			generation: backend.DNF5,
			enabled:    map[string]bool{},
			want:       dnfAutomaticUnit{Timer: "dnf5-automatic.timer", Service: "dnf5-automatic.service"},
			wantCalls:  []string{"dnf5-automatic.timer", "dnf-automatic.timer"},
		},
		{
			name:       "dnf4",
			generation: backend.DNF4,
			enabled:    map[string]bool{"dnf-automatic.timer": true},
			want:       dnfAutomaticUnit{Timer: "dnf-automatic.timer", Service: "dnf-automatic.service", Enabled: true},
			wantCalls:  []string{"dnf-automatic.timer"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			got := selectDNFAutomaticUnit(test.generation, func(unit string) bool {
				calls = append(calls, unit)
				return test.enabled[unit]
			})
			if got != test.want || !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("unit=%+v calls=%v want=%+v calls=%v", got, calls, test.want, test.wantCalls)
			}
		})
	}
}
