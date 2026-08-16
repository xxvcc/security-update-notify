package cli

import (
	"bufio"
	"os"
	"strings"
	"syscall"
	"testing"
)

// nonRootTestUID is the effective uid borrowed while exercising the uninstall
// root gate. Any non-zero uid reaches the gate; nobody is the least privileged.
const nonRootTestUID = 65534

// runWithNonRootEUID runs fn with a non-root effective uid. The uninstall root
// gate reads the process euid directly, so a test process that happens to be
// root has to drop privileges for real to reach it; the drop is reverted as
// soon as fn returns, and fn is never invoked while the process could still
// uninstall the host.
func runWithNonRootEUID(t *testing.T, fn func() int) int {
	t.Helper()
	if os.Geteuid() == 0 {
		if err := syscall.Setresuid(-1, nonRootTestUID, 0); err != nil {
			t.Skipf("cannot drop the effective uid to reach the root gate: %v", err)
		}
		defer func() {
			if err := syscall.Setresuid(-1, 0, 0); err != nil {
				t.Fatalf("restore effective uid: %v", err)
			}
		}()
	}
	if os.Geteuid() == 0 {
		t.Fatal("effective uid is still root; refusing to run uninstall against this host")
	}
	return fn()
}

func TestConfirmPurgeSkipsTheTypedTokenWithoutATerminal(t *testing.T) {
	tests := []struct {
		name      string
		purge     bool
		assumeYes bool
		want      bool
	}{
		{name: "keeping configuration", want: true},
		{name: "keeping configuration with assumed yes", assumeYes: true, want: true},
		{name: "purge with assumed yes", purge: true, assumeYes: true, want: true},
		// captureCLIOutput hands the command a regular file for os.Stderr, so the
		// terminal gate is closed here: the prompt is skipped and the purge
		// proceeds, which is what keeps existing automation working without -y.
		{name: "purge without a terminal", purge: true, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader("PURGE\n"))
			var got bool
			stdout, stderr, _ := captureCLIOutput(t, func() int {
				got = confirmPurge(test.purge, test.assumeYes, "en", reader)
				return 0
			})
			if got != test.want {
				t.Fatalf("confirmPurge(purge=%v, assumeYes=%v)=%v want %v", test.purge, test.assumeYes, got, test.want)
			}
			if stdout != "" || stderr != "" {
				t.Fatalf("non-interactive confirmation wrote stdout=%q stderr=%q", stdout, stderr)
			}
			// Automation that pipes a script into the CLI must keep every byte it
			// sent; a prompt reading here would swallow the next command instead.
			line, err := readBoundedLine(reader)
			if err != nil || line != "PURGE\n" {
				t.Fatalf("confirmation consumed buffered input: line=%q err=%v", line, err)
			}
		})
	}
}

func TestUninstallAssumeYesFlagsParseAndStopAtTheRootGate(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long flag with purge", args: []string{"uninstall", "--yes", "--purge-config", "--lang", "en"}},
		{name: "purge before long flag", args: []string{"uninstall", "--purge-config", "--yes", "--lang", "en"}},
		{name: "short flag", args: []string{"uninstall", "-y", "--lang", "en"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, rc := captureCLIOutput(t, func() int {
				return runWithNonRootEUID(t, func() int { return Main("3.2.0-test", test.args) })
			})
			// The root gate is the first check after argument parsing, so stopping
			// there proves the flag was understood rather than rejected.
			if rc != 1 || !strings.Contains(stderr, "Please run as root") || stdout != "" {
				t.Fatalf("Main(%q) rc=%d stdout=%q stderr=%q", test.args, rc, stdout, stderr)
			}
			if strings.Contains(stderr, "Unknown uninstall argument") {
				t.Fatalf("Main(%q) rejected a supported flag: %q", test.args, stderr)
			}
		})
	}
}

func TestUninstallStillRejectsUnknownAssumeYesSpellings(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "assume yes", args: []string{"uninstall", "--assume-yes", "--lang", "en"}},
		{name: "force", args: []string{"uninstall", "--purge-config", "-f", "--lang", "en"}},
		{name: "bare y", args: []string{"uninstall", "y"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Rejection happens in the argument loop, before the root gate, so this
			// never reaches the uninstaller regardless of the effective uid.
			stdout, stderr, rc := captureCLIOutput(t, func() int { return Main("3.2.0-test", test.args) })
			if rc != 2 || !strings.Contains(stderr, "Unknown uninstall argument") || stdout != "" {
				t.Fatalf("Main(%q) rc=%d stdout=%q stderr=%q", test.args, rc, stdout, stderr)
			}
		})
	}
}

func TestUninstallHelpDocumentsTheAssumeYesFlag(t *testing.T) {
	t.Setenv("UI_LANG", "")
	t.Setenv("SUN_LANG", "")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "english",
			args: []string{"uninstall", "--help", "--lang", "en"},
			want: "Usage: security-update-notify uninstall [--purge-config] [--yes] [--lang zh|en]",
		},
		{
			name: "default chinese",
			args: []string{"uninstall", "--help"},
			want: "用法: security-update-notify uninstall [--purge-config] [--yes] [--lang zh|en]",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, rc := captureCLIOutput(t, func() int { return Main("3.2.0-test", test.args) })
			if rc != 0 || !strings.Contains(stdout, test.want) || stderr != "" {
				t.Fatalf("Main(%q) rc=%d stdout=%q stderr=%q", test.args, rc, stdout, stderr)
			}
		})
	}
}

func TestGlobalHelpDocumentsTheUninstallAssumeYesFlag(t *testing.T) {
	stdout, stderr, rc := captureCLIOutput(t, func() int {
		return Main("3.3.0-test", []string{"--help"})
	})
	if rc != 0 || stdout != "" {
		t.Fatalf("Main(--help) rc=%d stdout=%q stderr=%q", rc, stdout, stderr)
	}
	const want = "\n  security-update-notify uninstall [--purge-config] [--yes] [--lang zh|en]\n"
	if !strings.Contains(stderr, want) {
		t.Fatalf("global help does not document --yes: %q", stderr)
	}
}

// TestConfirmPurgeRequiresTheExactTokenAtATerminal drives the interactive half of
// the purge gate through injected terminal probes. The prompt itself is the part
// that protects an administrator from an irreversible command, so it must be
// exercised rather than assumed.
func TestConfirmPurgeRequiresTheExactTokenAtATerminal(t *testing.T) {
	terminal := func() bool { return true }
	tests := []struct {
		name    string
		input   string
		want    bool
		message string
	}{
		{name: "exact token", input: "PURGE\n", want: true},
		{name: "exact token without a trailing newline", input: "PURGE", want: true},
		{name: "lower case", input: "purge\n", message: "Confirmation did not match"},
		{name: "token with trailing text", input: "PURGE now\n", message: "Confirmation did not match"},
		{name: "empty line", input: "\n", message: "Confirmation did not match"},
		{name: "end of input", input: "", message: "Confirmation did not match"},
		{name: "oversized line", input: strings.Repeat("P", 70<<10) + "\n", message: "Unable to read input"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var out strings.Builder
			reader := bufio.NewReader(strings.NewReader(test.input))
			got := confirmPurgeWith(true, false, "en", reader, &out, terminal, terminal)
			if got != test.want {
				t.Fatalf("confirmPurgeWith(%q) = %v, want %v", test.name, got, test.want)
			}
			if !strings.Contains(out.String(), "Type PURGE to confirm:") {
				t.Fatalf("prompt was not shown at a terminal: %q", out.String())
			}
			if !strings.Contains(out.String(), "removes SUN configuration") {
				t.Fatalf("consequences were not shown before the prompt: %q", out.String())
			}
			if test.message != "" && !strings.Contains(out.String(), test.message) {
				t.Fatalf("output = %q, want it to mention %q", out.String(), test.message)
			}
		})
	}
}

// TestConfirmPurgeConsumesOnlyItsOwnAnswer pins that the shared buffered reader
// is left positioned at the next line, so a caller that already read from stdin
// never loses input to this prompt.
func TestConfirmPurgeConsumesOnlyItsOwnAnswer(t *testing.T) {
	terminal := func() bool { return true }
	reader := bufio.NewReader(strings.NewReader("PURGE\nnext-line\n"))
	var out strings.Builder
	if !confirmPurgeWith(true, false, "en", reader, &out, terminal, terminal) {
		t.Fatal("exact token was rejected")
	}
	remaining, err := readBoundedLine(reader)
	if err != nil {
		t.Fatalf("read remaining input: %v", err)
	}
	if remaining != "next-line\n" {
		t.Fatalf("remaining input = %q, want %q", remaining, "next-line\n")
	}
}

// TestConfirmPurgeSkipsThePromptWhenOnlyOneStreamIsATerminal keeps the gate from
// prompting where the question could not be seen or answered.
func TestConfirmPurgeSkipsThePromptWhenOnlyOneStreamIsATerminal(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }
	tests := []struct {
		name               string
		stdinTTY, stderrTT func() bool
	}{
		{name: "only stdin is a terminal", stdinTTY: yes, stderrTT: no},
		{name: "only stderr is a terminal", stdinTTY: no, stderrTT: yes},
		{name: "neither stream is a terminal", stdinTTY: no, stderrTT: no},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var out strings.Builder
			reader := bufio.NewReader(strings.NewReader("unrelated automation input\n"))
			if !confirmPurgeWith(true, false, "en", reader, &out, test.stdinTTY, test.stderrTT) {
				t.Fatal("non-interactive purge was blocked")
			}
			if out.String() != "" {
				t.Fatalf("wrote %q without a usable terminal", out.String())
			}
			line, err := readBoundedLine(reader)
			if err != nil || line != "unrelated automation input\n" {
				t.Fatalf("automation input was consumed: line=%q err=%v", line, err)
			}
		})
	}
}
