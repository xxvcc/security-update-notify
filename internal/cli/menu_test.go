package cli

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

func newMenuTestCommand(input string, lang i18n.Lang, dispatch func([]string) int) (*menuCommand, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	return &menuCommand{
		version:   "3.2.0-test",
		lang:      lang,
		reader:    bufio.NewReader(strings.NewReader(input)),
		out:       &stdout,
		errOut:    &stderr,
		geteuid:   func() int { return 0 },
		stdinTTY:  func() bool { return true },
		stdoutTTY: func() bool { return true },
		stderrTTY: func() bool { return true },
		dispatch:  dispatch,
	}, &stdout, &stderr
}

func TestAliasMenuInvocationRouting(t *testing.T) {
	tests := []struct {
		name  string
		argv0 string
		args  []string
		want  bool
	}{
		{name: "bare short alias", argv0: "/usr/local/sbin/sun", want: true},
		{name: "short alias language", argv0: "sun", args: []string{"--lang", "en"}, want: true},
		{name: "short alias help", argv0: "sun", args: []string{"--help"}, want: true},
		{name: "long name stays automated", argv0: "/usr/local/sbin/security-update-notify", want: false},
		{name: "similar name is not alias", argv0: "/usr/local/sbin/sun-old", want: false},
		{name: "subcommand is forwarded", argv0: "sun", args: []string{"run", "--version"}, want: false},
		{name: "positional language is not menu syntax", argv0: "sun", args: []string{"en"}, want: false},
		{name: "missing language value stays menu syntax", argv0: "sun", args: []string{"--lang"}, want: true},
		{name: "invalid language value stays menu syntax", argv0: "sun", args: []string{"--lang", "fr"}, want: true},
		{name: "help plus invalid value stays menu syntax", argv0: "sun", args: []string{"--help", "--bad"}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isAliasMenuInvocation(test.argv0, test.args); got != test.want {
				t.Fatalf("isAliasMenuInvocation(%q, %q)=%v want %v", test.argv0, test.args, got, test.want)
			}
		})
	}
}

func TestMainAsAliasHelpAndSubcommandForwarding(t *testing.T) {
	stdout, stderr, rc := captureCLIOutput(t, func() int {
		return MainAs("3.2.0-test", "/usr/local/sbin/sun", []string{"--lang", "en", "--help"})
	})
	if rc != 0 || !strings.Contains(stdout, "Usage: security-update-notify menu [--lang zh|en]") || stderr != "" {
		t.Fatalf("alias help rc=%d stdout=%q stderr=%q", rc, stdout, stderr)
	}

	stdout, stderr, rc = captureCLIOutput(t, func() int {
		return MainAs("3.2.0-test", "/usr/local/sbin/sun", []string{"run", "--version"})
	})
	if rc != 0 || stdout != "security-update-notify 3.2.0-test\n" || stderr != "" {
		t.Fatalf("alias subcommand rc=%d stdout=%q stderr=%q", rc, stdout, stderr)
	}
}

func TestMainAsAliasMenuArgumentErrors(t *testing.T) {
	for _, args := range [][]string{{"--lang"}, {"--lang", "fr"}, {"--help", "--bad"}} {
		stdout, stderr, rc := captureCLIOutput(t, func() int {
			return MainAs("3.2.0-test", "/usr/local/sbin/sun", args)
		})
		if rc != 2 || stdout != "" || stderr == "" {
			t.Fatalf("args=%q rc=%d stdout=%q stderr=%q", args, rc, stdout, stderr)
		}
	}
}

func TestMainAsBareLongNamePreservesAutomatedRun(t *testing.T) {
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FD", "invalid")
	stdout, stderr, rc := captureCLIOutput(t, func() int {
		return MainAs("3.2.0-test", "/usr/local/sbin/security-update-notify", nil)
	})
	if rc != 1 || stdout != "" || !strings.Contains(stderr, "invalid inherited runtime lock descriptor") {
		t.Fatalf("bare long-name run rc=%d stdout=%q stderr=%q", rc, stdout, stderr)
	}
	if strings.Contains(stdout+stderr, "Select [0-9]") || strings.Contains(stdout+stderr, "请选择 [0-9]") {
		t.Fatalf("bare long-name invocation opened the menu: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestMenuRequiresRootBeforeTTY(t *testing.T) {
	calls := 0
	command, _, stderr := newMenuTestCommand("0\n", i18n.EN, func([]string) int {
		calls++
		return 0
	})
	command.geteuid = func() int { return 1000 }
	ttyProbes := 0
	command.stdinTTY = func() bool { ttyProbes++; return true }
	command.stdoutTTY = func() bool { ttyProbes++; return true }
	command.stderrTTY = func() bool { ttyProbes++; return true }
	if rc := command.run(); rc != 1 {
		t.Fatalf("menu rc=%d want 1", rc)
	}
	if calls != 0 || ttyProbes != 0 || !strings.Contains(stderr.String(), "Please run as root") {
		t.Fatalf("calls=%d ttyProbes=%d stderr=%q", calls, ttyProbes, stderr.String())
	}
}

func TestMenuRequiresAllThreeTTYStreams(t *testing.T) {
	for _, test := range []struct {
		name                  string
		stdin, stdout, stderr bool
	}{
		{name: "stdin", stdin: false, stdout: true, stderr: true},
		{name: "stdout", stdin: true, stdout: false, stderr: true},
		{name: "stderr", stdin: true, stdout: true, stderr: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			command, stdout, stderr := newMenuTestCommand("0\n", i18n.EN, func([]string) int {
				calls++
				return 0
			})
			command.stdinTTY = func() bool { return test.stdin }
			command.stdoutTTY = func() bool { return test.stdout }
			command.stderrTTY = func() bool { return test.stderr }
			if rc := command.run(); rc != 2 {
				t.Fatalf("menu rc=%d want 2", rc)
			}
			if calls != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "stdin, stdout, and stderr") {
				t.Fatalf("calls=%d stdout=%q stderr=%q", calls, stdout.String(), stderr.String())
			}
		})
	}
}

func TestMenuDispatchesFixedArguments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "preview", input: "1\n0\n", want: []string{"run", "--dry-run", "--lang", "en"}},
		{name: "immediate check", input: "2\ny\n0\n", want: []string{"run", "--wait-lock", "60", "--lang", "en"}},
		{name: "doctor", input: "3\n0\n", want: []string{"doctor", "--wait-lock", "60", "--lang", "en"}},
		{name: "configure", input: "4\n", want: []string{"configure", "notifications", "--lang", "en"}},
		{name: "normal notification", input: "5\n1\nyes\n0\n", want: []string{"test", "--send-test", "--no-dedupe", "--lang", "en"}},
		{name: "reboot notification", input: "5\n2\ny\n0\n", want: []string{"test", "--simulate-reboot", "--no-dedupe", "--lang", "en"}},
		{name: "check upgrade", input: "6\n0\n", want: []string{"check-upgrade", "--lang", "en"}},
		{name: "upgrade", input: "7\nYES\n", want: []string{"upgrade", "--lang", "en"}},
		{name: "uninstall keep config", input: "8\n1\nYES\n", want: []string{"uninstall", "--lang", "en"}},
		{name: "uninstall purge", input: "8\n2\nPURGE\n", want: []string{"uninstall", "--purge-config", "--lang", "en"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls [][]string
			command, _, _ := newMenuTestCommand(test.input, i18n.EN, func(args []string) int {
				calls = append(calls, append([]string(nil), args...))
				return 0
			})
			if rc := command.run(); rc != 0 {
				t.Fatalf("menu rc=%d want 0", rc)
			}
			if len(calls) != 1 || !reflect.DeepEqual(calls[0], test.want) {
				t.Fatalf("dispatch calls=%q want [%q]", calls, test.want)
			}
		})
	}
}

func TestMenuCancellationDoesNotDispatch(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "immediate check", input: "2\nn\n0\n"},
		{name: "notification test", input: "5\n1\n\n0\n"},
		{name: "upgrade mismatch", input: "7\nNO\n0\n"},
		{name: "upgrade surrounding whitespace", input: "7\n YES \n0\n"},
		{name: "upgrade extra carriage return", input: "7\nYES\r\r\n0\n"},
		{name: "uninstall keep surrounding whitespace", input: "8\n1\n YES \n0\n"},
		{name: "purge mismatch", input: "8\n2\nNO\n0\n"},
		{name: "purge surrounding whitespace", input: "8\n2\n PURGE \n0\n"},
		{name: "purge extra carriage return", input: "8\n2\nPURGE\r\r\n0\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			command, _, _ := newMenuTestCommand(test.input, i18n.EN, func([]string) int {
				calls++
				return 0
			})
			if rc := command.run(); rc != 0 {
				t.Fatalf("menu rc=%d want 0", rc)
			}
			if calls != 0 {
				t.Fatalf("cancelled action dispatched %d times", calls)
			}
		})
	}
}

func TestMenuPreservesActionFailureStatus(t *testing.T) {
	for _, code := range []int{1, 2, 75} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			calls := 0
			command, _, _ := newMenuTestCommand("1\n", i18n.EN, func([]string) int {
				calls++
				return code
			})
			if rc := command.run(); rc != code {
				t.Fatalf("menu rc=%d want %d", rc, code)
			}
			if calls != 1 {
				t.Fatalf("dispatch calls=%d want 1", calls)
			}
		})
	}
}

func TestMenuTerminalActionExitsAfterDispatch(t *testing.T) {
	for _, choice := range []string{"4\n", "7\nYES\n", "8\n1\nYES\n"} {
		calls := 0
		command, _, _ := newMenuTestCommand(choice+"1\n0\n", i18n.EN, func([]string) int {
			calls++
			return 0
		})
		if rc := command.run(); rc != 0 {
			t.Fatalf("choice %q rc=%d want 0", choice, rc)
		}
		if calls != 1 {
			t.Fatalf("choice %q dispatched %d times want 1", choice, calls)
		}
	}
}

func TestMenuEOFBlankInvalidAndOversizedInput(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "empty EOF"},
		{name: "unterminated exit choice", input: "0"},
		{name: "unterminated action choice", input: "1"},
		{name: "unterminated yes-no confirmation", input: "2\ny"},
		{name: "unterminated upgrade confirmation", input: "7\nYES"},
		{name: "unterminated purge confirmation", input: "8\n2\nPURGE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, _, stderr := newMenuTestCommand(test.input, i18n.EN, func([]string) int {
				t.Fatal("EOF dispatched an action")
				return 0
			})
			if rc := command.run(); rc != 2 || !strings.Contains(stderr.String(), "Input ended; cancelled") {
				t.Fatalf("rc=%d stderr=%q", rc, stderr.String())
			}
		})
	}

	t.Run("blank redraws", func(t *testing.T) {
		command, stdout, stderr := newMenuTestCommand("\n0\n", i18n.EN, func([]string) int {
			t.Fatal("blank input dispatched an action")
			return 0
		})
		if rc := command.run(); rc != 0 {
			t.Fatalf("menu rc=%d want 0", rc)
		}
		if strings.Count(stdout.String(), "security-update-notify 3.2.0-test") != 2 || strings.Contains(stderr.String(), "Invalid choice") {
			t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})

	t.Run("invalid retries", func(t *testing.T) {
		command, _, stderr := newMenuTestCommand("invalid\n0\n", i18n.EN, func([]string) int {
			t.Fatal("invalid choice dispatched an action")
			return 0
		})
		if rc := command.run(); rc != 0 || !strings.Contains(stderr.String(), "Invalid choice") {
			t.Fatalf("rc=%d stderr=%q", rc, stderr.String())
		}
	})

	t.Run("oversized line is drained", func(t *testing.T) {
		var got []string
		input := strings.Repeat("x", maxInteractiveLineBytes+1) + "\n1\n0\n"
		command, _, stderr := newMenuTestCommand(input, i18n.EN, func(args []string) int {
			got = append([]string(nil), args...)
			return 0
		})
		if rc := command.run(); rc != 0 {
			t.Fatalf("menu rc=%d want 0", rc)
		}
		want := []string{"run", "--dry-run", "--lang", "en"}
		if !reflect.DeepEqual(got, want) || !strings.Contains(stderr.String(), "Input is too long") {
			t.Fatalf("dispatch=%q stderr=%q", got, stderr.String())
		}
	})
}

func TestInstallCommandUsesProvidedBufferedReader(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("already-buffered\n"))
	command := defaultInstallCommandWithReader(reader)
	if command.console.in != reader {
		t.Fatal("install command replaced the menu's buffered reader")
	}
	line, err := command.readLine()
	if err != nil || line != "already-buffered" {
		t.Fatalf("shared reader line=%q err=%v", line, err)
	}
}

func TestMenuLanguageSwitchIsSessionOnlyAndAppliesToActions(t *testing.T) {
	var got []string
	command, stdout, _ := newMenuTestCommand("9\n2\n1\n0\n", i18n.ZH, func(args []string) int {
		got = append([]string(nil), args...)
		return 0
	})
	if rc := command.run(); rc != 0 {
		t.Fatalf("menu rc=%d want 0", rc)
	}
	want := []string{"run", "--dry-run", "--lang", "en"}
	if command.lang != i18n.EN || !reflect.DeepEqual(got, want) {
		t.Fatalf("lang=%q dispatch=%q", command.lang, got)
	}
	if !strings.Contains(stdout.String(), "Interface language switched to English") ||
		!strings.Contains(stdout.String(), "Preview this check") {
		t.Fatalf("output did not switch language: %q", stdout.String())
	}
}

func TestReadBoundedLineBoundaryAndDrain(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", maxInteractiveLineBytes) + "\nnext\n"))
	line, err := readBoundedLine(reader)
	if err != nil || line != strings.Repeat("x", maxInteractiveLineBytes)+"\n" {
		t.Fatalf("boundary len=%d err=%v", len(line), err)
	}
	line, err = readBoundedLine(reader)
	if err != nil || line != "next\n" {
		t.Fatalf("next line=%q err=%v", line, err)
	}

	reader = bufio.NewReader(strings.NewReader(strings.Repeat("x", maxInteractiveLineBytes+1) + "\nnext\n"))
	if line, err = readBoundedLine(reader); line != "" || !errors.Is(err, errInteractiveLineTooLong) {
		t.Fatalf("oversized line=%q err=%v", line, err)
	}
	if line, err = readBoundedLine(reader); err != nil || line != "next\n" {
		t.Fatalf("line after drain=%q err=%v", line, err)
	}
	if line, err = readBoundedLine(reader); line != "" || !errors.Is(err, io.EOF) {
		t.Fatalf("final line=%q err=%v", line, err)
	}
}
