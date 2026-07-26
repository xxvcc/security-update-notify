package cli

import (
	"strings"
	"testing"
)

func TestParseWaitLockSeconds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		want  int
		ok    bool
	}{
		{value: "0", want: 0, ok: true},
		{value: "60", want: 60, ok: true},
		{value: "3600", want: 3600, ok: true},
		{value: "0001", want: 1, ok: true},
		{value: "", ok: false},
		{value: "00001", ok: false},
		{value: "+1", ok: false},
		{value: "-1", ok: false},
		{value: "3601", ok: false},
		{value: "9999", ok: false},
		{value: "1s", ok: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			got, ok := parseWaitLockSeconds(tt.value)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parseWaitLockSeconds(%q) = (%d, %v), want (%d, %v)", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestExplicitRunSubcommandPreservesVersionFlag(t *testing.T) {
	if rc := Main("3.0.0-test", []string{"run", "--version"}); rc != 0 {
		t.Fatalf("Main(run --version)=%d", rc)
	}
}

func TestTestSubcommandRejectsUnknownAndInvalidLanguage(t *testing.T) {
	for _, args := range [][]string{{"test", "--unknown"}, {"test", "--lang", "fr"}, {"test", "--lang"}} {
		if rc := Main("3.0.0-test", args); rc != 2 {
			t.Fatalf("Main(%q)=%d want 2", strings.Join(args, " "), rc)
		}
	}
}

func TestUninstallSubcommandRejectsUnknownAndInvalidLanguageBeforeMutation(t *testing.T) {
	for _, args := range [][]string{{"uninstall", "--unknown"}, {"uninstall", "--lang", "fr"}, {"uninstall", "--lang"}} {
		if rc := Main("3.0.0-test", args); rc != 2 {
			t.Fatalf("Main(%q)=%d want 2", strings.Join(args, " "), rc)
		}
	}
}

func TestUninstallHelpAcceptsLanguageBeforeOrAfterHelp(t *testing.T) {
	for _, args := range [][]string{
		{"uninstall", "--lang", "en", "--help"},
		{"uninstall", "--help", "--lang", "en"},
	} {
		if rc := Main("3.0.0-test", args); rc != 0 {
			t.Fatalf("Main(%q)=%d want 0", strings.Join(args, " "), rc)
		}
	}
}

func TestInstallAndConfigureSubcommandDispatch(t *testing.T) {
	for _, args := range [][]string{
		{"install", "--help"},
		{"configure", "notifications", "--help"},
	} {
		if rc := Main("3.0.0-test", args); rc != 0 {
			t.Fatalf("Main(%q)=%d want 0", strings.Join(args, " "), rc)
		}
	}
	if rc := Main("3.0.0-test", []string{"configure", "unknown"}); rc != 2 {
		t.Fatalf("Main(configure unknown)=%d want 2", rc)
	}
}
