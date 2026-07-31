package textsafe

import "testing"

func TestSingleLineRemovesDisplayControls(t *testing.T) {
	input := "prod\nnode\r\x1b[31m\u202Eevil\u2028tail\u0085end"
	if got, want := SingleLine(input), "prod node  [31m evil tail end"; got != want {
		t.Fatalf("SingleLine() = %q, want %q", got, want)
	}
}

func TestMultilinePreservesOnlyIntentionalFormattingControls(t *testing.T) {
	input := "first\nsecond\tvalue\r\x1b[2J\u2066spoof\u2069\u2029tail"
	if got, want := Multiline(input), "first\nsecond\tvalue  [2J spoof  tail"; got != want {
		t.Fatalf("Multiline() = %q, want %q", got, want)
	}
}
