package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
