package filetrust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMkdirTempIgnoresTMPDIRAndCreatesPrivateDirectory(t *testing.T) {
	base := t.TempDir()
	attacker := t.TempDir()
	t.Setenv("TMPDIR", attacker)

	tmp, err := MkdirTemp(base, "trusted-", os.Geteuid())
	if err != nil {
		t.Fatalf("MkdirTemp(): %v", err)
	}
	defer os.RemoveAll(tmp)
	if filepath.Dir(tmp) != base || !strings.HasPrefix(filepath.Base(tmp), "trusted-") {
		t.Fatalf("temporary directory=%q, want prefixed child of %q", tmp, base)
	}
	info, err := os.Lstat(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("temporary directory mode=%v, want drwx------", info.Mode())
	}
	entries, err := os.ReadDir(attacker)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("caller-controlled TMPDIR was used: %v", entries)
	}
}

func TestMkdirTempValidatesEveryPathComponent(t *testing.T) {
	root := t.TempDir()
	unsafeAncestor := filepath.Join(root, "unsafe")
	unsafeBase := filepath.Join(unsafeAncestor, "base")
	if err := os.MkdirAll(unsafeBase, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeAncestor, 0o777); err != nil {
		t.Fatal(err)
	}
	if tmp, err := MkdirTemp(unsafeBase, "test-", os.Geteuid()); err == nil {
		_ = os.RemoveAll(tmp)
		t.Fatal("unsafe ancestor was accepted")
	}

	stickyAncestor := filepath.Join(root, "sticky")
	stickyBase := filepath.Join(stickyAncestor, "base")
	if err := os.Mkdir(stickyAncestor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stickyAncestor, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stickyBase, 0o700); err != nil {
		t.Fatal(err)
	}
	tmp, err := MkdirTemp(stickyBase, "test-", os.Geteuid())
	if err != nil {
		t.Fatalf("sticky ancestor was rejected: %v", err)
	}
	if err := os.RemoveAll(tmp); err != nil {
		t.Fatal(err)
	}

	protected := filepath.Join(root, "protected")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkAncestor := filepath.Join(root, "linked")
	if err := os.Symlink(protected, symlinkAncestor); err != nil {
		t.Fatal(err)
	}
	if tmp, err := MkdirTemp(symlinkAncestor, "test-", os.Geteuid()); err == nil {
		_ = os.RemoveAll(tmp)
		t.Fatal("symlink path component was accepted")
	}
}

func TestMkdirTempRejectsInvalidRequest(t *testing.T) {
	for _, test := range []struct {
		base   string
		prefix string
		uid    int
	}{
		{base: "relative", prefix: "test-", uid: os.Geteuid()},
		{base: t.TempDir() + string(filepath.Separator), prefix: "test-", uid: os.Geteuid()},
		{base: t.TempDir(), prefix: "bad/prefix", uid: os.Geteuid()},
		{base: t.TempDir(), prefix: "test-", uid: -1},
	} {
		if tmp, err := MkdirTemp(test.base, test.prefix, test.uid); err == nil {
			_ = os.RemoveAll(tmp)
			t.Fatalf("invalid request accepted: %+v", test)
		}
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if tmp, err := MkdirTemp(missing, "test-", os.Geteuid()); err == nil {
		_ = os.RemoveAll(tmp)
		t.Fatal("missing base was accepted")
	} else if errors.Is(err, os.ErrNotExist) {
		// Error wrapping must preserve the underlying cause for callers.
	} else {
		t.Fatalf("missing base error=%v, want os.ErrNotExist", err)
	}
}

func TestMkdirTempRejectsBaseOwnedByUntrustedUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing fixture ownership requires root")
	}
	base := t.TempDir()
	if err := os.Chown(base, 65534, 65534); err != nil {
		t.Skipf("cannot change fixture ownership: %v", err)
	}
	if tmp, err := MkdirTemp(base, "test-", 0); err == nil {
		_ = os.RemoveAll(tmp)
		t.Fatal("temporary base owned by an untrusted user was accepted")
	}
}
