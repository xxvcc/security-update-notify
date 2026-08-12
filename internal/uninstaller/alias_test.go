package uninstaller

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallRemovesOnlyExactCommandAlias(t *testing.T) {
	for _, test := range []struct {
		name    string
		setup   func(*testing.T, string)
		removed bool
	}{
		{name: "exact relative link", setup: func(t *testing.T, path string) {
			if err := os.Symlink(aliasTarget, path); err != nil {
				t.Fatal(err)
			}
		}, removed: true},
		{name: "absolute link", setup: func(t *testing.T, path string) {
			if err := os.Symlink("/usr/local/sbin/security-update-notify", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong relative link", setup: func(t *testing.T, path string) {
			if err := os.Symlink("other-command", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "regular file", setup: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("operator command"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory", setup: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			alias := hostPath(root, aliasPath)
			if err := os.MkdirAll(filepath.Dir(alias), 0o755); err != nil {
				t.Fatal(err)
			}
			test.setup(t, alias)
			if _, err := uninstallAsRoot(Options{RootDir: root, RunCommand: successfulRunner}); err != nil {
				t.Fatal(err)
			}
			_, err := os.Lstat(alias)
			if test.removed && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("exact alias still exists: %v", err)
			}
			if !test.removed && err != nil {
				t.Fatalf("conflicting alias was not preserved: %v", err)
			}
		})
	}
}

func TestConditionalCommandAliasRemovalPreservesConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	alias := hostPath(root, aliasPath)
	if err := os.MkdirAll(filepath.Dir(alias), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(aliasTarget, alias); err != nil {
		t.Fatal(err)
	}
	removed, err := removeLogicalSymlinkTargetWithHook(root, aliasPath, aliasTarget, func() error {
		if err := os.Remove(alias); err != nil {
			return err
		}
		return os.WriteFile(alias, []byte("replacement"), 0o755)
	})
	if err == nil || removed {
		t.Fatalf("conditional remove result removed=%t err=%v", removed, err)
	}
	data, readErr := os.ReadFile(alias)
	if readErr != nil || string(data) != "replacement" {
		t.Fatalf("concurrent replacement data=%q err=%v", data, readErr)
	}
}

func TestCommandAliasRemovalRetrySyncsMissingAlias(t *testing.T) {
	root := t.TempDir()
	alias := hostPath(root, aliasPath)
	if err := os.MkdirAll(filepath.Dir(alias), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(aliasTarget, alias); err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("forced alias directory sync failure")
	syncCalls := 0
	syncParent := func(parent *os.File) error {
		syncCalls++
		if syncCalls == 1 {
			return syncFailure
		}
		return syncLogicalRemovalParent(parent)
	}

	removed, err := removeLogicalSymlinkTargetWithSync(root, aliasPath, aliasTarget, nil, syncParent)
	if !removed || !errors.Is(err, syncFailure) {
		t.Fatalf("first removal = (%t, %v), want removed with sync failure", removed, err)
	}
	if _, err := os.Lstat(alias); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("alias remained after successful unlink: %v", err)
	}

	removed, err = removeLogicalSymlinkTargetWithSync(root, aliasPath, aliasTarget, nil, syncParent)
	if removed || err != nil {
		t.Fatalf("retry removal = (%t, %v), want durable missing alias", removed, err)
	}
	if syncCalls != 2 {
		t.Fatalf("directory sync calls = %d, want 2", syncCalls)
	}
}

func TestCommandAliasConflictIsPreservedWhenParentSyncFails(t *testing.T) {
	root := t.TempDir()
	alias := hostPath(root, aliasPath)
	if err := os.MkdirAll(filepath.Dir(alias), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other-command", alias); err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("forced conflicting alias directory sync failure")
	syncCalls := 0

	removed, err := removeLogicalSymlinkTargetWithSync(root, aliasPath, aliasTarget, nil, func(*os.File) error {
		syncCalls++
		return syncFailure
	})
	if removed || !errors.Is(err, syncFailure) {
		t.Fatalf("conflicting alias removal = (%t, %v), want preserved with sync failure", removed, err)
	}
	if syncCalls != 1 {
		t.Fatalf("directory sync calls = %d, want 1", syncCalls)
	}
	target, readErr := os.Readlink(alias)
	if readErr != nil || target != "other-command" {
		t.Fatalf("conflicting alias target=%q err=%v", target, readErr)
	}
}
