package installer

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
)

type failAliasFS struct {
	FileSystem
	err error
}

func (f *failAliasFS) Symlink(target, name string) error {
	if name == AliasPath {
		return f.err
	}
	return f.FileSystem.Symlink(target, name)
}

type failAliasSyncFS struct {
	FileSystem
	err            error
	aliasCreated   bool
	remainingFails int
}

type replaceAliasAfterSyncFS struct {
	FileSystem
	aliasCreated bool
	replace      func() error
}

type failAliasReadlinkFS struct {
	FileSystem
	err       error
	reads     int
	failAfter int
}

func (f *failAliasReadlinkFS) Readlink(name string) (string, error) {
	if name == AliasPath {
		f.reads++
		if f.reads == f.failAfter {
			return "", f.err
		}
	}
	return f.FileSystem.Readlink(name)
}

func (f *replaceAliasAfterSyncFS) Symlink(target, name string) error {
	err := f.FileSystem.Symlink(target, name)
	if err == nil && name == AliasPath {
		f.aliasCreated = true
	}
	return err
}

func (f *replaceAliasAfterSyncFS) SyncDir(name string) error {
	if err := f.FileSystem.SyncDir(name); err != nil {
		return err
	}
	if f.aliasCreated && name == path.Dir(AliasPath) && f.replace != nil {
		replace := f.replace
		f.replace = nil
		return replace()
	}
	return nil
}

func (f *failAliasSyncFS) Symlink(target, name string) error {
	err := f.FileSystem.Symlink(target, name)
	if err == nil && name == AliasPath {
		f.aliasCreated = true
	}
	return err
}

func (f *failAliasSyncFS) SyncDir(name string) error {
	if f.aliasCreated && name == path.Dir(AliasPath) && f.remainingFails > 0 {
		f.remainingFails--
		return f.err
	}
	return f.FileSystem.SyncDir(name)
}

func TestInstallCreatesAndReusesCommandAlias(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	first, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Warnings) != 0 {
		t.Fatalf("fresh install warnings = %v", first.Warnings)
	}
	assertCommandAliasTarget(t, root, AliasTarget)

	second, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Warnings) != 0 {
		t.Fatalf("reinstall warnings = %v", second.Warnings)
	}
	assertCommandAliasTarget(t, root, AliasTarget)
}

func TestInstallPreservesCommandAliasConflicts(t *testing.T) {
	for _, test := range []struct {
		name   string
		setup  func(*testing.T, *RootFS)
		assert func(*testing.T, *RootFS)
	}{
		{
			name:  "regular file",
			setup: func(t *testing.T, root *RootFS) { write(t, root, AliasPath, "operator command", 0o755) },
			assert: func(t *testing.T, root *RootFS) {
				if got := readFile(t, root, AliasPath); got != "operator command" {
					t.Fatalf("regular conflict changed to %q", got)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, root *RootFS) {
				if err := root.Mkdir(AliasPath, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			assert: func(t *testing.T, root *RootFS) {
				info, err := root.Lstat(AliasPath)
				if err != nil || !info.IsDir() {
					t.Fatalf("directory conflict info=%v err=%v", info, err)
				}
			},
		},
		{
			name: "wrong symbolic link",
			setup: func(t *testing.T, root *RootFS) {
				if err := root.Symlink("other-command", AliasPath); err != nil {
					t.Fatal(err)
				}
			},
			assert: func(t *testing.T, root *RootFS) { assertCommandAliasTarget(t, root, "other-command") },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			test.setup(t, root)
			options := telegramOptions()
			options.SkipPostInstallCheck = true
			result, err := installer.Install(context.Background(), options)
			if err != nil {
				t.Fatalf("conflict made core install fail: %v", err)
			}
			if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], AliasPath) {
				t.Fatalf("conflict warnings = %v", result.Warnings)
			}
			if got := readFile(t, root, BinaryPath); got != "new-runtime" {
				t.Fatalf("core runtime = %q", got)
			}
			test.assert(t, root)
		})
	}
}

func TestFailedInstallDoesNotPublishCommandAlias(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.failedCommands["systemctl daemon-reload"] = CommandResult{Err: errors.New("forced activation failure")}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err == nil {
		t.Fatal("Install() succeeded despite forced activation failure")
	}
	if _, err := root.Lstat(AliasPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("alias was published before the core transaction committed: %v", err)
	}
}

func TestCommandAliasStaysOutsideCoreTransactionJournal(t *testing.T) {
	installer, _, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	b, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := installer.beginTransaction(b, nil, timerSnapshot{enablement: "not-found"})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range tx.journal.Paths {
		if entry.Path == AliasPath {
			t.Fatal("optional alias leaked into the backward-compatible core transaction journal")
		}
	}
}

func TestCommandAliasFailureWarnsAfterCoreCommit(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	aliasErr := errors.New("forced alias creation failure")
	installer.fs = &failAliasFS{FileSystem: root, err: aliasErr}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatalf("optional alias failure changed core install status: %v", err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], aliasErr.Error()) {
		t.Fatalf("alias warnings = %v", result.Warnings)
	}
	if got := readFile(t, root, BinaryPath); got != "new-runtime" {
		t.Fatalf("committed runtime = %q", got)
	}
	if _, err := root.Lstat(AliasPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("failed alias unexpectedly exists: %v", err)
	}
	if existsNoErr(root, path.Join(result.BackupDir, transactionJournalName)) {
		t.Fatal("optional alias ran before the core transaction journal was removed")
	}
}

func TestCommandAliasSyncFailureReportsCreatedAlias(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	syncErr := errors.New("forced alias directory sync failure")
	installer.fs = &failAliasSyncFS{FileSystem: root, err: syncErr, remainingFails: 1}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatalf("optional alias sync failure changed core install status: %v", err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], syncErr.Error()) ||
		!strings.Contains(result.Warnings[0], "was created, but its durability could not be confirmed") ||
		strings.Contains(result.Warnings[0], "could not be installed") {
		t.Fatalf("alias warnings = %v", result.Warnings)
	}
	if got := readFile(t, root, BinaryPath); got != "new-runtime" {
		t.Fatalf("committed runtime = %q", got)
	}
	assertCommandAliasTarget(t, root, AliasTarget)
	if existsNoErr(root, path.Join(result.BackupDir, transactionJournalName)) {
		t.Fatal("optional alias sync ran before the core transaction journal was removed")
	}

	if warning := installer.installCommandAlias(); warning != "" {
		t.Fatalf("alias durability retry warning = %q", warning)
	}
	assertCommandAliasTarget(t, root, AliasTarget)
}

func TestCommandAliasFinalVerificationDetectsConcurrentReplacement(t *testing.T) {
	for _, test := range []struct {
		name    string
		replace func(*RootFS) error
		assert  func(*testing.T, *RootFS)
	}{
		{
			name: "regular file",
			replace: func(root *RootFS) error {
				if err := root.Remove(AliasPath); err != nil {
					return err
				}
				return root.WriteFileAtomic(AliasPath, []byte("operator command"), 0o755)
			},
			assert: func(t *testing.T, root *RootFS) {
				if got := readFile(t, root, AliasPath); got != "operator command" {
					t.Fatalf("concurrent regular replacement changed to %q", got)
				}
			},
		},
		{
			name: "wrong symbolic link",
			replace: func(root *RootFS) error {
				if err := root.Remove(AliasPath); err != nil {
					return err
				}
				return root.Symlink("other-command", AliasPath)
			},
			assert: func(t *testing.T, root *RootFS) {
				assertCommandAliasTarget(t, root, "other-command")
			},
		},
		{
			name: "removed",
			replace: func(root *RootFS) error {
				return root.Remove(AliasPath)
			},
			assert: func(t *testing.T, root *RootFS) {
				if _, err := root.Lstat(AliasPath); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("concurrently removed alias still exists: %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			wrapper := &replaceAliasAfterSyncFS{FileSystem: root}
			wrapper.replace = func() error { return test.replace(root) }
			installer.fs = wrapper
			options := telegramOptions()
			options.SkipPostInstallCheck = true

			result, err := installer.Install(context.Background(), options)
			if err != nil {
				t.Fatalf("concurrent alias replacement changed core install status: %v", err)
			}
			if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "changed concurrently") {
				t.Fatalf("concurrent alias warnings = %v", result.Warnings)
			}
			if got := readFile(t, root, BinaryPath); got != "new-runtime" {
				t.Fatalf("committed runtime = %q", got)
			}
			test.assert(t, root)
		})
	}
}

func TestCommandAliasFinalVerificationReportsStableReadlinkFailure(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	readErr := errors.New("forced stable alias read failure")
	installer.fs = &failAliasReadlinkFS{FileSystem: root, err: readErr, failAfter: 2}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatalf("stable alias read failure changed core install status: %v", err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], readErr.Error()) ||
		!strings.Contains(result.Warnings[0], "could not be installed") ||
		strings.Contains(result.Warnings[0], "changed concurrently") {
		t.Fatalf("stable alias read warnings = %v", result.Warnings)
	}
	if got := readFile(t, root, BinaryPath); got != "new-runtime" {
		t.Fatalf("committed runtime = %q", got)
	}
	assertCommandAliasTarget(t, root, AliasTarget)
}

func assertCommandAliasTarget(t *testing.T, root *RootFS, want string) {
	t.Helper()
	info, err := root.Lstat(AliasPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("alias info=%v err=%v", info, err)
	}
	target, err := root.Readlink(AliasPath)
	if err != nil || target != want {
		t.Fatalf("alias target=%q err=%v want=%q", target, err, want)
	}
}
