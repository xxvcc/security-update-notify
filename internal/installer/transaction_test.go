package installer

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"
)

type journalCleanupFaultFS struct {
	FileSystem
	journalPath    string
	removeAfterErr error
	syncErr        error
}

func (f *journalCleanupFaultFS) Remove(name string) error {
	err := f.FileSystem.Remove(name)
	if err == nil && name == f.journalPath && f.removeAfterErr != nil {
		return f.removeAfterErr
	}
	return err
}

func (f *journalCleanupFaultFS) SyncDir(name string) error {
	if name == path.Dir(f.journalPath) && f.syncErr != nil {
		return f.syncErr
	}
	return f.FileSystem.SyncDir(name)
}

type failAfterAtomicWriteFS struct {
	FileSystem
	path string
	err  error
}

type blockAfterAtomicWriteFS struct {
	FileSystem
	path      string
	readyPath string
}

type panicRemoveFS struct {
	FileSystem
	path string
}

type recordDirectorySyncFS struct {
	FileSystem
	paths []string
}

func (f *recordDirectorySyncFS) SyncDir(name string) error {
	f.paths = append(f.paths, name)
	return f.FileSystem.SyncDir(name)
}

func TestBackupCreationFailsClosedAtEveryDirectoryDurabilityBoundary(t *testing.T) {
	for _, name := range []string{
		"backups", "security-update-notify", "20260726120000", "usr", "local", "sbin",
	} {
		t.Run(name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, BinaryPath, "old-runtime", 0o755)
			syncErr := errors.New("forced backup directory sync failure")
			failed := false
			root.beforeDirectoryEntrySync = func(_ *os.File, entry string) error {
				if !failed && entry == name {
					failed = true
					return syncErr
				}
				return nil
			}
			if _, err := installer.createBackup(); !errors.Is(err, syncErr) {
				t.Fatalf("create backup error = %v, want directory sync failure", err)
			}
			if !failed {
				t.Fatalf("backup creation did not reach directory entry %q", name)
			}
			if got := readFile(t, root, BinaryPath); got != "old-runtime" {
				t.Fatalf("managed path changed before durable backup: %q", got)
			}
			if existsNoErr(root, path.Join(BackupRoot, "latest")) {
				t.Fatal("failed backup published a latest pointer")
			}
		})
	}
}

func TestBackupCreationRetryResynchronizesResidualDirectoryChain(t *testing.T) {
	for _, test := range []struct {
		name           string
		failedEntry    string
		residualPath   string
		expectedParent string
	}{
		{
			name:           "backups parent",
			failedEntry:    "backups",
			residualPath:   "/var/backups",
			expectedParent: "/var",
		},
		{
			name:           "backup root parent",
			failedEntry:    "security-update-notify",
			residualPath:   BackupRoot,
			expectedParent: "/var/backups",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, BinaryPath, "old-runtime", 0o755)
			syncErr := errors.New("forced initial directory entry sync failure")
			root.beforeDirectoryEntrySync = func(_ *os.File, entry string) error {
				if entry == test.failedEntry {
					return syncErr
				}
				return nil
			}
			if _, err := installer.createBackup(); !errors.Is(err, syncErr) {
				t.Fatalf("initial create backup error = %v, want directory sync failure", err)
			}
			if info, err := root.Lstat(test.residualPath); err != nil || !info.IsDir() {
				t.Fatalf("residual directory %s info=%v err=%v", test.residualPath, info, err)
			}

			root.beforeDirectoryEntrySync = nil
			recorder := &recordDirectorySyncFS{FileSystem: root}
			installer.fs = recorder
			if _, err := installer.createBackup(); err != nil {
				t.Fatalf("retry create backup: %v", err)
			}
			found := false
			for _, synchronized := range recorder.paths {
				if synchronized == test.expectedParent {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("retry directory syncs = %v, want parent %s", recorder.paths, test.expectedParent)
			}
		})
	}
}

func (f *panicRemoveFS) Remove(name string) error {
	if name == f.path {
		panic("simulated abrupt stop before metadata unlink")
	}
	return f.FileSystem.Remove(name)
}

func (f *blockAfterAtomicWriteFS) WriteFileAtomic(name string, data []byte, perm fs.FileMode) error {
	if err := f.FileSystem.WriteFileAtomic(name, data, perm); err != nil {
		return err
	}
	if name != f.path {
		return nil
	}
	if err := os.WriteFile(f.readyPath, []byte("ready\n"), 0o600); err != nil {
		return err
	}
	select {}
}

func (f *failAfterAtomicWriteFS) WriteFileAtomic(name string, data []byte, perm fs.FileMode) error {
	if err := f.FileSystem.WriteFileAtomic(name, data, perm); err != nil {
		return err
	}
	if name == f.path {
		return f.err
	}
	return nil
}

func TestTransactionJournalCleanupFailureRepublishesFinalState(t *testing.T) {
	for _, test := range []struct {
		name        string
		removeError bool
	}{
		{name: "remove reports failure after unlink", removeError: true},
		{name: "directory sync reports failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			b, err := installer.createBackup()
			if err != nil {
				t.Fatal(err)
			}
			tx, err := installer.beginTransaction(b, nil, timerSnapshot{enablement: "not-found"})
			if err != nil {
				t.Fatal(err)
			}
			cleanupErr := errors.New("forced journal cleanup durability failure")
			faults := &journalCleanupFaultFS{FileSystem: root, journalPath: tx.path}
			if test.removeError {
				faults.removeAfterErr = cleanupErr
			} else {
				faults.syncErr = cleanupErr
			}
			installer.fs = faults
			finalized, err := tx.finish(transactionStateCommit)
			if !finalized || !errors.Is(err, cleanupErr) {
				t.Fatalf("finish finalized=%t err=%v", finalized, err)
			}
			data, exists, readErr := installer.readProtectedTransactionFile(tx.path, maxTransactionBytes, 0o600)
			if readErr != nil || !exists {
				t.Fatalf("republished journal exists=%t err=%v", exists, readErr)
			}
			journal, decodeErr := decodeTransactionJournal(data)
			if decodeErr != nil || journal.State != transactionStateCommit {
				t.Fatalf("republished journal state=%q err=%v", journal.State, decodeErr)
			}
		})
	}
}

func TestPrivateRecoveryCleanupFailureRetainsJournal(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, FeishuPlainCredentialPath, "old-private-secret", 0o600)
	private, err := installer.snapshotPrivateCredentials()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroPrivateSnapshots(private)
	b, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := installer.beginTransaction(b, private, timerSnapshot{enablement: "not-found"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("forced private recovery cleanup failure")
	installer.fs = &failRemoveFS{FileSystem: root, path: plainCredentialRecoveryPath, err: cleanupErr}
	finalized, err := tx.finish(transactionStateCommit)
	if !finalized || !errors.Is(err, cleanupErr) {
		t.Fatalf("finish finalized=%t err=%v", finalized, err)
	}
	if !existsNoErr(root, tx.path) || !existsNoErr(root, plainCredentialRecoveryPath) {
		t.Fatal("private cleanup failure lost the journal or recovery material")
	}
}

func TestPrivateRecoveryWriteDurabilityFailureDoesNotChangeParentMode(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, FeishuPlainCredentialPath, "old-private-secret", 0o600)
	credentialDir := path.Dir(FeishuPlainCredentialPath)
	if err := root.Chmod(credentialDir, 0o750); err != nil {
		t.Fatal(err)
	}
	private, err := installer.snapshotPrivateCredentials()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroPrivateSnapshots(private)
	b, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("forced recovery write durability failure")
	installer.fs = &failAfterAtomicWriteFS{FileSystem: root, path: plainCredentialRecoveryPath, err: writeErr}
	if _, err := installer.beginTransaction(b, private, timerSnapshot{enablement: "not-found"}); !errors.Is(err, writeErr) {
		t.Fatalf("begin transaction error = %v", err)
	}
	assertMode(t, root, credentialDir, 0o750)
	if !existsNoErr(root, plainCredentialRecoveryPath) {
		t.Fatal("published recovery material disappeared after uncertain durability")
	}
	data, exists, err := installer.readProtectedTransactionFile(path.Join(b.dir, transactionJournalName), maxTransactionBytes, 0o600)
	if err != nil || !exists {
		t.Fatalf("mutation-false journal exists=%t err=%v", exists, err)
	}
	journal, err := decodeTransactionJournal(data)
	if err != nil || journal.MutationStarted {
		t.Fatalf("journal mutation_started=%t err=%v", journal.MutationStarted, err)
	}
}

func TestInterruptedTransactionRestoresPrivateCredentials(t *testing.T) {
	for _, credentialPath := range []string{FeishuPlainCredentialPath, FeishuEncryptedCredPath} {
		t.Run(path.Base(credentialPath), func(t *testing.T) {
			installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			const oldSecret = "old-private-secret"
			write(t, root, credentialPath, oldSecret, 0o600)
			private, err := installer.snapshotPrivateCredentials()
			if err != nil {
				t.Fatal(err)
			}
			defer zeroPrivateSnapshots(private)
			b, err := installer.createBackup()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := installer.beginTransaction(b, private, timerSnapshot{enablement: "not-found"}); err != nil {
				t.Fatal(err)
			}
			write(t, root, credentialPath, "interrupted-new-secret", 0o600)
			otherPath := FeishuPlainCredentialPath
			if credentialPath == otherPath {
				otherPath = FeishuEncryptedCredPath
			}
			write(t, root, otherPath, "interrupted-other-secret", 0o600)

			recovery := freshTestInstaller(t, root, runner, locker)
			if err := recovery.recoverInterruptedTransaction(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, root, credentialPath); got != oldSecret {
				t.Fatalf("restored credential = %q", got)
			}
			if _, err := root.Lstat(otherPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("credential originally absent remained after recovery: %v", err)
			}
			if existsNoErr(root, plainCredentialRecoveryPath) || existsNoErr(root, encryptedCredentialRecoveryPath) ||
				existsNoErr(root, path.Join(b.dir, transactionJournalName)) {
				t.Fatal("completed private recovery left transaction material")
			}
		})
	}
}

func zeroPrivateSnapshots(private map[string]privateSnapshot) {
	for _, snapshot := range private {
		zeroBytes(snapshot.data)
	}
}

func TestTransactionCredentialAbsentSiblingMatrixFailsClosed(t *testing.T) {
	for _, credentialPath := range []string{FeishuPlainCredentialPath, FeishuEncryptedCredPath} {
		for _, kind := range []string{"regular", "symlink"} {
			t.Run(path.Base(credentialPath)+"/"+kind, func(t *testing.T) {
				installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
				b, err := installer.createBackup()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := installer.beginTransaction(b, nil, timerSnapshot{enablement: "not-found"}); err != nil {
					t.Fatal(err)
				}
				recoveryPath := privateRecoveryPath(credentialPath)
				if err := root.MkdirAll(path.Dir(recoveryPath), 0o755); err != nil {
					t.Fatal(err)
				}
				if kind == "regular" {
					if err := root.WriteFileAtomic(recoveryPath, []byte("unexpected"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else if err := root.Symlink("unexpected-target", recoveryPath); err != nil {
					t.Fatal(err)
				}
				commandsBefore := len(runner.commands)
				recovery := freshTestInstaller(t, root, runner, locker)
				err = recovery.recoverInterruptedTransaction(context.Background(), 0)
				if err == nil || !strings.Contains(err.Error(), "absent credential has an unexpected reserved recovery file") {
					t.Fatalf("absent credential sibling error = %v", err)
				}
				if len(runner.commands) != commandsBefore || !existsNoErr(root, recoveryPath) ||
					!existsNoErr(root, path.Join(b.dir, transactionJournalName)) {
					t.Fatal("absent sibling failure mutated host state or lost its locator")
				}
			})
		}
	}
}

func TestTransactionJournalValidationFailsBeforeHostMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Installer, *RootFS, *installTransaction, *backup)
	}{
		{name: "corrupt JSON", mutate: func(t *testing.T, _ *Installer, root *RootFS, tx *installTransaction, _ *backup) {
			if err := root.WriteFileAtomic(tx.path, []byte("{not-json\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "journal mode", mutate: func(t *testing.T, _ *Installer, root *RootFS, tx *installTransaction, _ *backup) {
			if err := root.Chmod(tx.path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "arbitrary managed path", mutate: func(t *testing.T, _ *Installer, _ *RootFS, tx *installTransaction, _ *backup) {
			tx.journal.Paths[0].Path = "/tmp/untrusted-transaction-path"
			if err := tx.write(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "final state before mutation", mutate: func(t *testing.T, _ *Installer, _ *RootFS, tx *installTransaction, _ *backup) {
			tx.journal.State = transactionStateCommit
			tx.journal.MutationStarted = false
			if err := tx.write(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe final state", mutate: func(t *testing.T, _ *Installer, _ *RootFS, tx *installTransaction, _ *backup) {
			tx.journal.State = transactionStateRevert
			tx.journal.RecoverySafe = false
			tx.journal.UnsafeReason = "synthetic unsafe final state"
			tx.journal.Dependency = &transactionDependency{
				State: "mutating", Backend: "apt", Engine: "apt",
				AutomaticUnits: []string{"apt-daily.timer", "apt-daily-upgrade.timer", "unattended-upgrades.service"},
			}
			if err := tx.write(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "safe state with unsafe reason", mutate: func(t *testing.T, _ *Installer, _ *RootFS, tx *installTransaction, _ *backup) {
			tx.journal.UnsafeReason = "unexpected stale reason"
			if err := tx.write(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing snapshot", mutate: func(t *testing.T, _ *Installer, root *RootFS, _ *installTransaction, b *backup) {
			if err := root.Remove(b.snapshots[ConfigPath].backupPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "writable snapshot", mutate: func(t *testing.T, _ *Installer, root *RootFS, _ *installTransaction, b *backup) {
			if err := root.Chmod(b.snapshots[ConfigPath].backupPath, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, ConfigPath, "old config\n", 0o600)
			b, err := installer.createBackup()
			if err != nil {
				t.Fatal(err)
			}
			tx, err := installer.beginTransaction(b, nil, timerSnapshot{enablement: "not-found"})
			if err != nil {
				t.Fatal(err)
			}
			write(t, root, ConfigPath, "interrupted config\n", 0o600)
			test.mutate(t, installer, root, tx, b)
			commandsBefore := len(runner.commands)
			recovery := freshTestInstaller(t, root, runner, locker)
			if err := recovery.recoverInterruptedTransaction(context.Background(), 0); err == nil {
				t.Fatal("invalid transaction unexpectedly recovered")
			}
			if got := readFile(t, root, ConfigPath); got != "interrupted config\n" {
				t.Fatalf("invalid transaction changed managed config to %q", got)
			}
			if len(runner.commands) != commandsBefore {
				t.Fatalf("invalid transaction ran host commands: %v", runner.commands[commandsBefore:])
			}
			if !existsNoErr(root, tx.path) {
				t.Fatal("invalid transaction lost its journal locator")
			}
		})
	}
}

func TestMultipleTransactionJournalsFailClosed(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, ConfigPath, "old config\n", 0o600)
	first, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installer.beginTransaction(first, nil, timerSnapshot{enablement: "not-found"}); err != nil {
		t.Fatal(err)
	}
	write(t, root, ConfigPath, "interrupted config\n", 0o600)
	second, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installer.beginTransaction(second, nil, timerSnapshot{enablement: "not-found"}); err != nil {
		t.Fatal(err)
	}
	commandsBefore := len(runner.commands)
	recovery := freshTestInstaller(t, root, runner, locker)
	err = recovery.recoverInterruptedTransaction(context.Background(), 0)
	if err == nil || !strings.Contains(err.Error(), "multiple transaction journals") {
		t.Fatalf("multiple journal error = %v", err)
	}
	if got := readFile(t, root, ConfigPath); got != "interrupted config\n" {
		t.Fatalf("multiple journal scan changed config to %q", got)
	}
	if len(runner.commands) != commandsBefore || !existsNoErr(root, path.Join(first.dir, transactionJournalName)) ||
		!existsNoErr(root, path.Join(second.dir, transactionJournalName)) {
		t.Fatal("multiple journal scan mutated the host or lost a locator")
	}
}

func TestTransactionRecoveryDoesNotDependOnLatestBackupPointer(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, ConfigPath, "old config\n", 0o600)
	interrupted, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installer.beginTransaction(interrupted, nil, timerSnapshot{enablement: "not-found"}); err != nil {
		t.Fatal(err)
	}
	write(t, root, ConfigPath, "interrupted config\n", 0o600)
	later, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	if latest := strings.TrimSpace(readFile(t, root, path.Join(BackupRoot, "latest"))); latest != later.dir {
		t.Fatalf("latest backup = %q, want %q", latest, later.dir)
	}

	recovery := freshTestInstaller(t, root, runner, locker)
	if err := recovery.recoverInterruptedTransaction(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, ConfigPath); got != "old config\n" {
		t.Fatalf("non-latest transaction restored config = %q", got)
	}
	if existsNoErr(root, path.Join(interrupted.dir, transactionJournalName)) {
		t.Fatal("non-latest recovered transaction left its journal")
	}
}

func TestSIGKILLAfterManagedWriteIsRecoveredByIndependentProcess(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	oldValues := cloneConfig(configDefaults)
	oldValues["NOTIFY_CHANNELS"] = "telegram"
	oldValues["TELEGRAM_BOT_TOKEN"] = "123456:old_secret"
	oldValues["TELEGRAM_CHAT_ID"] = "-100123"
	oldValues["HOST_LABEL"] = "original-host"
	oldValues["BACKEND"] = "apt"
	writeConfig(t, root, oldValues)
	write(t, root, BinaryPath, "old-runtime", 0o755)
	write(t, root, ServicePath, "old service\n", 0o644)
	write(t, root, TimerPath, "old timer\n", 0o644)
	if err := root.MkdirAll(path.Dir(PersistentTimerLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("../security-update-notify.timer", PersistentTimerLink); err != nil {
		t.Fatal(err)
	}
	readyPath := path.Join(t.TempDir(), "managed-write-ready")
	first := exec.Command(os.Args[0], "-test.run=^TestInstallCrashRecoveryProcessHelper$")
	first.Env = append(os.Environ(),
		"SUN_INSTALL_CRASH_HELPER=1",
		"SUN_INSTALL_CRASH_PHASE=interrupt",
		"SUN_INSTALL_CRASH_ROOT="+root.Root,
		"SUN_INSTALL_CRASH_READY="+readyPath,
	)
	var firstOutput bytes.Buffer
	first.Stdout = &firstOutput
	first.Stderr = &firstOutput
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			_ = first.Process.Kill()
			_, _ = first.Process.Wait()
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			_ = first.Process.Kill()
			_, _ = first.Process.Wait()
			t.Fatalf("interrupted helper did not reach managed write: %s", firstOutput.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := readFile(t, root, ConfigPath); !strings.Contains(got, "HOST_LABEL='first-process-interrupted'") {
		_ = first.Process.Kill()
		_, _ = first.Process.Wait()
		t.Fatalf("helper signaled before publishing interrupted config:\n%s", got)
	}
	if err := first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitErr := first.Wait()
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("interrupted helper wait error = %v, output=%s", waitErr, firstOutput.String())
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("interrupted helper status=%v, want SIGKILL", exitErr.Sys())
	}
	if tx, _, err := installer.loadTransaction(); err != nil || tx == nil || !tx.journal.MutationStarted {
		t.Fatalf("SIGKILL transaction tx=%v err=%v", tx, err)
	}

	second := exec.Command(os.Args[0], "-test.run=^TestInstallCrashRecoveryProcessHelper$")
	second.Env = append(os.Environ(),
		"SUN_INSTALL_CRASH_HELPER=1",
		"SUN_INSTALL_CRASH_PHASE=recover",
		"SUN_INSTALL_CRASH_ROOT="+root.Root,
	)
	if output, err := second.CombinedOutput(); err != nil {
		t.Fatalf("independent recovery helper: %v\n%s", err, output)
	}
	if got := readFile(t, root, ConfigPath); !strings.Contains(got, "HOST_LABEL='second-process-complete'") {
		t.Fatalf("second process did not complete installation:\n%s", got)
	}
	if tx, _, err := installer.loadTransaction(); err != nil || tx != nil {
		t.Fatalf("independent recovery left transaction tx=%v err=%v", tx, err)
	}
}

func TestInstallCrashRecoveryProcessHelper(t *testing.T) {
	if os.Getenv("SUN_INSTALL_CRASH_HELPER") != "1" {
		t.Skip("process helper")
	}
	root, err := NewRootFS(os.Getenv("SUN_INSTALL_CRASH_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{
		fs: root, missingPackages: map[string]bool{}, dpkgStatuses: map[string]string{},
		missingCommands: map[string]bool{"dnf5": true}, enabledUnits: map[string]bool{},
		unitEnablements: map[string]string{}, activeUnits: map[string]bool{}, failedCommands: map[string]CommandResult{},
	}
	locker := &fakeLocker{}
	runner.locker = locker
	phase := os.Getenv("SUN_INSTALL_CRASH_PHASE")
	if phase == "interrupt" {
		runner.timerActive = true
	}
	filesystem := FileSystem(root)
	if phase == "interrupt" {
		filesystem = &blockAfterAtomicWriteFS{
			FileSystem: root, path: ConfigPath, readyPath: os.Getenv("SUN_INSTALL_CRASH_READY"),
		}
	}
	installer, err := New(Dependencies{
		FS: filesystem, Runner: runner, Locker: locker, EffectiveUID: func() int { return 0 },
		RootOwnerUID: uint32(os.Geteuid()),
		Now:          func() time.Time { return time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	options := telegramOptions()
	options.SkipDependencies = true
	options.SkipPostInstallCheck = true
	switch phase {
	case "interrupt":
		options.Config["HOST_LABEL"] = "first-process-interrupted"
	case "recover":
		options.Config["HOST_LABEL"] = "second-process-complete"
		options.Preflight = func(context.Context, *Prepared) error {
			config, err := root.ReadFile(ConfigPath)
			if err != nil {
				return err
			}
			if !bytes.Contains(config, []byte("HOST_LABEL='original-host'")) {
				return errors.New("disk transaction was not recovered before the second request")
			}
			return nil
		}
	default:
		t.Fatalf("unknown helper phase %q", phase)
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
}

func TestDependencyMetadataAbsenceIsDurableBeforeLiveUnlink(t *testing.T) {
	for _, test := range []struct {
		name           string
		release        string
		markerPath     string
		markerContents string
		stablePath     string
		persist        func(*Installer, installPlan, *backup) error
	}{
		{
			name: "APT", release: "ID=debian\nVERSION_ID=13\n", markerPath: aptAbsentMarkerPath,
			markerContents: aptAbsentMarkerContents, stablePath: aptStableBackupPath,
			persist: func(installer *Installer, _ installPlan, b *backup) error {
				return installer.persistAPTDependencyBaseline(b, true, true)
			},
		},
		{
			name: "DNF4", release: "ID=rocky\nVERSION_ID=9.6\n", markerPath: dnfAbsentMarkerPath,
			markerContents: dnfAbsentMarkerContents, stablePath: dnfStableBackupPath,
			persist: func(installer *Installer, plan installPlan, b *backup) error {
				return installer.persistDNF4DependencyBaseline(plan, b, true)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, runner, locker := setupInstaller(t, test.release)
			plan, err := installer.prepare(context.Background(), telegramOptions())
			if err != nil {
				t.Fatal(err)
			}
			write(t, root, test.markerPath, test.markerContents, 0o600)
			b, err := installer.createBackup()
			if err != nil {
				t.Fatal(err)
			}
			tx, err := installer.beginTransaction(b, nil, timerSnapshot{enablement: "not-found"})
			if err != nil {
				t.Fatal(err)
			}
			write(t, root, test.stablePath, "retained vendor baseline\n", 0o600)
			if err := installer.captureDependencyDefaults(b); err != nil {
				t.Fatal(err)
			}
			installer.fs = &panicRemoveFS{FileSystem: root, path: test.markerPath}
			var interrupted any
			func() {
				defer func() { interrupted = recover() }()
				_ = test.persist(installer, plan, b)
			}()
			if interrupted == nil {
				t.Fatal("metadata unlink was not interrupted")
			}
			if !existsNoErr(root, test.markerPath) {
				t.Fatal("interruption model removed live metadata before stopping")
			}
			entryFound := false
			for _, entry := range tx.journal.Paths {
				if entry.Path == test.markerPath {
					entryFound = true
					if entry.Exists || entry.PreserveCurrent {
						t.Fatalf("durable marker baseline = %+v, want absent", entry)
					}
				}
			}
			if !entryFound {
				t.Fatal("transaction journal omitted metadata path")
			}

			recovery := freshTestInstaller(t, root, runner, locker)
			if err := recovery.recoverInterruptedTransaction(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			if existsNoErr(root, test.markerPath) {
				t.Fatal("recovery resurrected superseded dependency metadata")
			}
			if got := readFile(t, root, test.stablePath); got != "retained vendor baseline\n" {
				t.Fatalf("recovery changed retained baseline to %q", got)
			}
		})
	}
}

func TestFinalTransactionCleanupIsIdempotentAfterPartialPrivateRemoval(t *testing.T) {
	for _, state := range []string{transactionStateCommit, transactionStateRevert} {
		t.Run(state, func(t *testing.T) {
			installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, FeishuPlainCredentialPath, "plain-old-secret", 0o600)
			write(t, root, FeishuEncryptedCredPath, "encrypted-old-secret", 0o600)
			private, err := installer.snapshotPrivateCredentials()
			if err != nil {
				t.Fatal(err)
			}
			defer zeroPrivateSnapshots(private)
			b, err := installer.createBackup()
			if err != nil {
				t.Fatal(err)
			}
			tx, err := installer.beginTransaction(b, private, timerSnapshot{enablement: "not-found"})
			if err != nil {
				t.Fatal(err)
			}
			tx.journal.State = state
			if err := tx.write(); err != nil {
				t.Fatal(err)
			}
			if err := root.Remove(plainCredentialRecoveryPath); err != nil {
				t.Fatal(err)
			}
			if !existsNoErr(root, encryptedCredentialRecoveryPath) {
				t.Fatal("partial cleanup model lost both private recovery files")
			}

			recovery := freshTestInstaller(t, root, runner, locker)
			if err := recovery.recoverInterruptedTransaction(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			if existsNoErr(root, plainCredentialRecoveryPath) || existsNoErr(root, encryptedCredentialRecoveryPath) ||
				existsNoErr(root, tx.path) {
				t.Fatal("idempotent final cleanup left transaction material")
			}
		})
	}
}
