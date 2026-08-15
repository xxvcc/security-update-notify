package uninstaller

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
	"github.com/xxvcc/security-update-notify/internal/dependencyproof"
	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

func TestUninstallNormalRemovesRuntimeAndPreservesUserData(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"/etc/systemd/system/security-update-notify.service",
		"/etc/systemd/system/security-update-notify.timer",
		"/etc/systemd/system/security-update-notify.service.d/credentials.conf",
		"/etc/logrotate.d/security-update-notify",
		"/usr/local/sbin/security-update-notify",
		timerStampLogical,
		"/etc/security-update-notify/telegram.env",
		"/var/lib/security-update-notify/last-alert.hash",
		"/var/backups/security-update-notify/backup/telegram.env",
		"/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred",
		"/var/log/security-update-notify.log",
		"/etc/systemd/system/security-update-notify.service.d/keep.conf",
		"/var/lib/systemd/timers/stamp-unrelated.timer",
	} {
		writeFixture(t, root, path, "data")
	}
	for _, logical := range []string{persistentTimerLinkLogical, runtimeTimerLinkLogical} {
		link := hostPath(root, logical)
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(timerUnitLogical, link); err != nil {
			t.Fatal(err)
		}
	}

	var calls [][]string
	report, err := uninstallAsRoot(Options{
		RootDir: root,
		RunCommand: func(name string, args ...string) sysexec.Result {
			calls = append(calls, append([]string{name}, args...))
			return sysexec.Result{Code: 1, Err: errors.New("systemd unavailable")}
		},
	})
	if err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	if report.SystemctlFailureCount != 3 {
		t.Fatalf("SystemctlFailureCount = %d, want 3", report.SystemctlFailureCount)
	}
	wantCalls := [][]string{
		{"systemctl", "disable", "--now", timerUnit},
		{"systemctl", "stop", serviceUnit},
		{"systemctl", "daemon-reload"},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("systemctl calls = %#v, want %#v", calls, wantCalls)
	}
	for _, path := range []string{
		"/etc/systemd/system/security-update-notify.service",
		"/etc/systemd/system/security-update-notify.timer",
		"/etc/systemd/system/security-update-notify.service.d/credentials.conf",
		"/etc/logrotate.d/security-update-notify",
		"/usr/local/sbin/security-update-notify",
		timerStampLogical,
		persistentTimerLinkLogical,
		runtimeTimerLinkLogical,
	} {
		assertMissing(t, root, path)
	}
	for _, path := range []string{
		"/etc/security-update-notify/telegram.env",
		"/var/lib/security-update-notify/last-alert.hash",
		"/var/backups/security-update-notify/backup/telegram.env",
		"/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred",
		"/var/log/security-update-notify.log",
		"/etc/systemd/system/security-update-notify.service.d/keep.conf",
		"/var/lib/systemd/timers/stamp-unrelated.timer",
	} {
		assertContent(t, root, path, "data")
	}
}

func TestUninstallTimerStampRemovalFailsClosedForUnsafeEntries(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string) string
		reason  string
	}{
		{
			name: "symbolic link",
			prepare: func(t *testing.T, root string) string {
				target := writeFixture(t, root, "/outside-timer-state", "outside")
				stamp := hostPath(root, timerStampLogical)
				if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, stamp); err != nil {
					t.Fatal(err)
				}
				return target
			},
			reason: "must be a regular file",
		},
		{
			name: "fifo",
			prepare: func(t *testing.T, root string) string {
				stamp := hostPath(root, timerStampLogical)
				if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(stamp, 0o600); err != nil {
					t.Fatal(err)
				}
				return ""
			},
			reason: "must be a regular file",
		},
		{
			name: "directory",
			prepare: func(t *testing.T, root string) string {
				stamp := hostPath(root, timerStampLogical)
				if err := os.MkdirAll(stamp, 0o755); err != nil {
					t.Fatal(err)
				}
				return ""
			},
			reason: "refusing to remove directory",
		},
		{
			name: "wrong owner",
			prepare: func(t *testing.T, root string) string {
				if os.Geteuid() != 0 {
					t.Skip("changing fixture ownership requires root")
				}
				stamp := writeFixture(t, root, timerStampLogical, "state")
				if err := os.Chown(stamp, 1, 1); err != nil {
					t.Skipf("cannot change fixture ownership: %v", err)
				}
				return ""
			},
			reason: "owner uid",
		},
		{
			name: "group writable",
			prepare: func(t *testing.T, root string) string {
				stamp := writeFixture(t, root, timerStampLogical, "state")
				if err := os.Chmod(stamp, 0o660); err != nil {
					t.Fatal(err)
				}
				return ""
			},
			reason: "forbidden permissions",
		},
		{
			name: "multiple hard links",
			prepare: func(t *testing.T, root string) string {
				stamp := writeFixture(t, root, timerStampLogical, "state")
				alias := stamp + ".alias"
				if err := os.Link(stamp, alias); err != nil {
					t.Fatal(err)
				}
				return alias
			},
			reason: "exactly one hard link",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			other := test.prepare(t, root)
			writeFixture(t, root, "/usr/local/sbin/security-update-notify", "runtime")

			_, err := uninstallAsRoot(Options{RootDir: root, RunCommand: successfulRunner})
			if err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("Uninstall() error = %v, want %q", err, test.reason)
			}
			if _, statErr := os.Lstat(hostPath(root, timerStampLogical)); statErr != nil {
				t.Fatalf("unsafe timer stamp was not retained: %v", statErr)
			}
			assertMissing(t, root, "/usr/local/sbin/security-update-notify")
			if other != "" {
				if _, statErr := os.Lstat(other); statErr != nil {
					t.Fatalf("related external entry changed: %v", statErr)
				}
			}
		})
	}
}

func TestTimerStampRemovalRejectsHardLinkAddedAfterValidation(t *testing.T) {
	root := t.TempDir()
	stamp := writeFixture(t, root, timerStampLogical, "state")
	alias := filepath.Join(root, "hard-link-after-validation")
	validate := func(info os.FileInfo) error {
		return filetrust.ValidateRegular(info, os.Geteuid(), 0o022, true)
	}
	err := removeLogicalFileValidatedWithSyncAndRecovery(
		root,
		timerStampLogical,
		func() error { return os.Link(stamp, alias) },
		syncLogicalRemovalParent,
		trustedParentRemovalRecovery,
		validate,
	)
	if err == nil || !strings.Contains(err.Error(), "entry changed before removal") {
		t.Fatalf("post-validation hard link error = %v, want fail-closed concurrent-change error", err)
	}
	stampInfo, stampErr := os.Stat(stamp)
	aliasInfo, aliasErr := os.Stat(alias)
	if stampErr != nil || aliasErr != nil || !os.SameFile(stampInfo, aliasInfo) {
		t.Fatalf("validated stamp and concurrent alias were not both retained: stamp=%v alias=%v", stampErr, aliasErr)
	}
}

func TestTimerStampOwnedRecoveryRejectsChangedHardLinkCount(t *testing.T) {
	root := t.TempDir()
	stamp := writeFixture(t, root, timerStampLogical, "state")
	info, err := os.Lstat(stamp)
	if err != nil {
		t.Fatal(err)
	}
	pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("d", 32)
	owned, err := ownedRemovalName(pending, info, removalLeaf)
	if err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(filepath.Dir(stamp), owned)
	if err := os.Rename(stamp, ownedPath); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "hard-link-after-crash")
	if err := os.Link(ownedPath, alias); err != nil {
		t.Fatal(err)
	}

	err = removeLogicalFile(root, filepath.Join(filepath.Dir(timerStampLogical), "missing"))
	if err == nil || !strings.Contains(err.Error(), "does not match its durable identity") {
		t.Fatalf("changed owned hard-link count error = %v, want durable-identity refusal", err)
	}
	ownedInfo, ownedErr := os.Stat(ownedPath)
	aliasInfo, aliasErr := os.Stat(alias)
	if ownedErr != nil || aliasErr != nil || !os.SameFile(ownedInfo, aliasInfo) {
		t.Fatalf("changed owned quarantine and alias were not retained: owned=%v alias=%v", ownedErr, aliasErr)
	}
}

func TestTrustedTimerStampRemovalRestoresStampWhenHardLinkAppearsBeforeClaim(t *testing.T) {
	root := t.TempDir()
	stamp := writeFixture(t, root, timerStampLogical, "state")
	alias := stamp + ".alias"

	err := removeTrustedLogicalRegularFileWithHook(root, timerStampLogical, func() error {
		return os.Link(stamp, alias)
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one hard link") ||
		!strings.Contains(err.Error(), "concurrent entry restored") {
		t.Fatalf("removeTrustedLogicalRegularFileWithHook() error = %v, want restored hard-link refusal", err)
	}
	assertPathContent(t, stamp, "state")
	assertPathContent(t, alias, "state")
}

func TestTrustedTimerStampRemovalRetainsQuarantineWhenHardLinkAppearsBeforeDelete(t *testing.T) {
	root := t.TempDir()
	stamp := writeFixture(t, root, timerStampLogical, "state")
	parent, name, err := openLogicalParent(root, timerStampLogical)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	expected, err := readRemovalEntry(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	validate := func(info os.FileInfo) error {
		return filetrust.ValidateRegular(info, os.Geteuid(), 0o022, true)
	}
	alias := stamp + ".alias"
	retained := ""
	err = removeValidatedEntryAtWithHooks(parent, name, expected, removalLeaf, removalHooks{
		validate: validate,
		beforeDelete: func(owned string) error {
			retained = filepath.Join(filepath.Dir(stamp), owned)
			return os.Link(retained, alias)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one hard link") ||
		!strings.Contains(err.Error(), "retained at "+retained) {
		t.Fatalf("removeValidatedEntryAtWithHooks() error = %v, want retained hard-link refusal", err)
	}
	assertPathMissing(t, stamp)
	assertPathContent(t, retained, "state")
	assertPathContent(t, alias, "state")
}

func TestUninstallRejectsInterruptedInstallStateBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		logical string
	}{
		{
			name:    "transaction journal",
			logical: "/var/backups/security-update-notify/20260806010101/transaction.json",
		},
		{
			name:    "plain credential recovery",
			logical: "/etc/security-update-notify/credentials/.feishu-app-secret.install-recovery",
		},
		{
			name:    "encrypted credential recovery",
			logical: "/etc/credstore.encrypted/.security-update-notify-feishu-app-secret.cred.install-recovery",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			marker := writeFixture(t, root, "/usr/local/sbin/security-update-notify", "runtime")
			state := writeFixture(t, root, test.logical, "recovery state")
			if err := os.Chmod(state, 0o600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			_, err := uninstallAsRoot(Options{
				RootDir: root,
				RunCommand: func(string, ...string) sysexec.Result {
					calls++
					return sysexec.Result{Code: 0}
				},
			})
			if err == nil || ExitCode(err) != 1 || !strings.Contains(err.Error(), "interrupted installation") {
				t.Fatalf("Uninstall() error=%v, want interrupted-install refusal", err)
			}
			if calls != 0 {
				t.Fatalf("systemctl ran %d times before interrupted-install refusal", calls)
			}
			if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "runtime" {
				t.Fatalf("runtime changed before refusal: data=%q err=%v", got, readErr)
			}
			if got, readErr := os.ReadFile(state); readErr != nil || string(got) != "recovery state" {
				t.Fatalf("recovery state changed before refusal: data=%q err=%v", got, readErr)
			}
		})
	}
}

func TestUninstallRejectsUntrustedInterruptedStateDirectoryBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		logical string
	}{
		{name: "backup directory", logical: "/var/backups/security-update-notify/20260806010101"},
		{name: "plain recovery parent", logical: "/etc/security-update-notify/credentials"},
		{name: "encrypted recovery parent", logical: "/etc/credstore.encrypted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			marker := writeFixture(t, root, "/usr/local/sbin/security-update-notify", "runtime")
			unsafeDirectory := hostPath(root, test.logical)
			if err := os.MkdirAll(unsafeDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(unsafeDirectory, 0o770); err != nil {
				t.Fatal(err)
			}
			calls := 0
			_, err := uninstallAsRoot(Options{
				RootDir: root,
				RunCommand: func(string, ...string) sysexec.Result {
					calls++
					return sysexec.Result{Code: 0}
				},
			})
			if err == nil || ExitCode(err) != 1 || !strings.Contains(err.Error(), "forbidden permissions") {
				t.Fatalf("Uninstall() error=%v, want untrusted interrupted-state refusal", err)
			}
			if calls != 0 {
				t.Fatalf("systemctl ran %d times before untrusted-state refusal", calls)
			}
			if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "runtime" {
				t.Fatalf("runtime changed before refusal: data=%q err=%v", got, readErr)
			}
		})
	}
}

func TestPurgeRestoresFixedAPTBackupAndRemovesSensitiveData(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades", "managed")
	fixed := writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak", "baseline")
	timestamp := writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260726120000", "newer")
	setMtime(t, fixed, time.Unix(100, 0))
	setMtime(t, timestamp, time.Unix(200, 0))
	for _, path := range []string{
		"/etc/security-update-notify/telegram.env",
		"/etc/security-update-notify/credentials/feishu-app-secret",
		"/var/lib/security-update-notify/last-alert.hash",
		"/var/backups/security-update-notify/20260726/telegram.env",
		"/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred",
		"/var/log/security-update-notify.log",
		"/var/log/security-update-notify.log.1",
		"/var/log/security-update-notify.log.2.gz",
		"/var/log/security-update-notify.logger",
		"/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify",
		"/etc/needrestart/conf.d/99-security-update-notify-report-only.conf",
	} {
		writeFixture(t, root, path, "secret")
	}
	// The 1.1.x legacy policy is removed only when its bytes still match that
	// release exactly; identical-path administrator files must survive.
	writeFixture(t, root, aptLegacyLocalPolicyLogical, aptconfig.LegacyLocalPolicy)

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatalf("Uninstall(purge) error = %v", err)
	}
	if report.RestoredAPTFrom != "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak" {
		t.Fatalf("RestoredAPTFrom = %q", report.RestoredAPTFrom)
	}
	assertContent(t, root, "/etc/apt/apt.conf.d/20auto-upgrades", "baseline")
	assertMissing(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak")
	assertMissing(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260726120000")
	for _, path := range []string{
		"/etc/security-update-notify",
		"/var/lib/security-update-notify",
		"/var/backups/security-update-notify",
		"/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred",
		"/var/log/security-update-notify.log",
		"/var/log/security-update-notify.log.1",
		"/var/log/security-update-notify.log.2.gz",
		"/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify",
		aptLegacyLocalPolicyLogical,
		"/etc/needrestart/conf.d/99-security-update-notify-report-only.conf",
	} {
		assertMissing(t, root, path)
	}
	assertContent(t, root, "/var/log/security-update-notify.logger", "secret")
}

func TestPurgeRestorePreservesFileMetadataAndXattrs(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	fixed := writeFixture(t, root, aptStableLogical, "vendor baseline")
	if err := os.Chmod(fixed, 0o641); err != nil {
		t.Fatal(err)
	}
	wantMtime := time.Unix(1_700_000_000, 123_456_789)
	if err := os.Chtimes(fixed, wantMtime, wantMtime); err != nil {
		t.Fatal(err)
	}

	xattrSupported := true
	const xattrName = "user.security-update-notify-restore-test"
	wantXattr := []byte("preserved")
	if err := syscall.Setxattr(fixed, xattrName, wantXattr, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
			xattrSupported = false
		} else {
			t.Fatal(err)
		}
	}
	wantInfo, err := os.Stat(fixed)
	if err != nil {
		t.Fatal(err)
	}
	if !wantInfo.ModTime().Equal(wantMtime) {
		t.Skipf("filesystem does not preserve nanosecond mtimes: got %s want %s", wantInfo.ModTime(), wantMtime)
	}

	if _, err := restoreAPT(root); err != nil {
		t.Fatalf("restoreAPT error = %v", err)
	}
	destination := hostPath(root, aptPeriodicLogical)
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	gotInfo, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if gotInfo.Mode() != wantInfo.Mode() {
		t.Fatalf("restored mode = %v, want %v", gotInfo.Mode(), wantInfo.Mode())
	}
	if !gotInfo.ModTime().Equal(wantInfo.ModTime()) {
		t.Fatalf("restored mtime = %v, want %v", gotInfo.ModTime(), wantInfo.ModTime())
	}
	wantStat, wantOK := wantInfo.Sys().(*syscall.Stat_t)
	gotStat, gotOK := gotInfo.Sys().(*syscall.Stat_t)
	if !wantOK || !gotOK {
		t.Fatalf("restored stat types = (%T, %T), want syscall.Stat_t", wantInfo.Sys(), gotInfo.Sys())
	}
	if gotStat.Uid != wantStat.Uid || gotStat.Gid != wantStat.Gid {
		t.Fatalf("restored owner = (%v, %v), want (%v, %v)", gotStat.Uid, gotStat.Gid, wantStat.Uid, wantStat.Gid)
	}
	if xattrSupported {
		gotXattr := make([]byte, len(wantXattr)+1)
		n, err := syscall.Getxattr(destination, xattrName, gotXattr)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotXattr[:n], wantXattr) {
			t.Fatalf("restored xattr = %q, want %q", gotXattr[:n], wantXattr)
		}
	}
}

func TestRestoreFileInfoDetectsHardLinkStateChange(t *testing.T) {
	root := t.TempDir()
	file := writeFixture(t, root, "/etc/apt/apt.conf.d/backup", "backup")
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, file+".alias"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if sameRestoreFileInfo(before, after) {
		t.Fatal("hard-link count change was accepted as a stable restore file")
	}
}

func TestRestoreFileStateDetectsSameSizeRewriteWithRestoredMtime(t *testing.T) {
	root := t.TempDir()
	file := writeFixture(t, root, "/etc/apt/apt.conf.d/backup", "original")
	mtime := time.Unix(1_700_000_000, 123_456_789)
	if err := os.Chtimes(file, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("modified"), before.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat := before.Sys().(*syscall.Stat_t)
	afterStat := after.Sys().(*syscall.Stat_t)
	if beforeStat.Ctim == afterStat.Ctim {
		t.Skip("filesystem did not expose a ctime change for the rewrite")
	}
	if !sameRestoreFileInfo(before, after) {
		t.Fatal("rewrite fixture changed metadata other than ctime")
	}
	if sameRestoreFileState(before, after) {
		t.Fatal("same-size rewrite with restored mtime was accepted as a stable restore file")
	}
}

func TestPurgeRestoresFixedAPTBackupWhenDestinationIsMissing(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptStableLogical, "vendor baseline")

	if _, err := restoreAPT(root); err != nil {
		t.Fatalf("restoreAPT error = %v", err)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	assertMissing(t, root, aptStableLogical)
}

func TestPurgeDoesNotRestoreAPTTimestampWhenFixedBackupMissing(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades", "managed")
	old := writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260725000000", "old")
	newer := writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260726000000", "newest")
	setMtime(t, old, time.Unix(100, 0))
	setMtime(t, newer, time.Unix(200, 0))

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatalf("Uninstall(purge) error = %v", err)
	}
	if report.RestoredAPTFrom != "" {
		t.Fatalf("RestoredAPTFrom = %q, want empty", report.RestoredAPTFrom)
	}
	assertContent(t, root, "/etc/apt/apt.conf.d/20auto-upgrades", "managed")
	assertMissing(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260725000000")
	assertMissing(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.20260726000000")
}

func TestPurgePreservesUnknownProjectBackupSuffixes(t *testing.T) {
	root := t.TempDir()
	aptUnknown := writeFixture(t, root, aptStableLogical+".not-a-timestamp", "apt unrelated")
	dnfUnknown := writeFixture(t, root, "/etc/dnf/"+dnfStableName+".not-a-timestamp", "dnf unrelated")
	if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
		t.Fatal(err)
	}
	assertContent(t, root, logicalPath(root, aptUnknown), "apt unrelated")
	assertContent(t, root, logicalPath(root, dnfUnknown), "dnf unrelated")
}

func TestPurgeRestoresOldestProjectDNFBackupForLegacyCompatibility(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/dnf/automatic.conf", "managed")
	old := writeFixture(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260725000000", "old")
	newer := writeFixture(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260726000000", "newest")
	legacy := writeFixture(t, root, "/etc/dnf/automatic.conf.bak.99999999999999", "legacy")
	// Backup filenames record creation order. File mtimes belong to the copied
	// configuration and may be newer or older than the backup itself.
	setMtime(t, old, time.Unix(300, 0))
	setMtime(t, newer, time.Unix(100, 0))
	setMtime(t, legacy, time.Unix(300, 0))

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatalf("Uninstall(purge) error = %v", err)
	}
	if report.RestoredDNFFrom != "/etc/dnf/automatic.conf.security-update-notify.bak.20260725000000" {
		t.Fatalf("RestoredDNFFrom = %q", report.RestoredDNFFrom)
	}
	if report.UsedLegacyDNFBackup {
		t.Fatal("UsedLegacyDNFBackup = true, want false")
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", "old")
	assertMissing(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260725000000")
	assertMissing(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260726000000")
	assertContent(t, root, "/etc/dnf/automatic.conf.bak.99999999999999", "legacy")
}

func TestPurgePrefersStableDNFBaselineAcrossReinstalls(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/dnf/automatic.conf", "managed-second-install")
	writeFixture(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak", "vendor-baseline")
	writeFixture(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260725000000", "managed-first-install")
	writeFixture(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260726000000", "managed-second-install")

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredDNFFrom != "/etc/dnf/automatic.conf.security-update-notify.bak" || report.UsedLegacyDNFBackup {
		t.Fatalf("report = %#v", report)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", "vendor-baseline")
	assertMissing(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak")
	assertMissing(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260725000000")
	assertMissing(t, root, "/etc/dnf/automatic.conf.security-update-notify.bak.20260726000000")
}

func TestPurgeRestoresOriginallyAbsentAPTConfiguration(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredAPTFrom != "" {
		t.Fatalf("RestoredAPTFrom = %q, want empty for absent baseline", report.RestoredAPTFrom)
	}
	assertMissing(t, root, aptPeriodicLogical)
	assertMissing(t, root, aptAbsentLogical)
}

func TestPurgeRestoresAPTAbsenceWithOnlyManagedTimestampHistory(t *testing.T) {
	root := t.TempDir()
	currentTimestamp := aptPeriodicLogical + ".security-update-notify.20260726000000.bak"
	legacyTimestamp := aptStableLogical + ".20260725000000"
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, currentTimestamp, aptconfig.Periodic)
	writeFixture(t, root, legacyTimestamp, aptconfig.Periodic)

	if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
		t.Fatal(err)
	}
	assertMissing(t, root, aptPeriodicLogical)
	assertMissing(t, root, aptAbsentLogical)
	assertMissing(t, root, currentTimestamp)
	assertMissing(t, root, legacyTimestamp)
}

func TestPurgePreservesProvenAPTDependencyDefault(t *testing.T) {
	root := t.TempDir()
	const vendor = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	writeFixture(t, root, aptPeriodicLogical, vendor)
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, aptDependencyProof, string(dependencyproof.Contents("apt", []byte(vendor))))

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredAPTFrom != "" {
		t.Fatalf("RestoredAPTFrom = %q, want retained current dependency default", report.RestoredAPTFrom)
	}
	assertContent(t, root, aptPeriodicLogical, vendor)
	assertMissing(t, root, aptAbsentLogical)
	assertMissing(t, root, aptDependencyProof)
}

func TestPurgeAPTMarkerRemovalFailureRetainsDependencyProof(t *testing.T) {
	root := t.TempDir()
	const vendor = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	writeFixture(t, root, aptPeriodicLogical, vendor)
	marker := writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, aptDependencyProof, string(dependencyproof.Contents("apt", []byte(vendor))))
	forced := errors.New("forced APT marker unlink failure")
	remove := func(name string) error {
		if name == marker {
			return forced
		}
		return nil
	}

	_, err := restoreAPTWithRemove(root, remove)
	if err == nil || !errors.Is(err, forced) {
		t.Fatalf("restoreAPTWithRemove error = %v", err)
	}
	assertContent(t, root, aptPeriodicLogical, vendor)
	assertContent(t, root, aptAbsentLogical, aptAbsentContents)
	assertContent(t, root, aptDependencyProof, string(dependencyproof.Contents("apt", []byte(vendor))))
}

func TestPurgeAPTMarkerRemovalFailureRetainsFixedBaselineForRetry(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	marker := writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, aptDependencyProof, string(dependencyproof.Contents("apt", []byte(aptconfig.Periodic))))
	forced := errors.New("forced APT marker unlink failure")
	remove := func(name string) error {
		if name == marker {
			return forced
		}
		return nil
	}

	_, err := restoreAPTWithRemove(root, remove)
	if err == nil || !errors.Is(err, forced) {
		t.Fatalf("restoreAPTWithRemove error = %v", err)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	assertContent(t, root, aptStableLogical, "vendor baseline")
	assertContent(t, root, aptAbsentLogical, aptAbsentContents)
	assertContent(t, root, aptDependencyProof, string(dependencyproof.Contents("apt", []byte(aptconfig.Periodic))))

	source, err := restoreAPT(root)
	if err != nil {
		t.Fatalf("retry restoreAPT error = %v", err)
	}
	if source != hostPath(root, aptStableLogical) {
		t.Fatalf("retry restoreAPT source = %q", source)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	assertMissing(t, root, aptStableLogical)
	assertMissing(t, root, aptAbsentLogical)
	assertMissing(t, root, aptDependencyProof)
}

func TestPurgeAPTConcurrentConfigReplacementRetainsRecoveryEvidence(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	marker := writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	proof := string(dependencyproof.Contents("apt", []byte(aptconfig.Periodic)))
	writeFixture(t, root, aptDependencyProof, proof)
	const concurrent = "concurrent administrator configuration"
	replaced := false

	_, err := restoreAPTWithRemove(root, func(name string) error {
		if name == marker && !replaced {
			replaceFileAtomically(t, hostPath(root, aptPeriodicLogical), concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "validated file changed") {
		t.Fatalf("restoreAPTWithRemove error = %v, want concurrent-change refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, aptStableLogical, "vendor baseline")
	assertContent(t, root, aptAbsentLogical, aptAbsentContents)
	assertContent(t, root, aptDependencyProof, proof)
	if _, err := restoreAPT(root); err == nil || !strings.Contains(err.Error(), "unfinished apt restore transaction") {
		t.Fatalf("retry restoreAPT error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, aptStableLogical, "vendor baseline")
	assertContent(t, root, aptDependencyProof, proof)
}

func TestPurgeAPTDoesNotDeleteConcurrentReplacementOfManagedConfig(t *testing.T) {
	root := t.TempDir()
	currentTimestamp := aptPeriodicLogical + ".security-update-notify.20260726000000.bak"
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, currentTimestamp, aptconfig.Periodic)
	const concurrent = "concurrent administrator configuration"
	destination := hostPath(root, aptPeriodicLogical)
	replaced := false

	_, err := restoreAPTWithRemove(root, func(name string) error {
		if name == destination && !replaced {
			replaceFileAtomically(t, destination, concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "validated file changed") {
		t.Fatalf("restoreAPTWithRemove error = %v, want concurrent-change refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, aptAbsentLogical, aptAbsentContents)
	assertContent(t, root, currentTimestamp, aptconfig.Periodic)
	if _, err := restoreAPT(root); err == nil || !strings.Contains(err.Error(), "unfinished apt restore transaction") {
		t.Fatalf("retry restoreAPT error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, currentTimestamp, aptconfig.Periodic)
}

func TestPurgeAPTDirectoryReplacementCannotRedirectRestore(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	marker := writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, aptDependencyProof, string(dependencyproof.Contents("apt", []byte(aptconfig.Periodic))))
	for name, content := range map[string]string{
		filepath.Base(aptPeriodicLogical): "outside config",
		filepath.Base(aptStableLogical):   "outside fixed",
		filepath.Base(aptAbsentLogical):   "outside marker",
		filepath.Base(aptDependencyProof): "outside proof",
	} {
		if err := os.WriteFile(filepath.Join(external, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	directory := filepath.Dir(hostPath(root, aptPeriodicLogical))
	heldDirectory := directory + "-held"
	replaced := false

	_, err := restoreAPTWithRemove(root, func(name string) error {
		if name == marker && !replaced {
			if err := os.Rename(directory, heldDirectory); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(external, directory); err != nil {
				t.Fatal(err)
			}
			replaced = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("restoreAPTWithRemove error = %v", err)
	}
	if !replaced {
		t.Fatal("directory replacement hook was not called")
	}
	assertPathContent(t, filepath.Join(heldDirectory, filepath.Base(aptPeriodicLogical)), "vendor baseline")
	assertPathMissing(t, filepath.Join(heldDirectory, filepath.Base(aptStableLogical)))
	assertPathMissing(t, filepath.Join(heldDirectory, filepath.Base(aptAbsentLogical)))
	assertPathMissing(t, filepath.Join(heldDirectory, filepath.Base(aptDependencyProof)))
	assertPathContent(t, filepath.Join(external, filepath.Base(aptPeriodicLogical)), "outside config")
	assertPathContent(t, filepath.Join(external, filepath.Base(aptStableLogical)), "outside fixed")
	assertPathContent(t, filepath.Join(external, filepath.Base(aptAbsentLogical)), "outside marker")
	assertPathContent(t, filepath.Join(external, filepath.Base(aptDependencyProof)), "outside proof")
}

func TestPurgeAPTDoesNotOverwriteConfigReplacedBeforePublish(t *testing.T) {
	root := t.TempDir()
	destination := writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	const concurrent = "concurrent administrator configuration"
	replaced := false

	_, err := restoreAPTWithRemove(root, func(name string) error {
		if name == destination && !replaced {
			replaceFileAtomically(t, destination, concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "destination changed before restore") {
		t.Fatalf("restoreAPTWithRemove error = %v, want pre-publish change refusal", err)
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, aptStableLogical, "vendor baseline")
	if _, err := restoreAPT(root); err == nil || !strings.Contains(err.Error(), "unfinished apt restore transaction") {
		t.Fatalf("retry restoreAPT error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, aptStableLogical, "vendor baseline")
}

func TestRestoreFileRetainsConcurrentDestinationChangedAfterExchange(t *testing.T) {
	root := t.TempDir()
	destination := writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()

	sourceName := filepath.Base(aptStableLogical)
	destinationName := filepath.Base(aptPeriodicLogical)
	sourceSnapshot, err := directory.readRegular(sourceName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	destinationSnapshot, err := directory.readRegular(destinationName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	const concurrent = "concurrent administrator configuration"
	directory.afterExchange = func() {
		replaceFileAtomically(t, destination, concurrent)
	}

	if _, err := directory.restoreFile(sourceName, destinationName, sourceSnapshot, destinationSnapshot); err == nil ||
		!strings.Contains(err.Error(), "entries retained") {
		t.Fatalf("restoreFile error = %v, want retained-entry conflict", err)
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, aptStableLogical, "vendor baseline")
	names, err := directory.names()
	if err != nil {
		t.Fatal(err)
	}
	temporaryNames := restoreNamesWithPrefix(names, ".security-update-notify-restore.")
	if len(temporaryNames) != 1 {
		t.Fatalf("retained restore entries = %v, want exactly one", temporaryNames)
	}
	assertPathContent(t, directory.host(temporaryNames[0]), "managed")
	if _, err := restoreAPT(root); err == nil || !strings.Contains(err.Error(), "unfinished apt restore transaction") {
		t.Fatalf("retry restoreAPT error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, aptPeriodicLogical, concurrent)
	assertContent(t, root, aptStableLogical, "vendor baseline")
}

func TestRestoreFileRecordsRecoverableStateWhenExchangeSyncFails(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()

	sourceName := filepath.Base(aptStableLogical)
	destinationName := filepath.Base(aptPeriodicLogical)
	sourceSnapshot, err := directory.readRegular(sourceName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	destinationSnapshot, err := directory.readRegular(destinationName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("forced directory sync failure")
	syncCalls := 0
	directory.syncDirectory = func() error {
		syncCalls++
		if syncCalls == 1 {
			return syncFailure
		}
		return directory.file.Sync()
	}

	if _, err := directory.restoreFile(sourceName, destinationName, sourceSnapshot, destinationSnapshot); err == nil ||
		!errors.Is(err, syncFailure) || !strings.Contains(err.Error(), "sync restore exchange; entries retained at") ||
		!strings.Contains(err.Error(), "recovery marker retained") {
		t.Fatalf("restoreFile error = %v, want recoverable exchange sync failure", err)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	names, err := directory.names()
	if err != nil {
		t.Fatal(err)
	}
	temporaryNames := restoreNamesWithPrefix(names, ".security-update-notify-restore.")
	conflictNames := restoreNamesWithPrefix(names, ".security-update-notify-conflict.")
	if len(temporaryNames) != 1 || len(conflictNames) != 1 {
		t.Fatalf("recovery artifacts: temporary=%v conflicts=%v", temporaryNames, conflictNames)
	}
	assertPathContent(t, directory.host(temporaryNames[0]), "managed")
	if _, err := restoreAPT(root); err == nil || !strings.Contains(err.Error(), "unfinished apt restore transaction") {
		t.Fatalf("retry restoreAPT error = %v, want unfinished-transaction refusal", err)
	}
}

func TestRestoreFileDoesNotDeleteReplacedTemporaryOnValidationFailure(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()

	sourceName := filepath.Base(aptStableLogical)
	destinationName := filepath.Base(aptPeriodicLogical)
	sourceSnapshot, err := directory.readRegular(sourceName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	destinationSnapshot, err := directory.readRegular(destinationName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := ""
	heldPath := ""
	directory.beforeTemporaryCommit = func(name string) error {
		temporaryPath = directory.host(name)
		heldPath = temporaryPath + ".held"
		if err := os.Rename(temporaryPath, heldPath); err != nil {
			return err
		}
		return os.WriteFile(temporaryPath, []byte("untrusted replacement"), 0o600)
	}

	if _, err := directory.restoreFile(sourceName, destinationName, sourceSnapshot, destinationSnapshot); err == nil ||
		!strings.Contains(err.Error(), "temporary restore file changed before commit") ||
		!strings.Contains(err.Error(), "temporary restore entry changed; retained at") {
		t.Fatalf("restoreFile error = %v, want replaced-temporary refusal", err)
	}
	assertPathContent(t, temporaryPath, "untrusted replacement")
	assertPathContent(t, heldPath, "vendor baseline")
	assertContent(t, root, aptPeriodicLogical, "managed")
}

func TestRestoreFileRejectsUnsafeBackupSourceMetadata(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *restoreDirectory, string)
		reason  string
	}{
		{name: "wrong owner", prepare: func(_ *testing.T, directory *restoreDirectory, _ string) {
			directory.ownerUID++
		}, reason: "owner uid"},
		{name: "group writable", prepare: func(t *testing.T, _ *restoreDirectory, source string) {
			if err := os.Chmod(source, 0o664); err != nil {
				t.Fatal(err)
			}
		}, reason: "forbidden permissions"},
		{name: "hard linked", prepare: func(t *testing.T, _ *restoreDirectory, source string) {
			if err := os.Link(source, source+".alias"); err != nil {
				t.Fatal(err)
			}
		}, reason: "exactly one hard link"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			destination := writeFixture(t, root, aptPeriodicLogical, "managed")
			source := writeFixture(t, root, aptStableLogical, "vendor baseline")
			directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
			if err != nil {
				t.Fatal(err)
			}
			defer directory.close()
			test.prepare(t, directory, source)
			sourceSnapshot, err := directory.readRegular(filepath.Base(source), restoreConfigLimit)
			if err != nil {
				t.Fatal(err)
			}
			destinationSnapshot, err := directory.readRegular(filepath.Base(destination), restoreConfigLimit)
			if err != nil {
				t.Fatal(err)
			}

			_, err = directory.restoreFile(filepath.Base(source), filepath.Base(destination), sourceSnapshot, destinationSnapshot)
			if err == nil || !strings.Contains(err.Error(), "unsafe backup source") || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("unsafe backup error = %v, want %q", err, test.reason)
			}
			assertPathContent(t, destination, "managed")
			names, readErr := directory.names()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if temporary := restoreNamesWithPrefix(names, ".security-update-notify-restore."); len(temporary) != 0 {
				t.Fatalf("restore temporary created before source validation: %v", temporary)
			}
		})
	}
}

func TestRestoreDecisionFilesRejectUnsafeMetadata(t *testing.T) {
	targets := []struct {
		name    string
		logical string
		content string
		read    func(*restoreDirectory, string) error
	}{
		{
			name: "apt marker", logical: aptAbsentLogical, content: aptAbsentContents,
			read: func(directory *restoreDirectory, name string) error {
				_, err := readAPTMarkerSnapshot(directory, name)
				return err
			},
		},
		{
			name: "apt proof", logical: aptDependencyProof, content: "proof\n",
			read: func(directory *restoreDirectory, name string) error {
				_, err := directory.readTrustedRegular(name, 256)
				return err
			},
		},
		{
			name: "dnf marker", logical: "/etc/dnf/" + dnfAbsentName, content: dnf4AbsentContents,
			read: func(directory *restoreDirectory, name string) error {
				_, _, err := readDNFMarkerSnapshot(directory, name)
				return err
			},
		},
		{
			name: "dnf proof", logical: "/etc/dnf/" + dnfDependencyProofName, content: "proof\n",
			read: func(directory *restoreDirectory, name string) error {
				_, err := directory.readTrustedRegular(name, 256)
				return err
			},
		},
	}
	mutations := []struct {
		name    string
		prepare func(*testing.T, *restoreDirectory, string)
		reason  string
	}{
		{
			name: "wrong owner", reason: "owner uid",
			prepare: func(_ *testing.T, directory *restoreDirectory, _ string) { directory.ownerUID++ },
		},
		{
			name: "group writable", reason: "forbidden permissions",
			prepare: func(t *testing.T, _ *restoreDirectory, file string) {
				if err := os.Chmod(file, 0o660); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard linked", reason: "exactly one hard link",
			prepare: func(t *testing.T, _ *restoreDirectory, file string) {
				if err := os.Link(file, file+".alias"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, target := range targets {
		for _, mutation := range mutations {
			t.Run(target.name+"/"+mutation.name, func(t *testing.T) {
				root := t.TempDir()
				file := writeFixture(t, root, target.logical, target.content)
				directory, err := openRestoreDirectory(root, filepath.Dir(target.logical))
				if err != nil {
					t.Fatal(err)
				}
				defer directory.close()
				mutation.prepare(t, directory, file)

				err = target.read(directory, filepath.Base(target.logical))
				if err == nil || !strings.Contains(err.Error(), "unsafe restore decision file") ||
					!strings.Contains(err.Error(), mutation.reason) {
					t.Fatalf("unsafe decision metadata error = %v, want %q", err, mutation.reason)
				}
			})
		}
	}
}

func TestRemoveValidatedReportsRetainedQuarantinePath(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	destination := filepath.Base(aptPeriodicLogical)
	snapshot, err := directory.readRegular(destination, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	forced := errors.New("forced quarantine removal failure")
	directory.beforeRemove = func(name string) error {
		if isRestoreTemporaryName(name, restorePurgePrefix) {
			return forced
		}
		return nil
	}

	err = directory.removeValidated(destination, snapshot)
	if err == nil || !errors.Is(err, forced) || !strings.Contains(err.Error(), "remove validated file retained at "+directory.host("."+restorePurgePrefix+".")) {
		t.Fatalf("removeValidated error = %v, want retained quarantine path", err)
	}
}

func TestFailedPlaceholderCleanupReportsPrimaryErrorAndRetainedPath(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	placeholder, name, err := directory.newTemporary(restorePurgePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := placeholder.Close(); err != nil {
		t.Fatal(err)
	}
	closeFailure := errors.New("forced placeholder close failure")
	cleanupFailure := errors.New("forced placeholder cleanup failure")
	directory.beforeRemove = func(candidate string) error {
		if candidate == name {
			return cleanupFailure
		}
		return nil
	}

	err = directory.cleanupUncommittedPlaceholder(name, closeFailure)
	if !errors.Is(err, closeFailure) || !errors.Is(err, cleanupFailure) ||
		!strings.Contains(err.Error(), "retained at "+directory.host(name)) {
		t.Fatalf("placeholder cleanup error = %v, want both failures and retained path", err)
	}
	assertPathContent(t, directory.host(name), "")
}

func TestPurgeAPTDoesNotDeleteFixedBackupReplacedDuringCleanup(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	fixed := writeFixture(t, root, aptStableLogical, "vendor baseline")
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	proof := string(dependencyproof.Contents("apt", []byte(aptconfig.Periodic)))
	writeFixture(t, root, aptDependencyProof, proof)
	const concurrent = "concurrent replacement backup"
	replaced := false

	_, err := restoreAPTWithRemove(root, func(name string) error {
		if name == fixed && !replaced {
			replaceFileAtomically(t, fixed, concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "validated file changed") {
		t.Fatalf("restoreAPTWithRemove error = %v, want cleanup change refusal", err)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	assertContent(t, root, aptStableLogical, concurrent)
	assertMissing(t, root, aptAbsentLogical)
	assertContent(t, root, aptDependencyProof, proof)
	if _, err := restoreAPT(root); err == nil || !strings.Contains(err.Error(), "unfinished apt restore transaction") {
		t.Fatalf("retry restoreAPT error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	assertContent(t, root, aptStableLogical, concurrent)
	assertContent(t, root, aptDependencyProof, proof)
}

func TestPurgeAPTDoesNotDeleteTimestampReplacedDuringCleanup(t *testing.T) {
	root := t.TempDir()
	timestampLogical := aptPeriodicLogical + ".security-update-notify.20260726000000.bak"
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	timestamp := writeFixture(t, root, timestampLogical, aptconfig.Periodic)
	const concurrent = "concurrent replacement backup"
	replaced := false

	_, err := restoreAPTWithRemove(root, func(name string) error {
		if name == timestamp && !replaced {
			replaceFileAtomically(t, timestamp, concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "validated file changed") {
		t.Fatalf("restoreAPTWithRemove error = %v, want cleanup change refusal", err)
	}
	assertMissing(t, root, aptPeriodicLogical)
	assertMissing(t, root, aptAbsentLogical)
	assertContent(t, root, timestampLogical, concurrent)
	if _, err := restoreAPT(root); err == nil || !strings.Contains(err.Error(), "unfinished apt restore transaction") {
		t.Fatalf("retry restoreAPT error = %v, want unfinished-transaction refusal", err)
	}
	assertMissing(t, root, aptPeriodicLogical)
	assertContent(t, root, timestampLogical, concurrent)
}

func TestPurgeRejectsUnprovenAPTDependencyDefault(t *testing.T) {
	root := t.TempDir()
	currentTimestamp := aptPeriodicLogical + ".security-update-notify.20260726000000.bak"
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, currentTimestamp, "vendor baseline")

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("error = %v, want unproven APT dependency-default error", err)
	}
	assertContent(t, root, aptPeriodicLogical, aptconfig.Periodic)
	assertContent(t, root, aptAbsentLogical, aptAbsentContents)
	assertContent(t, root, currentTimestamp, "vendor baseline")
}

func TestPurgeRejectsMismatchedAPTDependencyProof(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "vendor default")
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	proof := string(dependencyproof.Contents("apt", []byte("different")))
	writeFixture(t, root, aptDependencyProof, proof)

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "proof does not match") {
		t.Fatalf("error = %v, want mismatched APT proof error", err)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor default")
	assertContent(t, root, aptAbsentLogical, aptAbsentContents)
	assertContent(t, root, aptDependencyProof, proof)
}

func TestPurgeRestoresOriginallyAbsentDNFConfiguration(t *testing.T) {
	root := t.TempDir()
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	writeFixture(t, root, "/etc/dnf/automatic.conf", "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf5AbsentContents)
	writeFixture(t, root, currentTimestamp, "managed")

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredDNFFrom != "" || report.UsedLegacyDNFBackup {
		t.Fatalf("report = %#v", report)
	}
	assertMissing(t, root, "/etc/dnf/automatic.conf")
	assertMissing(t, root, "/etc/dnf/"+dnfAbsentName)
	assertMissing(t, root, "/etc/dnf/"+dnfDependencyProofName)
	assertMissing(t, root, currentTimestamp)
}

func TestPurgeRejectsUnprovenDNF4DependencyDefault(t *testing.T) {
	root := t.TempDir()
	const vendorConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	writeFixture(t, root, "/etc/dnf/automatic.conf", vendorConfig)
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, currentTimestamp, "managed timestamp")

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("error = %v, want unproven DNF4 dependency-default error", err)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", vendorConfig)
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	assertMissing(t, root, "/etc/dnf/"+dnfDependencyProofName)
	assertContent(t, root, currentTimestamp, "managed timestamp")
}

func TestPurgePreservesProvenDNFDependencyDefault(t *testing.T) {
	root := t.TempDir()
	const vendorConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	writeFixture(t, root, "/etc/dnf/automatic.conf", vendorConfig)
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte(vendorConfig))))
	writeFixture(t, root, currentTimestamp, "managed")

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredDNFFrom != "" || report.UsedLegacyDNFBackup {
		t.Fatalf("report = %#v", report)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", vendorConfig)
	assertMissing(t, root, "/etc/dnf/"+dnfAbsentName)
	assertMissing(t, root, "/etc/dnf/"+dnfDependencyProofName)
	assertMissing(t, root, currentTimestamp)
}

func TestPurgeDNFMarkerRemovalFailureRetainsDependencyProof(t *testing.T) {
	root := t.TempDir()
	const vendor = "[commands]\nupgrade_type = default\napply_updates = no\n"
	writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, vendor)
	marker := writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte(vendor))))
	forced := errors.New("forced DNF marker unlink failure")
	remove := func(name string) error {
		if name == marker {
			return forced
		}
		return nil
	}

	_, _, err := restoreDNFWithRemove(root, remove)
	if err == nil || !errors.Is(err, forced) {
		t.Fatalf("restoreDNFWithRemove error = %v", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, vendor)
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte(vendor))))
}

func TestPurgeDNFMarkerRemovalFailureRetainsFixedBaselineForRetry(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	marker := writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte("managed"))))
	forced := errors.New("forced DNF marker unlink failure")
	remove := func(name string) error {
		if name == marker {
			return forced
		}
		return nil
	}

	_, _, err := restoreDNFWithRemove(root, remove)
	if err == nil || !errors.Is(err, forced) {
		t.Fatalf("restoreDNFWithRemove error = %v", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, "vendor baseline")
	assertContent(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte("managed"))))

	source, legacy, err := restoreDNF(root)
	if err != nil {
		t.Fatalf("retry restoreDNF error = %v", err)
	}
	if source != hostPath(root, "/etc/dnf/"+dnfStableName) || legacy {
		t.Fatalf("retry restoreDNF source = %q legacy=%t", source, legacy)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, "vendor baseline")
	assertMissing(t, root, "/etc/dnf/"+dnfStableName)
	assertMissing(t, root, "/etc/dnf/"+dnfAbsentName)
	assertMissing(t, root, "/etc/dnf/"+dnfDependencyProofName)
}

func TestPurgeDNFConcurrentConfigReplacementRetainsRecoveryEvidence(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	marker := writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	proof := string(dnfconfig.DependencyDefaultProof([]byte("managed")))
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, proof)
	const concurrent = "concurrent administrator configuration"
	replaced := false

	_, _, err := restoreDNFWithRemove(root, func(name string) error {
		if name == marker && !replaced {
			replaceFileAtomically(t, hostPath(root, "/etc/dnf/"+dnfAutomaticName), concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "validated file changed") {
		t.Fatalf("restoreDNFWithRemove error = %v, want concurrent-change refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, concurrent)
	assertContent(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, proof)
	if _, _, err := restoreDNF(root); err == nil || !strings.Contains(err.Error(), "unfinished dnf restore transaction") {
		t.Fatalf("retry restoreDNF error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, concurrent)
	assertContent(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, proof)
}

func TestPurgeDNFDoesNotDeleteConcurrentReplacementOfManagedConfig(t *testing.T) {
	root := t.TempDir()
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf5AbsentContents)
	writeFixture(t, root, currentTimestamp, "managed")
	const concurrent = "concurrent administrator configuration"
	destination := hostPath(root, "/etc/dnf/"+dnfAutomaticName)
	replaced := false

	_, _, err := restoreDNFWithRemove(root, func(name string) error {
		if name == destination && !replaced {
			replaceFileAtomically(t, destination, concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "validated file changed") {
		t.Fatalf("restoreDNFWithRemove error = %v, want concurrent-change refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, concurrent)
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf5AbsentContents)
	assertContent(t, root, currentTimestamp, "managed")
	if _, _, err := restoreDNF(root); err == nil || !strings.Contains(err.Error(), "unfinished dnf restore transaction") {
		t.Fatalf("retry restoreDNF error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, concurrent)
	assertContent(t, root, currentTimestamp, "managed")
}

func TestPurgeDNFDoesNotDeleteConfigRecreatedAfterValidatedTargetDisappears(t *testing.T) {
	root := t.TempDir()
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	destination := writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf5AbsentContents)
	writeFixture(t, root, currentTimestamp, "managed")
	removed := false

	_, _, err := restoreDNFWithRemove(root, func(name string) error {
		if name == destination && !removed {
			if err := os.Remove(destination); err != nil {
				t.Fatal(err)
			}
			removed = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "conflict marker retained") {
		t.Fatalf("restoreDNFWithRemove error = %v, want disappeared-target conflict", err)
	}
	if !removed {
		t.Fatal("target disappearance hook was not called")
	}
	assertMissing(t, root, "/etc/dnf/"+dnfAutomaticName)

	writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, "new administrator configuration")
	if _, _, err := restoreDNF(root); err == nil || !strings.Contains(err.Error(), "unfinished dnf restore transaction") {
		t.Fatalf("retry restoreDNF error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, "new administrator configuration")
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf5AbsentContents)
	assertContent(t, root, currentTimestamp, "managed")
}

func TestPurgeDNFDirectoryReplacementCannotRedirectRestore(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	marker := writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte("managed"))))
	for name, content := range map[string]string{
		dnfAutomaticName:       "outside config",
		dnfStableName:          "outside fixed",
		dnfAbsentName:          "outside marker",
		dnfDependencyProofName: "outside proof",
	} {
		if err := os.WriteFile(filepath.Join(external, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	directory := hostPath(root, "/etc/dnf")
	heldDirectory := directory + "-held"
	replaced := false

	_, _, err := restoreDNFWithRemove(root, func(name string) error {
		if name == marker && !replaced {
			if err := os.Rename(directory, heldDirectory); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(external, directory); err != nil {
				t.Fatal(err)
			}
			replaced = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("restoreDNFWithRemove error = %v", err)
	}
	if !replaced {
		t.Fatal("directory replacement hook was not called")
	}
	assertPathContent(t, filepath.Join(heldDirectory, dnfAutomaticName), "vendor baseline")
	assertPathMissing(t, filepath.Join(heldDirectory, dnfStableName))
	assertPathMissing(t, filepath.Join(heldDirectory, dnfAbsentName))
	assertPathMissing(t, filepath.Join(heldDirectory, dnfDependencyProofName))
	assertPathContent(t, filepath.Join(external, dnfAutomaticName), "outside config")
	assertPathContent(t, filepath.Join(external, dnfStableName), "outside fixed")
	assertPathContent(t, filepath.Join(external, dnfAbsentName), "outside marker")
	assertPathContent(t, filepath.Join(external, dnfDependencyProofName), "outside proof")
}

func TestPurgeDNFDoesNotOverwriteConfigReplacedBeforePublish(t *testing.T) {
	root := t.TempDir()
	destination := writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	const concurrent = "concurrent administrator configuration"
	replaced := false

	_, _, err := restoreDNFWithRemove(root, func(name string) error {
		if name == destination && !replaced {
			replaceFileAtomically(t, destination, concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "destination changed before restore") {
		t.Fatalf("restoreDNFWithRemove error = %v, want pre-publish change refusal", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, concurrent)
	assertContent(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
	if _, _, err := restoreDNF(root); err == nil || !strings.Contains(err.Error(), "unfinished dnf restore transaction") {
		t.Fatalf("retry restoreDNF error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, concurrent)
	assertContent(t, root, "/etc/dnf/"+dnfStableName, "vendor baseline")
}

func TestPurgeDNFDoesNotDeleteProofReplacedDuringCleanup(t *testing.T) {
	root := t.TempDir()
	const vendor = "[commands]\nupgrade_type = default\napply_updates = no\n"
	writeFixture(t, root, "/etc/dnf/"+dnfAutomaticName, vendor)
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	proof := writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte(vendor))))
	const concurrent = "concurrent replacement proof"
	replaced := false

	_, _, err := restoreDNFWithRemove(root, func(name string) error {
		if name == proof && !replaced {
			replaceFileAtomically(t, proof, concurrent)
			replaced = true
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "validated file changed") {
		t.Fatalf("restoreDNFWithRemove error = %v, want cleanup change refusal", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, vendor)
	assertMissing(t, root, "/etc/dnf/"+dnfAbsentName)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, concurrent)
	if _, _, err := restoreDNF(root); err == nil || !strings.Contains(err.Error(), "unfinished dnf restore transaction") {
		t.Fatalf("retry restoreDNF error = %v, want unfinished-transaction refusal", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAutomaticName, vendor)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, concurrent)
}

func TestPurgeRejectsDNF5MarkerWithDependencyProof(t *testing.T) {
	root := t.TempDir()
	const currentConfig = "[commands]\nupgrade_type = security\napply_updates = yes\n"
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	writeFixture(t, root, "/etc/dnf/automatic.conf", currentConfig)
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf5AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte(currentConfig))))
	writeFixture(t, root, currentTimestamp, "managed")

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "DNF5 absence marker conflicts") {
		t.Fatalf("error = %v, want cross-generation metadata error", err)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", currentConfig)
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf5AbsentContents)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte(currentConfig))))
	assertContent(t, root, currentTimestamp, "managed")
}

func TestPurgePrefersFixedDNFBaselineOverDependencyProof(t *testing.T) {
	root := t.TempDir()
	const originalConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	const dependencyConfig = "[commands]\nupgrade_type = security\napply_updates = yes\n"
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	writeFixture(t, root, "/etc/dnf/automatic.conf", dependencyConfig)
	writeFixture(t, root, "/etc/dnf/"+dnfStableName, originalConfig)
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte(dependencyConfig))))
	writeFixture(t, root, currentTimestamp, "managed")

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredDNFFrom != "/etc/dnf/"+dnfStableName || report.UsedLegacyDNFBackup {
		t.Fatalf("report = %#v", report)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", originalConfig)
	assertMissing(t, root, "/etc/dnf/"+dnfStableName)
	assertMissing(t, root, "/etc/dnf/"+dnfAbsentName)
	assertMissing(t, root, "/etc/dnf/"+dnfDependencyProofName)
	assertMissing(t, root, currentTimestamp)
}

func TestPurgeRejectsMismatchedDNFDependencyProof(t *testing.T) {
	root := t.TempDir()
	const vendorConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
	writeFixture(t, root, "/etc/dnf/automatic.conf", vendorConfig)
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte("different"))))
	writeFixture(t, root, currentTimestamp, "managed")

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "proof does not match automatic.conf") {
		t.Fatalf("error = %v, want mismatched proof error", err)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", vendorConfig)
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte("different"))))
	assertContent(t, root, currentTimestamp, "managed")
}

func TestPurgeRejectsDNFDependencyProofWithoutCurrentConfig(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte("missing"))))

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "automatic.conf is missing") {
		t.Fatalf("error = %v, want missing config error", err)
	}
	assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
	assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, string(dnfconfig.DependencyDefaultProof([]byte("missing"))))
}

func TestPurgeRejectsUnsafeDNFDependencyProof(t *testing.T) {
	for _, test := range []struct {
		name    string
		wantErr string
		create  func(t *testing.T, proofPath string)
	}{
		{
			name:    "invalid format",
			wantErr: "proof does not match automatic.conf",
			create: func(t *testing.T, proofPath string) {
				t.Helper()
				if err := os.WriteFile(proofPath, []byte("not a SUN proof\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:    "oversized",
			wantErr: "no larger than 256 bytes",
			create: func(t *testing.T, proofPath string) {
				t.Helper()
				if err := os.WriteFile(proofPath, []byte(strings.Repeat("x", 257)), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:    "leaf symlink",
			wantErr: "symlinked",
			create: func(t *testing.T, proofPath string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "proof")
				if err := os.WriteFile(target, dnfconfig.DependencyDefaultProof([]byte("managed")), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, proofPath); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
			writeFixture(t, root, "/etc/dnf/automatic.conf", "managed")
			writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
			writeFixture(t, root, currentTimestamp, "managed timestamp")
			proofPath := filepath.Join(root, "etc/dnf", dnfDependencyProofName)
			test.create(t, proofPath)

			_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
			assertContent(t, root, "/etc/dnf/automatic.conf", "managed")
			assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
			assertContent(t, root, currentTimestamp, "managed timestamp")
			if _, statErr := os.Lstat(proofPath); statErr != nil {
				t.Fatalf("unsafe proof was removed: %v", statErr)
			}
		})
	}
}

func TestPurgeRejectsUnsafeProvenDNFDependencyConfig(t *testing.T) {
	for _, test := range []struct {
		name    string
		wantErr string
		create  func(t *testing.T, configPath string) []byte
	}{
		{
			name:    "leaf symlink",
			wantErr: "symlinked",
			create: func(t *testing.T, configPath string) []byte {
				t.Helper()
				data := []byte("[commands]\napply_updates = no\n")
				target := filepath.Join(t.TempDir(), "automatic.conf")
				if err := os.WriteFile(target, data, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, configPath); err != nil {
					t.Fatal(err)
				}
				return data
			},
		},
		{
			name:    "oversized",
			wantErr: "no larger than 4194304 bytes",
			create: func(t *testing.T, configPath string) []byte {
				t.Helper()
				data := []byte(strings.Repeat("x", (4<<20)+1))
				if err := os.WriteFile(configPath, data, 0o644); err != nil {
					t.Fatal(err)
				}
				return data
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
			currentTimestamp := "/etc/dnf/" + dnfStableName + ".20260726000000"
			writeFixture(t, root, currentTimestamp, "managed timestamp")
			configPath := filepath.Join(root, "etc/dnf", dnfAutomaticName)
			config := test.create(t, configPath)
			proof := string(dnfconfig.DependencyDefaultProof(config))
			writeFixture(t, root, "/etc/dnf/"+dnfDependencyProofName, proof)

			_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
			if _, statErr := os.Lstat(configPath); statErr != nil {
				t.Fatalf("unsafe configuration was removed: %v", statErr)
			}
			assertContent(t, root, "/etc/dnf/"+dnfAbsentName, dnf4AbsentContents)
			assertContent(t, root, "/etc/dnf/"+dnfDependencyProofName, proof)
			assertContent(t, root, currentTimestamp, "managed timestamp")
		})
	}
}

func TestPurgeRejectsInvalidDNFAbsenceMarkerWithoutDeletingConfig(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/dnf/automatic.conf", "managed")
	writeFixture(t, root, "/etc/dnf/"+dnfAbsentName, "not-a-valid-marker\n")

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "invalid contents") {
		t.Fatalf("error = %v, want invalid marker error", err)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", "managed")
}

func TestPurgeSupportsLegacyAPTAbsenceMarker(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, aptconfig.Periodic)
	writeFixture(t, root, aptLegacyAbsent, aptAbsentContents)
	if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
		t.Fatal(err)
	}
	assertMissing(t, root, aptPeriodicLogical)
	assertMissing(t, root, aptLegacyAbsent)
}

func TestPurgeRejectsInvalidAPTAbsenceMarkerWithoutDeletingConfig(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptAbsentLogical, "not-a-valid-marker\n")

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "invalid contents") {
		t.Fatalf("error = %v, want invalid marker error", err)
	}
	assertContent(t, root, aptPeriodicLogical, "managed")
}

func TestUninstallIgnoresOnlyExactMissingUnitDiagnostics(t *testing.T) {
	root := t.TempDir()
	report, err := uninstallAsRoot(Options{
		RootDir: root,
		RunCommand: func(_ string, args ...string) sysexec.Result {
			switch strings.Join(args, " ") {
			case "disable --now " + timerUnit:
				return sysexec.Result{Code: 1, Stderr: "Failed to disable unit: Unit file " + timerUnit + " does not exist.\n"}
			case "stop " + serviceUnit:
				return sysexec.Result{Code: 5, Stderr: "Failed to stop " + serviceUnit + ": Unit " + serviceUnit + " not loaded.\n"}
			default:
				return sysexec.Result{}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.SystemctlFailureCount != 0 {
		t.Fatalf("SystemctlFailureCount = %d, want 0", report.SystemctlFailureCount)
	}

	for _, result := range []sysexec.Result{
		{Code: 5, Stderr: "Failed to disable unit: Unit file " + timerUnit + " does not exist.\n"},
		{Code: 1, Stderr: "Failed to disable unit: Unit file other.timer does not exist.\n"},
		{Code: 1, Stderr: "Failed to disable unit: Unit file " + timerUnit + " does not exist.\npermission denied\n"},
		{Code: -1, Err: errors.New("systemctl unavailable"), Stderr: "Failed to disable unit: Unit file " + timerUnit + " does not exist.\n"},
		{Code: 1, Stderr: "Failed to disable unit: Unit file " + timerUnit + " does not exist.\n", StderrTruncated: true},
	} {
		if !systemctlCleanupFailed(result, "disable", timerUnit) {
			t.Fatalf("real/mismatched failure was suppressed: %+v", result)
		}
	}
	if result := (sysexec.Result{Code: 1, Stderr: "Failed to stop " + serviceUnit + ": Unit " + serviceUnit + " not loaded.\n"}); !systemctlCleanupFailed(result, "stop", serviceUnit) {
		t.Fatalf("stop failure with wrong exit code was suppressed: %+v", result)
	}
}

func TestUninstallCountsTruncatedDaemonReloadAsSystemctlFailure(t *testing.T) {
	for _, result := range []sysexec.Result{
		{Code: 0, Stdout: "partial", StdoutTruncated: true},
		{Code: 0, Stderr: "partial", StderrTruncated: true},
	} {
		root := t.TempDir()
		report, err := uninstallAsRoot(Options{
			RootDir: root,
			RunCommand: func(_ string, args ...string) sysexec.Result {
				if strings.Join(args, " ") == "daemon-reload" {
					return result
				}
				return sysexec.Result{}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.SystemctlFailureCount != 1 {
			t.Fatalf("SystemctlFailureCount = %d, want 1 for %+v", report.SystemctlFailureCount, result)
		}
	}
}

func TestPurgeFallsBackToNewestLegacyDNFBackupWithoutDeletingIt(t *testing.T) {
	root := t.TempDir()
	old := writeFixture(t, root, "/etc/dnf/automatic.conf.bak.1", "old")
	newer := writeFixture(t, root, "/etc/dnf/automatic.conf.bak.2", "newest")
	setMtime(t, old, time.Unix(100, 0))
	setMtime(t, newer, time.Unix(200, 0))

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatalf("Uninstall(purge) error = %v", err)
	}
	if !report.UsedLegacyDNFBackup || report.RestoredDNFFrom != "/etc/dnf/automatic.conf.bak.2" {
		t.Fatalf("legacy report = %#v", report)
	}
	assertContent(t, root, "/etc/dnf/automatic.conf", "newest")
	assertContent(t, root, "/etc/dnf/automatic.conf.bak.1", "old")
	assertContent(t, root, "/etc/dnf/automatic.conf.bak.2", "newest")
}

func TestPurgeRejectsSymlinkBackupAndPreservesIt(t *testing.T) {
	root := t.TempDir()
	target := writeFixture(t, root, "/tmp/not-a-backup", "do not restore")
	backup := hostPath(root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak")
	if err := os.MkdirAll(filepath.Dir(backup), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, backup); err != nil {
		t.Fatal(err)
	}

	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || (!strings.Contains(err.Error(), "not a regular file") && !strings.Contains(err.Error(), "symlinked")) {
		t.Fatalf("error = %v, want symlink/non-regular backup error", err)
	}
	if info, statErr := os.Lstat(backup); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("backup symlink was not preserved: info=%v err=%v", info, statErr)
	}
	assertMissing(t, root, "/etc/apt/apt.conf.d/20auto-upgrades")
}

func TestUninstallRejectsRelativeRoot(t *testing.T) {
	_, err := uninstallAsRoot(Options{RootDir: "relative", RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("error = %v, want absolute-root error", err)
	}
}

func TestUninstallRefusesUnexpectedDirectoryButContinuesCleanup(t *testing.T) {
	root := t.TempDir()
	binary := hostPath(root, "/usr/local/sbin/security-update-notify")
	if err := os.MkdirAll(binary, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "/etc/systemd/system/security-update-notify.service", "unit")

	_, err := uninstallAsRoot(Options{RootDir: root, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "refusing to remove directory") {
		t.Fatalf("error = %v, want directory refusal", err)
	}
	if info, statErr := os.Stat(binary); statErr != nil || !info.IsDir() {
		t.Fatalf("unexpected binary directory was not preserved: info=%v err=%v", info, statErr)
	}
	assertMissing(t, root, "/etc/systemd/system/security-update-notify.service")
}

func TestPurgeSupportsRootContainingGlobMetacharacters(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root[1]*")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	backup := writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak.1", "old managed")
	setMtime(t, backup, time.Unix(100, 0))
	writeFixture(t, root, "/etc/apt/apt.conf.d/20auto-upgrades", "managed")
	writeFixture(t, root, "/var/log/security-update-notify.log.1", "rotated")

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatalf("Uninstall(purge) error = %v", err)
	}
	if report.RestoredAPTFrom != "" {
		t.Fatalf("RestoredAPTFrom = %q, want empty", report.RestoredAPTFrom)
	}
	assertContent(t, root, "/etc/apt/apt.conf.d/20auto-upgrades", "managed")
	assertMissing(t, root, "/var/log/security-update-notify.log.1")
}

func TestUninstallLockOrderAndTemporaryFailures(t *testing.T) {
	t.Run("order", func(t *testing.T) {
		root := t.TempDir()
		var events []string
		_, err := uninstallAsRoot(Options{
			RootDir: root,
			Lock: func(path string, wait time.Duration) (func() error, error) {
				events = append(events, "lock:"+filepath.Base(path))
				return func() error { events = append(events, "unlock:"+filepath.Base(path)); return nil }, nil
			},
			RunCommand: func(_ string, args ...string) sysexec.Result {
				events = append(events, "systemctl:"+strings.Join(args, " "))
				return sysexec.Result{}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		wantPrefix := []string{
			"lock:security-update-notify.install.lock",
			"lock:security-update-notify.lock",
			"systemctl:disable --now security-update-notify.timer",
			"systemctl:stop security-update-notify.service",
		}
		if len(events) < len(wantPrefix) || !reflect.DeepEqual(events[:len(wantPrefix)], wantPrefix) {
			t.Fatalf("events=%v want prefix %v", events, wantPrefix)
		}
		wantSuffix := []string{
			"unlock:security-update-notify.lock",
			"unlock:security-update-notify.install.lock",
		}
		if len(events) < len(wantSuffix) || !reflect.DeepEqual(events[len(events)-len(wantSuffix):], wantSuffix) {
			t.Fatalf("events=%v want suffix %v", events, wantSuffix)
		}
	})

	t.Run("unlock failures are reported", func(t *testing.T) {
		root := t.TempDir()
		_, err := uninstallAsRoot(Options{
			RootDir: root,
			Lock: func(path string, _ time.Duration) (func() error, error) {
				name := filepath.Base(path)
				return func() error { return errors.New("forced " + name + " unlock failure") }, nil
			},
			RunCommand: successfulRunner,
		})
		if err == nil || !strings.Contains(err.Error(), "release runtime lock") ||
			!strings.Contains(err.Error(), "release install lock") {
			t.Fatalf("unlock errors were lost: %v", err)
		}
	})

	for _, busyLock := range []string{"security-update-notify.install.lock", "security-update-notify.lock"} {
		t.Run(busyLock, func(t *testing.T) {
			root := t.TempDir()
			runs := 0
			_, err := uninstallAsRoot(Options{
				RootDir: root,
				Lock: func(path string, _ time.Duration) (func() error, error) {
					if filepath.Base(path) == busyLock {
						return nil, ErrLockBusy
					}
					return func() error { return nil }, nil
				},
				RunCommand: func(string, ...string) sysexec.Result { runs++; return sysexec.Result{} },
			})
			if ExitCode(err) != 75 || runs != 0 {
				t.Fatalf("err=%v code=%d systemctl runs=%d", err, ExitCode(err), runs)
			}
		})
	}
}

func TestUninstallRejectsNonRootBeforeLocksOrCommands(t *testing.T) {
	locks, runs := 0, 0
	_, err := Uninstall(Options{
		RootDir: t.TempDir(), EffectiveUID: func() int { return 1000 },
		Lock:       func(string, time.Duration) (func() error, error) { locks++; return func() error { return nil }, nil },
		RunCommand: func(string, ...string) sysexec.Result { runs++; return sysexec.Result{} },
	})
	if ExitCode(err) != 1 || locks != 0 || runs != 0 {
		t.Fatalf("err=%v code=%d locks=%d runs=%d", err, ExitCode(err), locks, runs)
	}
}

func TestUninstallPrivateRootDefaultsToNoHostSystemctl(t *testing.T) {
	root := t.TempDir()
	if _, err := uninstallAsRoot(Options{RootDir: root}); err != nil {
		t.Fatal(err)
	}
}

func TestUninstallRejectsSymlinkedParentWithoutEscapingRoot(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	externalFile := filepath.Join(external, "security-update-notify")
	if err := os.WriteFile(externalFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "symlinked path component") {
		t.Fatalf("error=%v, want symlink rejection", err)
	}
	got, readErr := os.ReadFile(externalFile)
	if readErr != nil || string(got) != "outside" {
		t.Fatalf("external file changed: %q err=%v", got, readErr)
	}
}

func TestRecursiveRemovalStaysBoundToOpenedParent(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	writeFixture(t, root, "/etc/security-update-notify/secret", "inside")
	externalFile := filepath.Join(external, "secret")
	if err := os.WriteFile(externalFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	parent, name, err := openLogicalParent(root, "/etc/security-update-notify")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	oldEtc := filepath.Join(root, "etc-old")
	if err := os.Rename(filepath.Join(root, "etc"), oldEtc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	if err := removeAllAt(parent, name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(oldEtc, "security-update-notify")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original tree was not removed: %v", err)
	}
	if got, err := os.ReadFile(externalFile); err != nil || string(got) != "outside" {
		t.Fatalf("replacement symlink target changed: %q err=%v", got, err)
	}
}

func TestRemovalFailureReportsFullRetainedQuarantinePath(t *testing.T) {
	root := t.TempDir()
	logical := "/var/lib/security-update-notify/state"
	target := writeFixture(t, root, logical, "managed")
	parent, name, err := openLogicalParent(root, logical)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	expected, err := readRemovalEntry(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	forced := errors.New("forced claimed-entry deletion failure")
	quarantine := ""
	err = removeValidatedEntryAtWithHook(parent, name, expected, removalLeaf, func(name string) error {
		quarantine = name
		return forced
	})
	retained := filepath.Join(filepath.Dir(target), quarantine)
	if err == nil || !errors.Is(err, forced) || quarantine == "" || !strings.Contains(err.Error(), "retained at "+retained) {
		t.Fatalf("removal error = %v, want retained path %s", err, retained)
	}
	assertPathMissing(t, target)
	assertPathContent(t, retained, "managed")
}

func TestRemovalPlaceholderInitializationFailureReportsRetainedPath(t *testing.T) {
	root := t.TempDir()
	logical := "/var/lib/security-update-notify/state"
	target := writeFixture(t, root, logical, "managed")
	parent, _, err := openLogicalParent(root, logical)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	forced := errors.New("forced quarantine close failure")
	retained := ""
	name, _, err := newRemovalPlaceholderWithClose(parent, false, uninstallRemovalPendingPrefix, func(file *os.File, name string) error {
		if err := file.Close(); err != nil {
			return err
		}
		retained = removalEntryPath(parent, name)
		if err := os.Rename(retained, retained+".held"); err != nil {
			return err
		}
		if err := os.WriteFile(retained, []byte("concurrent replacement"), 0o600); err != nil {
			return err
		}
		return forced
	})
	if err == nil || !errors.Is(err, forced) || name == "" || retained == "" ||
		!strings.Contains(err.Error(), "retained at "+retained) {
		t.Fatalf("placeholder initialization error = %v, want retained path %s", err, retained)
	}
	assertPathContent(t, retained, "concurrent replacement")
	assertPathContent(t, retained+".held", "")
	assertPathContent(t, target, "managed")
}

func TestRemoveLogicalFileDoesNotDeleteConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	logical := "/etc/logrotate.d/security-update-notify"
	target := writeFixture(t, root, logical, "managed")
	held := target + ".held"
	replaced := false

	err := removeLogicalFileWithHook(root, logical, func() error {
		if err := os.Rename(target, held); err != nil {
			return err
		}
		if err := os.WriteFile(target, []byte("administrator replacement"), 0o640); err != nil {
			return err
		}
		replaced = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "entry changed before removal") {
		t.Fatalf("removeLogicalFileWithHook error = %v, want replacement refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	assertPathContent(t, held, "managed")
	assertPathContent(t, target, "administrator replacement")
}

func TestRemoveLogicalTreeDoesNotDeleteConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	logical := "/etc/security-update-notify"
	target := filepath.Dir(writeFixture(t, root, logical+"/managed", "managed"))
	held := target + ".held"
	replaced := false

	err := removeLogicalTreeWithHook(root, logical, func() error {
		if err := os.Rename(target, held); err != nil {
			return err
		}
		if err := os.Mkdir(target, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(target, "administrator.conf"), []byte("keep"), 0o640); err != nil {
			return err
		}
		replaced = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "entry changed before removal") {
		t.Fatalf("removeLogicalTreeWithHook error = %v, want replacement refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	assertPathContent(t, filepath.Join(held, "managed"), "managed")
	assertPathContent(t, filepath.Join(target, "administrator.conf"), "keep")
}

func TestLogicalRemovalRetainsUnverifiedQuarantinesAndRecoversOwned(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "etc")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := "." + uninstallRemovalPrefix + "." + strings.Repeat("a", 32)
	pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("b", 32)
	nearMatch := "." + uninstallRemovalOwnedPrefix + ".not-a-valid-artifact"
	oldOwned := "." + uninstallRemovalOwnedPrefix + "." + strings.Repeat("d", 32) + ".0.1.2.81a0.0.0.5.6.7"
	for _, name := range []string{legacy, pending, nearMatch, oldOwned} {
		if err := os.WriteFile(filepath.Join(parent, name), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ownedSource := filepath.Join(parent, "owned-source")
	if err := os.WriteFile(ownedSource, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownedInfo, err := os.Lstat(ownedSource)
	if err != nil {
		t.Fatal(err)
	}
	pendingOwned := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("c", 32)
	owned, err := ownedRemovalName(pendingOwned, ownedInfo, removalLeaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ownedSource, filepath.Join(parent, owned)); err != nil {
		t.Fatal(err)
	}

	logical := "/etc/missing"
	err = removeLogicalTree(root, logical)
	if err == nil || !strings.Contains(err.Error(), "legacy uninstall quarantine") ||
		!strings.Contains(err.Error(), "unverified uninstall quarantine") ||
		!strings.Contains(err.Error(), "unsupported durable identity") {
		t.Fatalf("removeLogicalTree error = %v, want legacy, pending, and old owned retention", err)
	}
	for _, name := range []string{legacy, pending, nearMatch, oldOwned} {
		assertPathContent(t, filepath.Join(parent, name), "keep")
	}
	if _, err := os.Lstat(filepath.Join(parent, owned)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified owned quarantine survived recovery: %v", err)
	}
}

func TestInterruptedOwnedTreeRecoveryAllowsDirectoryMetadataChanges(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "etc")
	tree := filepath.Join(parentPath, "owned-tree")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"removed-before-crash", "remaining"} {
		if err := os.WriteFile(filepath.Join(tree, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(tree)
	if err != nil {
		t.Fatal(err)
	}
	pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("d", 32)
	owned, err := ownedRemovalName(pending, info, removalTree)
	if err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(parentPath, owned)
	if err := os.Rename(tree, ownedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(ownedPath, "removed-before-crash")); err != nil {
		t.Fatal(err)
	}
	parent, _, err := openLogicalParent(root, "/etc/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := cleanupUninstallRemovalArtifacts(parent, trustedParentRemovalRecovery); err != nil {
		t.Fatal(err)
	}
	assertPathMissing(t, ownedPath)
}

func TestTrustedParentRecoveryRejectsGroupWritableForgedOwnedEntries(t *testing.T) {
	for _, test := range []struct {
		name  string
		mode  removalMode
		setup func(*testing.T, string) string
	}{
		{
			name: "leaf",
			mode: removalLeaf,
			setup: func(t *testing.T, path string) string {
				if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "tree",
			mode: removalTree,
			setup: func(t *testing.T, path string) string {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				retained := filepath.Join(path, "protected")
				if err := os.WriteFile(retained, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				return retained
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			parentPath := filepath.Join(root, "etc", "logrotate.d")
			if err := os.MkdirAll(parentPath, 0o755); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(parentPath, "administrator-entry")
			retainedSuffix := strings.TrimPrefix(test.setup(t, source), source)
			info, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("2", 32)
			owned, err := ownedRemovalName(pending, info, test.mode)
			if err != nil {
				t.Fatal(err)
			}
			ownedPath := filepath.Join(parentPath, owned)
			if err := os.Rename(source, ownedPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parentPath, 0o770); err != nil {
				t.Fatal(err)
			}

			err = removeLogicalTree(root, "/etc/logrotate.d/missing")
			if err == nil || !strings.Contains(err.Error(), "unsafe trusted uninstall recovery parent") || !strings.Contains(err.Error(), "forbidden permissions") {
				t.Fatalf("trusted recovery error = %v, want unsafe-parent refusal", err)
			}
			assertPathContent(t, ownedPath+retainedSuffix, "keep")
		})
	}
}

func TestTrustedParentRecoveryValidatesResolvedLocalSbinDirectory(t *testing.T) {
	root := t.TempDir()
	physicalParent := filepath.Join(root, "usr", "local", "bin")
	if err := os.MkdirAll(physicalParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("bin", filepath.Join(root, "usr", "local", "sbin")); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(physicalParent, "administrator-command")
	if err := os.WriteFile(source, []byte("keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("3", 32)
	owned, err := ownedRemovalName(pending, info, removalLeaf)
	if err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(physicalParent, owned)
	if err := os.Rename(source, ownedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(physicalParent, 0o770); err != nil {
		t.Fatal(err)
	}

	err = removeLogicalFile(root, "/usr/local/sbin/missing")
	if err == nil || !strings.Contains(err.Error(), physicalParent) || !strings.Contains(err.Error(), "forbidden permissions") {
		t.Fatalf("resolved alias recovery error = %v, want physical bin refusal", err)
	}
	assertPathContent(t, ownedPath, "keep")
}

func TestTrustedParentRecoveryRemovesOwnedEntriesFromValidatedDirectory(t *testing.T) {
	for _, mode := range []removalMode{removalLeaf, removalTree} {
		t.Run(fmt.Sprintf("mode-%d", mode), func(t *testing.T) {
			root := t.TempDir()
			parentPath := filepath.Join(root, "etc")
			if err := os.MkdirAll(parentPath, 0o755); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(parentPath, "interrupted")
			if mode == removalTree {
				if err := os.Mkdir(source, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, "remaining"), []byte("data"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("4", 32)
			owned, err := ownedRemovalName(pending, info, mode)
			if err != nil {
				t.Fatal(err)
			}
			ownedPath := filepath.Join(parentPath, owned)
			if err := os.Rename(source, ownedPath); err != nil {
				t.Fatal(err)
			}

			if err := removeLogicalTree(root, "/etc/missing"); err != nil {
				t.Fatal(err)
			}
			assertPathMissing(t, ownedPath)
		})
	}
}

func TestVarLogRecoveryRetainsForgedOwnedTree(t *testing.T) {
	operations := []struct {
		name string
		run  func(string) error
	}{
		{
			name: "prefixed log removal",
			run: func(root string) error {
				return removeLogicalFilesWithPrefix(root, "/var/log", "security-update-notify.log.", nil)
			},
		},
		{
			name: "purge",
			run: func(root string) error {
				_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
				return err
			},
		},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			root := t.TempDir()
			parentPath := filepath.Join(root, "var", "log")
			tree := filepath.Join(parentPath, "administrator-tree")
			if err := os.MkdirAll(tree, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parentPath, 0o770); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tree, "protected"), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(tree)
			if err != nil {
				t.Fatal(err)
			}
			pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("f", 32)
			owned, err := ownedRemovalName(pending, info, removalTree)
			if err != nil {
				t.Fatal(err)
			}
			ownedPath := filepath.Join(parentPath, owned)
			if err := os.Rename(tree, ownedPath); err != nil {
				t.Fatal(err)
			}

			err = operation.run(root)
			if err == nil || !strings.Contains(err.Error(), "forbidden by shared-parent recovery policy") {
				t.Fatalf("operation error = %v, want shared-parent recovery refusal", err)
			}
			assertPathContent(t, filepath.Join(ownedPath, "protected"), "keep")
		})
	}
}

func TestSharedParentRecoveryRetainsOwnedEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "var", "log")
	directory := filepath.Join(parentPath, "administrator-empty-directory")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("0", 32)
	owned, err := ownedRemovalName(pending, info, removalEmptyDirectory)
	if err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(parentPath, owned)
	if err := os.Rename(directory, ownedPath); err != nil {
		t.Fatal(err)
	}

	err = removeLogicalFilesWithPrefix(root, "/var/log", "security-update-notify.log.", nil)
	if err == nil || !strings.Contains(err.Error(), "forbidden by shared-parent recovery policy") {
		t.Fatalf("prefixed removal error = %v, want shared-parent recovery refusal", err)
	}
	if info, err := os.Stat(ownedPath); err != nil || !info.IsDir() {
		t.Fatalf("owned empty directory was not retained: info=%v err=%v", info, err)
	}
}

func TestVarLogRecoveryRetainsForgedOwnedLeaf(t *testing.T) {
	operations := []struct {
		name string
		run  func(string) error
	}{
		{
			name: "prefixed log removal",
			run: func(root string) error {
				return removeLogicalFilesWithPrefix(root, "/var/log", "security-update-notify.log.", nil)
			},
		},
		{
			name: "purge",
			run: func(root string) error {
				_, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
				return err
			},
		},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			root := t.TempDir()
			parentPath := filepath.Join(root, "var", "log")
			source := writeFixture(t, root, "/var/log/root-owned-unrelated.log", "keep")
			if err := os.Chmod(parentPath, 0o770); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("1", 32)
			owned, err := ownedRemovalName(pending, info, removalLeaf)
			if err != nil {
				t.Fatal(err)
			}
			ownedPath := filepath.Join(parentPath, owned)
			if err := os.Rename(source, ownedPath); err != nil {
				t.Fatal(err)
			}

			err = operation.run(root)
			if err == nil || !strings.Contains(err.Error(), "forbidden by shared-parent recovery policy") {
				t.Fatalf("operation error = %v, want shared-parent recovery refusal", err)
			}
			assertPathContent(t, ownedPath, "keep")
		})
	}
}

func TestSharedParentRemovalDeletesRotatedLogWithoutQuarantine(t *testing.T) {
	root := t.TempDir()
	rotated := writeFixture(t, root, "/var/log/security-update-notify.log.1", "rotated")
	if err := removeLogicalFilesWithPrefix(root, "/var/log", "security-update-notify.log.", nil); err != nil {
		t.Fatal(err)
	}
	assertPathMissing(t, rotated)
}

func TestRemovalRecoveryDocumentationMatchesTrustBoundary(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	for _, document := range []struct {
		path     string
		required []string
	}{
		{
			path: "docs/operations.md",
			required: []string{
				"仍由 root 所有且禁止 group/other write 时，才视为可信私有父目录",
				"`/var/log` 是共享父目录",
				"任何遗留隔离项也会保留并失败关闭",
				"本次 purge 仍会正常删除 SUN 日志和轮转日志",
			},
		},
		{
			path: "docs/operations.en.md",
			required: []string{
				"trusted as private only while it remains root-owned and forbids group/other write",
				"`/var/log` is a shared parent",
				"every retained quarantine there fails closed and remains in place",
				"the current purge still removes SUN's log and rotated logs normally",
			},
		},
		{
			path: "CHANGELOG.md",
			required: []string{
				"`/var/log` 共享父",
				"目录中的任何遗留隔离项都保留并失败关闭",
				"Every retained quarantine in the shared",
				"`/var/log` parent remains in place and fails closed",
			},
		},
	} {
		content, err := os.ReadFile(filepath.Join(root, document.path))
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range document.required {
			if !bytes.Contains(content, []byte(required)) {
				t.Errorf("%s is missing removal-recovery boundary %q", document.path, required)
			}
		}
	}
}

func TestInterruptedOwnedTreeRecoveryRetainsIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "etc")
	tree := filepath.Join(parentPath, "owned-tree")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(tree)
	if err != nil {
		t.Fatal(err)
	}
	pending := "." + uninstallRemovalPendingPrefix + "." + strings.Repeat("e", 32)
	owned, err := ownedRemovalName(pending, info, removalTree)
	if err != nil {
		t.Fatal(err)
	}
	ownedPath := filepath.Join(parentPath, owned)
	if err := os.Remove(tree); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ownedPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ownedPath, "administrator-data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, _, err := openLogicalParent(root, "/etc/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	err = cleanupUninstallRemovalArtifacts(parent, trustedParentRemovalRecovery)
	if err == nil || !strings.Contains(err.Error(), "does not match its durable identity") {
		t.Fatalf("cleanup error = %v, want identity mismatch", err)
	}
	assertPathContent(t, filepath.Join(ownedPath, "administrator-data"), "keep")
}

func TestOwnedPromotionIdentityPreventsPostValidationReplacementCleanup(t *testing.T) {
	root := t.TempDir()
	logical := "/etc/logrotate.d/security-update-notify"
	target := writeFixture(t, root, logical, "managed")
	parent, name, err := openLogicalParent(root, logical)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	expected, err := readRemovalEntry(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	var replacementPath string
	crash := errors.New("simulated crash after owned promotion")
	err = removeValidatedEntryAtWithHooks(parent, name, expected, removalLeaf, removalHooks{
		afterPendingValidation: func(pending string) error {
			pendingPath := removalEntryPath(parent, pending)
			if err := os.Rename(pendingPath, pendingPath+".held"); err != nil {
				return err
			}
			return os.WriteFile(pendingPath, []byte("administrator replacement"), 0o640)
		},
		afterOwnedPromotion: func(owned string) error {
			replacementPath = removalEntryPath(parent, owned)
			return crash
		},
	})
	if !errors.Is(err, crash) || replacementPath == "" {
		t.Fatalf("removal error = %v replacement=%q, want simulated post-promotion crash", err, replacementPath)
	}
	assertPathContent(t, replacementPath, "administrator replacement")
	err = cleanupUninstallRemovalArtifacts(parent, trustedParentRemovalRecovery)
	if err == nil || !strings.Contains(err.Error(), "does not match its durable identity") {
		t.Fatalf("cleanup error = %v, want durable identity mismatch", err)
	}
	assertPathContent(t, replacementPath, "administrator replacement")
	assertPathMissing(t, target)
}

func TestOwnedPromotionIsSyncedBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	logical := "/etc/logrotate.d/security-update-notify"
	target := writeFixture(t, root, logical, "managed")
	parent, name, err := openLogicalParent(root, logical)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	expected, err := readRemovalEntry(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	synced := false
	err = removeValidatedEntryAtWithHooks(parent, name, expected, removalLeaf, removalHooks{
		syncOwned: func(parent *os.File) error {
			synced = true
			return syncLogicalRemovalParent(parent)
		},
		beforeDelete: func(owned string) error {
			if !synced {
				return errors.New("delete ran before owned promotion sync")
			}
			if _, err := os.Lstat(removalEntryPath(parent, owned)); err != nil {
				return err
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !synced {
		t.Fatal("owned promotion was not synced")
	}
	assertPathMissing(t, target)
}

func TestRemoveClaimedTreeUsesHeldDirectoryDescriptor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Dir(writeFixture(t, root, "/etc/security-update-notify/managed", "managed"))
	parent, name, err := openLogicalParent(root, "/etc/security-update-notify")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	directory, err := openRemovalDirectory(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	held := target + ".held"
	if err := os.Rename(target, held); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(target, "administrator.conf")
	if err := os.WriteFile(replacement, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := removeClaimedTree(directory); err != nil {
		t.Fatal(err)
	}
	assertPathMissing(t, filepath.Join(held, "managed"))
	assertPathContent(t, replacement, "keep")
}

func TestRemoveLogicalEmptyDirectoryDoesNotDeleteConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	logical := "/etc/systemd/system/security-update-notify.service.d"
	target := hostPath(root, logical)
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	held := target + ".held"
	replaced := false

	err := removeLogicalEmptyDirectoryWithHook(root, logical, func() error {
		if err := os.Rename(target, held); err != nil {
			return err
		}
		if err := os.Mkdir(target, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(target, "administrator.conf"), []byte("keep"), 0o640); err != nil {
			return err
		}
		replaced = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "entry changed before removal") {
		t.Fatalf("removeLogicalEmptyDirectoryWithHook error = %v, want replacement refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	if info, err := os.Stat(held); err != nil || !info.IsDir() {
		t.Fatalf("validated empty directory was not preserved: info=%v err=%v", info, err)
	}
	assertPathContent(t, filepath.Join(target, "administrator.conf"), "keep")
}

func TestRotatedLogRemovalDoesNotDeleteConcurrentReplacement(t *testing.T) {
	root := t.TempDir()
	logical := "/var/log/security-update-notify.log.1"
	target := writeFixture(t, root, logical, "managed log")
	held := target + ".held"
	replaced := false

	err := removeLogicalFilesWithPrefix(root, "/var/log", "security-update-notify.log.", func(name string) error {
		if name != filepath.Base(target) || replaced {
			return nil
		}
		if err := os.Rename(target, held); err != nil {
			return err
		}
		if err := os.WriteFile(target, []byte("new log"), 0o640); err != nil {
			return err
		}
		replaced = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "entry changed before removal") {
		t.Fatalf("removeLogicalFilesWithPrefix error = %v, want replacement refusal", err)
	}
	if !replaced {
		t.Fatal("concurrent replacement hook was not called")
	}
	assertPathContent(t, held, "managed log")
	assertPathContent(t, target, "new log")
}

func TestPurgeUnlinksLeafSymlinkWithoutFollowingIt(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	externalFile := filepath.Join(external, "keep")
	if err := os.WriteFile(externalFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "etc", "security-update-notify")
	if err := os.Symlink(external, linked); err != nil {
		t.Fatal(err)
	}

	if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(linked); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leaf symlink was not removed: %v", err)
	}
	if got, err := os.ReadFile(externalFile); err != nil || string(got) != "outside" {
		t.Fatalf("leaf symlink target changed: %q err=%v", got, err)
	}
}

func TestUninstallSupportsFedoraStandardLocalSbinAlias(t *testing.T) {
	for _, test := range []struct {
		name        string
		aliasTarget string
		removed     bool
	}{
		{name: "exact command alias", aliasTarget: aliasTarget, removed: true},
		{name: "conflicting command alias", aliasTarget: "operator-command"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "usr/local/sbin")
			if err := os.Symlink("bin", link); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(root, "usr/local/bin/security-update-notify")
			if err := os.WriteFile(binary, []byte("runtime"), 0o755); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, "usr/local/bin/sun")
			if err := os.Symlink(test.aliasTarget, alias); err != nil {
				t.Fatal(err)
			}

			if _, err := uninstallAsRoot(Options{RootDir: root, RunCommand: successfulRunner}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(binary); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("runtime remained behind standard alias: %v", err)
			}
			if target, err := os.Readlink(link); err != nil || target != "bin" {
				t.Fatalf("standard alias changed: target=%q err=%v", target, err)
			}
			target, err := os.Readlink(alias)
			if test.removed && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("exact command alias remained behind standard alias: target=%q err=%v", target, err)
			}
			if !test.removed && (err != nil || target != test.aliasTarget) {
				t.Fatalf("conflicting command alias changed: target=%q err=%v", target, err)
			}
		})
	}
}

func TestUninstallRejectsNonstandardLocalSbinAlias(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "usr/local/sbin")); err != nil {
		t.Fatal(err)
	}
	externalBinary := filepath.Join(external, "security-update-notify")
	if err := os.WriteFile(externalBinary, []byte("outside"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := uninstallAsRoot(Options{RootDir: root, RunCommand: successfulRunner})
	if err == nil || !strings.Contains(err.Error(), "symlinked path component") {
		t.Fatalf("nonstandard alias error=%v", err)
	}
	if got, readErr := os.ReadFile(externalBinary); readErr != nil || string(got) != "outside" {
		t.Fatalf("external binary changed: data=%q err=%v", got, readErr)
	}
}

func successfulRunner(string, ...string) sysexec.Result {
	return sysexec.Result{Code: 0}
}

func uninstallAsRoot(options Options) (Report, error) {
	options.EffectiveUID = func() int { return 0 }
	return Uninstall(options)
}

func writeFixture(t *testing.T, root, logical, content string) string {
	t.Helper()
	path := hostPath(root, logical)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func replaceFileAtomically(t *testing.T, path, content string) {
	t.Helper()
	temporary := path + ".concurrent"
	if err := os.WriteFile(temporary, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s still exists or stat failed: %v", path, err)
	}
}

func assertPathContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s content = %q, want %q", path, got, want)
	}
}

func setMtime(t *testing.T, path string, when time.Time) {
	t.Helper()
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func hostPath(root, logical string) string {
	return filepath.Join(root, strings.TrimPrefix(logical, "/"))
}

func assertMissing(t *testing.T, root, logical string) {
	t.Helper()
	if _, err := os.Lstat(hostPath(root, logical)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s still exists or stat failed: %v", logical, err)
	}
}

func assertContent(t *testing.T, root, logical, want string) {
	t.Helper()
	got, err := os.ReadFile(hostPath(root, logical))
	if err != nil {
		t.Fatalf("read %s: %v", logical, err)
	}
	if string(got) != want {
		t.Fatalf("%s content = %q, want %q", logical, got, want)
	}
}
