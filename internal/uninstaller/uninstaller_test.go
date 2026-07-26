package uninstaller

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
		"/etc/security-update-notify/telegram.env",
		"/var/lib/security-update-notify/last-alert.hash",
		"/var/backups/security-update-notify/backup/telegram.env",
		"/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred",
		"/var/log/security-update-notify.log",
		"/etc/systemd/system/security-update-notify.service.d/keep.conf",
	} {
		writeFixture(t, root, path, "data")
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
	} {
		assertContent(t, root, path, "data")
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
		"/etc/apt/apt.conf.d/52unattended-upgrades-local",
		"/etc/needrestart/conf.d/99-security-update-notify-report-only.conf",
	} {
		writeFixture(t, root, path, "secret")
	}

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
		"/etc/apt/apt.conf.d/52unattended-upgrades-local",
		"/etc/needrestart/conf.d/99-security-update-notify-report-only.conf",
	} {
		assertMissing(t, root, path)
	}
	assertContent(t, root, "/var/log/security-update-notify.logger", "secret")
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
	currentTimestamp := aptPeriodicLogical + ".security-update-notify.20260726000000.bak"
	writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	writeFixture(t, root, currentTimestamp, "managed")

	report, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner})
	if err != nil {
		t.Fatal(err)
	}
	if report.RestoredAPTFrom != "" {
		t.Fatalf("RestoredAPTFrom = %q, want empty for absent baseline", report.RestoredAPTFrom)
	}
	assertMissing(t, root, aptPeriodicLogical)
	assertMissing(t, root, aptAbsentLogical)
	assertMissing(t, root, currentTimestamp)
}

func TestPurgeSupportsLegacyAPTAbsenceMarker(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
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
	} {
		if !systemctlCleanupFailed(result, "disable", timerUnit) {
			t.Fatalf("real/mismatched failure was suppressed: %+v", result)
		}
	}
	if result := (sysexec.Result{Code: 1, Stderr: "Failed to stop " + serviceUnit + ": Unit " + serviceUnit + " not loaded.\n"}); !systemctlCleanupFailed(result, "stop", serviceUnit) {
		t.Fatalf("stop failure with wrong exit code was suppressed: %+v", result)
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
	if err == nil || (!strings.Contains(err.Error(), "not a regular file") && !strings.Contains(err.Error(), "symlinked path")) {
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
