package uninstaller

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
	"github.com/xxvcc/security-update-notify/internal/dependencyproof"
	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
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

func TestPurgeRestorePreservesFileMetadataAndXattrs(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	fixed := writeFixture(t, root, aptStableLogical, "vendor baseline")
	if err := os.Chmod(fixed, 0o641); err != nil {
		t.Fatal(err)
	}
	wantMtime := time.Unix(1_700_000_000, 123_000_000)
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

func TestUninstallSupportsFedoraStandardLocalSbinAlias(t *testing.T) {
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

	if _, err := uninstallAsRoot(Options{RootDir: root, RunCommand: successfulRunner}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(binary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime remained behind standard alias: %v", err)
	}
	if target, err := os.Readlink(link); err != nil || target != "bin" {
		t.Fatalf("standard alias changed: target=%q err=%v", target, err)
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
