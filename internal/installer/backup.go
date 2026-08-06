package installer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

var managedPaths = []string{
	BinaryPath,
	ConfigPath,
	ServicePath,
	FeishuCredentialDropIn,
	TimerPath,
	PersistentTimerLink,
	RuntimeTimerLink,
	LogrotatePath,
	aptPeriodicPath,
	aptStableBackupPath,
	aptAbsentMarkerPath,
	aptLegacyAbsentPath,
	aptDependencyProofPath,
	"/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify",
	"/etc/needrestart/conf.d/99-security-update-notify-report-only.conf",
	"/etc/dnf/automatic.conf",
	"/etc/dnf/automatic.conf.security-update-notify.bak",
	"/etc/dnf/automatic.conf.security-update-notify.absent.bak",
	"/etc/dnf/automatic.conf.security-update-notify.dependency-default.bak",
}

type nodeSnapshot struct {
	exists          bool
	backupPath      string
	preserveCurrent bool
}

type backup struct {
	dir                       string
	manifest                  []string
	paths                     []string
	snapshots                 map[string]nodeSnapshot
	skipDependencyCapturePath map[string]bool
	transaction               *installTransaction
}

type privateSnapshot struct {
	exists bool
	mode   fs.FileMode
	data   []byte
}

func (i *Installer) createBackup() (_ *backup, returnErr error) {
	if err := i.ensureManagedDir(BackupRoot, 0o700); err != nil {
		return nil, failure("create backup root", err)
	}
	if err := i.syncDirectoryChain(BackupRoot); err != nil {
		return nil, failure("sync backup directory chain", err)
	}
	stamp := i.now().Format("20060102150405")
	var dir string
	for suffix := 0; suffix < 1000; suffix++ {
		name := stamp
		if suffix > 0 {
			name = fmt.Sprintf("%s-%03d", stamp, suffix)
		}
		candidate := path.Join(BackupRoot, name)
		err := i.fs.Mkdir(candidate, 0o700)
		if err == nil {
			dir = candidate
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, failure("create backup directory", err)
		}
	}
	if dir == "" {
		return nil, failure("create backup directory", errors.New("too many timestamp collisions"))
	}
	complete := false
	defer func() {
		if !complete {
			if err := i.fs.RemoveAll(dir); err != nil {
				returnErr = errors.Join(returnErr, failure("remove incomplete backup "+dir, err))
			}
		}
	}()
	b := &backup{
		dir:                       dir,
		paths:                     append([]string(nil), managedPaths...),
		snapshots:                 make(map[string]nodeSnapshot, len(managedPaths)),
		skipDependencyCapturePath: make(map[string]bool),
	}
	for _, source := range b.paths {
		exists, err := i.exists(source)
		if err != nil {
			return nil, failure("inspect managed path", err)
		}
		snapshot := nodeSnapshot{exists: exists}
		if exists {
			snapshot.backupPath = path.Join(dir, strings.TrimPrefix(source, "/"))
			if err := i.copyNode(source, snapshot.backupPath); err != nil {
				return nil, failure("backup "+source, err)
			}
			b.manifest = append(b.manifest, strings.TrimPrefix(source, "/"))
		}
		b.snapshots[source] = snapshot
	}
	if err := i.writeManifest(b); err != nil {
		return nil, err
	}
	if err := i.pruneBackups(dir); err != nil {
		return nil, err
	}
	if err := i.fs.WriteFileAtomic(path.Join(BackupRoot, "latest"), []byte(dir+"\n"), 0o600); err != nil {
		return nil, failure("write latest backup pointer", err)
	}
	complete = true
	return b, nil
}

func (i *Installer) snapshotAdditionalPath(b *backup, source string) error {
	if _, tracked := b.snapshots[source]; tracked {
		return nil
	}
	exists, err := i.exists(source)
	if err != nil {
		return failure("inspect additional transaction path", err)
	}
	snapshot := nodeSnapshot{exists: exists}
	if exists {
		snapshot.backupPath = path.Join(b.dir, strings.TrimPrefix(source, "/"))
		if err := i.copyNode(source, snapshot.backupPath); err != nil {
			return failure("backup "+source, err)
		}
		b.manifest = append(b.manifest, strings.TrimPrefix(source, "/"))
	}
	b.paths = append(b.paths, source)
	b.snapshots[source] = snapshot
	return i.writeManifest(b)
}

func (i *Installer) captureDependencyDefaults(b *backup) error {
	changed := false
	for _, source := range managedPaths {
		if b.skipDependencyCapturePath[source] {
			continue
		}
		snapshot := b.snapshots[source]
		if snapshot.exists {
			continue
		}
		exists, err := i.exists(source)
		if err != nil {
			return failure("inspect dependency-created default", err)
		}
		if !exists {
			continue
		}
		backupPath := path.Join(b.dir, strings.TrimPrefix(source, "/"))
		// The package transaction is retained. If capturing a package-owned default
		// fails, rollback must not delete the only configuration that package wrote.
		// SUN metadata such as markers and proofs must still roll back normally.
		if source == aptPeriodicPath || source == dnfAutomaticPath {
			snapshot.preserveCurrent = true
			b.snapshots[source] = snapshot
			// Persist the non-destructive fallback before copying. A crash or
			// copy failure must never leave recovery believing that this
			// package-owned default is an installer-created path to delete.
			if b.transaction != nil {
				if err := b.transaction.syncBackup(b); err != nil {
					return err
				}
			}
		}
		if err := i.copyNode(source, backupPath); err != nil {
			return failure("capture dependency-created default", err)
		}
		snapshot.exists = true
		snapshot.backupPath = backupPath
		snapshot.preserveCurrent = false
		b.snapshots[source] = snapshot
		b.manifest = append(b.manifest, strings.TrimPrefix(source, "/"))
		changed = true
	}
	if changed {
		return i.writeManifest(b)
	}
	return nil
}

// keepPathAbsentOnRollback adopts a durable post-dependency absence as the new
// transaction baseline. This is used only for metadata whose replacement
// baseline has already been captured and whose owning package is not rolled
// back with the SUN transaction.
func (i *Installer) keepPathAbsentOnRollback(b *backup, source string) error {
	snapshot, tracked := b.snapshots[source]
	if !tracked {
		return failure("update transaction baseline", fmt.Errorf("path is not tracked: %s", source))
	}
	b.snapshots[source] = nodeSnapshot{}
	logical := strings.TrimPrefix(source, "/")
	manifest := b.manifest[:0]
	for _, entry := range b.manifest {
		if entry != logical {
			manifest = append(manifest, entry)
		}
	}
	b.manifest = manifest
	// Publish the new logical baseline before deleting its superseded bytes. If
	// the process stops between these operations, recovery ignores the harmless
	// extra backup instead of trying to restore a file that was already adopted
	// as absent.
	if err := i.writeManifest(b); err != nil {
		return err
	}
	if snapshot.backupPath != "" {
		if err := i.fs.Remove(snapshot.backupPath); err != nil {
			return failure("remove superseded transaction snapshot", err)
		}
	}
	return nil
}

func (i *Installer) writeManifest(b *backup) error {
	data := []byte(strings.Join(b.manifest, "\n"))
	if len(data) > 0 {
		data = append(data, '\n')
	}
	if err := i.fs.WriteFileAtomic(path.Join(b.dir, "manifest"), data, 0o600); err != nil {
		return failure("write backup manifest", err)
	}
	if b.transaction != nil {
		return b.transaction.syncBackup(b)
	}
	return nil
}

func (i *Installer) pruneBackups(current string) error {
	entries, err := i.fs.ReadDir(BackupRoot)
	if err != nil {
		return failure("list backups", err)
	}
	var directories []string
	for _, entry := range entries {
		if isRemovalArtifactName(entry.Name()) {
			if err := i.fs.RemoveAll(path.Join(BackupRoot, entry.Name())); err != nil {
				return failure("recover interrupted backup pruning", err)
			}
			continue
		}
		if entry.Name() == "" || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		info, err := i.fs.Lstat(path.Join(BackupRoot, entry.Name()))
		if err != nil {
			return failure("inspect backup", err)
		}
		if info.IsDir() && info.Mode()&fs.ModeSymlink == 0 {
			directories = append(directories, path.Join(BackupRoot, entry.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(directories)))
	keptOthers := 0
	for _, directory := range directories {
		if directory == current {
			continue
		}
		if keptOthers < 2 {
			keptOthers++
			continue
		}
		if err := i.fs.RemoveAll(directory); err != nil {
			return failure("prune backup", err)
		}
	}
	return nil
}

func (i *Installer) copyNode(source, destination string) error {
	info, err := i.fs.Lstat(source)
	if err != nil {
		return err
	}
	if err := i.fs.MkdirAll(path.Dir(destination), 0o700); err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := i.fs.Readlink(source)
		if err != nil {
			return err
		}
		finalInfo, err := i.fs.Lstat(source)
		if err != nil || !sameRemovalEntry(info, finalInfo) {
			return errors.Join(errors.New("managed symbolic link changed while copying: "+source), err)
		}
		if err := i.fs.Remove(destination); err != nil {
			return err
		}
		if err := i.fs.Symlink(target, destination); err != nil {
			return err
		}
		return i.fs.SyncDir(path.Dir(destination))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("managed path is not a regular file or symlink: %s", source)
	}
	if info.Size() < 0 || info.Size() > 256<<20 {
		return fmt.Errorf("managed file exceeds 256 MiB: %s", source)
	}
	return i.fs.CopyTrustedRegularFileAtomic(source, destination, 256<<20, i.rootOwnerUID)
}

func (i *Installer) validateSnapshotCopySource(logicalPath, backupPath string) error {
	info, err := i.fs.Lstat(backupPath)
	if err != nil {
		return fmt.Errorf("inspect snapshot for %s: %w", logicalPath, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		if _, err := i.fs.Readlink(backupPath); err != nil {
			return fmt.Errorf("read symlink snapshot for %s: %w", logicalPath, err)
		}
		finalInfo, err := i.fs.Lstat(backupPath)
		if err != nil || !sameRemovalEntry(info, finalInfo) {
			return errors.Join(fmt.Errorf("symlink snapshot for %s changed while validating", logicalPath), err)
		}
		return nil
	}
	if err := i.fs.ValidateTrustedRegularFile(backupPath, 256<<20, i.rootOwnerUID); err != nil {
		return fmt.Errorf("validate snapshot copy source for %s: %w", logicalPath, err)
	}
	return nil
}

func (i *Installer) preflightRollback(b *backup, private map[string]privateSnapshot) error {
	if b == nil {
		return errors.New("rollback backup is missing")
	}
	seen := make(map[string]bool, len(b.paths))
	for _, destination := range b.paths {
		snapshot, ok := b.snapshots[destination]
		if !ok || seen[destination] {
			return fmt.Errorf("rollback snapshot is missing or duplicated: %s", destination)
		}
		seen[destination] = true
		if snapshot.preserveCurrent {
			if snapshot.exists || destination != aptPeriodicPath && destination != dnfAutomaticPath {
				return fmt.Errorf("invalid preserve-current rollback snapshot: %s", destination)
			}
			continue
		}
		if !snapshot.exists {
			continue
		}
		expected := path.Join(b.dir, strings.TrimPrefix(destination, "/"))
		if snapshot.backupPath != expected {
			return fmt.Errorf("rollback snapshot path does not match %s", destination)
		}
		if err := i.validateSnapshotCopySource(destination, expected); err != nil {
			return err
		}
	}
	for _, credentialPath := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath} {
		snapshot, ok := private[credentialPath]
		if !ok {
			return fmt.Errorf("private rollback snapshot is missing: %s", credentialPath)
		}
		if !snapshot.exists {
			if len(snapshot.data) != 0 || snapshot.mode != 0 {
				return fmt.Errorf("absent private rollback snapshot has state: %s", credentialPath)
			}
			continue
		}
		if snapshot.mode.Perm()&0o077 != 0 || int64(len(snapshot.data)) > privateLimit(credentialPath) {
			return fmt.Errorf("private rollback snapshot is not protected or exceeds its limit: %s", credentialPath)
		}
	}
	return nil
}

func (i *Installer) restoreBackup(b *backup, private map[string]privateSnapshot, timer timerSnapshot, automaticUnits []unitSnapshot) error {
	if err := i.preflightRollback(b, private); err != nil {
		return failure("preflight rollback", err)
	}
	var errs []error
	systemctlAvailable := i.runner.LookPath("systemctl")
	unitRestoreAllowed := systemctlAvailable
	if !systemctlAvailable {
		errs = append(errs, failure("rollback", errors.New("systemctl disappeared during the installation transaction")))
	} else {
		if err := i.quiesceForRollback(timer); err != nil {
			errs = append(errs, err)
			unitRestoreAllowed = false
		}
		if err := i.quiesceAutomaticUnits(automaticUnits); err != nil {
			errs = append(errs, err)
			unitRestoreAllowed = false
		}
	}
	for _, destination := range b.paths {
		snapshot := b.snapshots[destination]
		if snapshot.preserveCurrent {
			continue
		}
		if err := i.fs.Remove(destination); err != nil {
			errs = append(errs, failure("remove changed path during rollback: "+destination, err))
			unitRestoreAllowed = false
			continue
		}
		if !snapshot.exists {
			if err := i.syncExistingDirectory(path.Dir(destination)); err != nil {
				errs = append(errs, failure("sync removed path during rollback: "+destination, err))
				unitRestoreAllowed = false
			}
			continue
		}
		if snapshot.exists {
			parentMode := fs.FileMode(0o755)
			if strings.HasPrefix(destination, "/etc/security-update-notify/") {
				parentMode = 0o750
			}
			if err := i.ensureDir(path.Dir(destination), parentMode); err != nil {
				errs = append(errs, failure("restore parent directory for "+destination, err))
				unitRestoreAllowed = false
				continue
			}
			if err := i.copyNode(snapshot.backupPath, destination); err != nil {
				errs = append(errs, failure("restore "+destination, err))
				unitRestoreAllowed = false
			}
		}
	}
	for _, destination := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath} {
		snapshot := private[destination]
		if err := i.fs.Remove(destination); err != nil {
			errs = append(errs, failure("remove changed credential during rollback: "+destination, err))
			unitRestoreAllowed = false
			continue
		}
		if !snapshot.exists {
			if err := i.syncExistingDirectory(path.Dir(destination)); err != nil {
				errs = append(errs, failure("sync removed credential during rollback: "+destination, err))
				unitRestoreAllowed = false
			}
			continue
		}
		if snapshot.exists {
			if err := i.fs.MkdirAll(path.Dir(destination), 0o700); err != nil {
				errs = append(errs, failure("restore credential directory for "+destination, err))
				unitRestoreAllowed = false
				continue
			}
			if err := i.fs.WriteFileAtomic(destination, snapshot.data, snapshot.mode); err != nil {
				errs = append(errs, failure("restore credential "+destination, err))
				unitRestoreAllowed = false
			}
		}
	}
	if systemctlAvailable {
		if err := i.requiredCommand("reload systemd after rollback", Command{Name: "systemctl", Args: []string{"daemon-reload"}, Timeout: 30 * time.Second}); err != nil {
			errs = append(errs, err)
			unitRestoreAllowed = false
		}
		if unitRestoreAllowed {
			if err := i.restoreAutomaticUnits(automaticUnits); err != nil {
				errs = append(errs, err)
				unitRestoreAllowed = false
			}
		}
		if !unitRestoreAllowed {
			if err := i.containIncompleteRollback(automaticUnits); err != nil {
				errs = append(errs, err)
			}
		}
		if unitRestoreAllowed {
			if err := i.restoreProjectTimer(timer); err != nil {
				errs = append(errs, err)
			}
			after, err := i.snapshotTimer(context.Background())
			if err != nil {
				errs = append(errs, failure("verify project timer after rollback", err))
			} else if after != timer {
				errs = append(errs, failure("verify project timer after rollback", fmt.Errorf(
					"got enablement=%q active=%t, want enablement=%q active=%t",
					after.enablement, after.active, timer.enablement, timer.active)))
			}
		} else if timer.active || len(automaticUnits) > 0 {
			errs = append(errs, failure("restore systemd units after rollback", errors.New(
				"dependent restoration was stopped because an earlier rollback step was incomplete; the project timer was not reactivated")))
		}
	}
	return errors.Join(errs...)
}

func (i *Installer) snapshotPrivateCredentials() (map[string]privateSnapshot, error) {
	result := make(map[string]privateSnapshot, 2)
	for _, credentialPath := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath} {
		limit := int64(64 << 10)
		if credentialPath == FeishuEncryptedCredPath {
			limit = 128 << 10
		}
		file, _, exists, err := i.openFeishuCredential(credentialPath, limit)
		if err != nil {
			return nil, failure("inspect Feishu credential", err)
		}
		if !exists {
			result[credentialPath] = privateSnapshot{}
			continue
		}
		data, openedInfo, err := readOpenedRegularFile(file, limit)
		closeErr := file.Close()
		if err != nil {
			return nil, failure("read Feishu credential", err)
		}
		if closeErr != nil {
			return nil, failure("read Feishu credential", closeErr)
		}
		result[credentialPath] = privateSnapshot{exists: true, mode: openedInfo.Mode().Perm(), data: data}
	}
	return result, nil
}

func (i *Installer) exists(path string) (bool, error) {
	_, err := i.fs.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}
