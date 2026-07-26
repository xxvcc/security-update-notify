package installer

import (
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
	aptAbsentMarkerPath,
	aptLegacyAbsentPath,
	aptPeriodicPath,
	aptStableBackupPath,
	"/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify",
	"/etc/needrestart/conf.d/99-security-update-notify-report-only.conf",
	"/etc/dnf/automatic.conf",
	"/etc/dnf/automatic.conf.security-update-notify.bak",
}

type nodeSnapshot struct {
	exists     bool
	backupPath string
}

type backup struct {
	dir                       string
	manifest                  []string
	paths                     []string
	snapshots                 map[string]nodeSnapshot
	skipDependencyCapturePath map[string]bool
}

type privateSnapshot struct {
	exists bool
	mode   fs.FileMode
	data   []byte
}

func (i *Installer) createBackup() (*backup, error) {
	if err := i.ensureManagedDir(BackupRoot, 0o700); err != nil {
		return nil, failure("create backup root", err)
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
			_ = i.fs.RemoveAll(dir)
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
		snapshot.exists = true
		snapshot.backupPath = path.Join(b.dir, strings.TrimPrefix(source, "/"))
		if err := i.copyNode(source, snapshot.backupPath); err != nil {
			return failure("capture dependency-created default", err)
		}
		b.snapshots[source] = snapshot
		b.manifest = append(b.manifest, strings.TrimPrefix(source, "/"))
		changed = true
	}
	if changed {
		return i.writeManifest(b)
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
	return nil
}

func (i *Installer) pruneBackups(current string) error {
	entries, err := i.fs.ReadDir(BackupRoot)
	if err != nil {
		return failure("list backups", err)
	}
	var directories []string
	for _, entry := range entries {
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
		if err := i.fs.Remove(destination); err != nil {
			return err
		}
		return i.fs.Symlink(target, destination)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("managed path is not a regular file or symlink: %s", source)
	}
	if info.Size() < 0 || info.Size() > 256<<20 {
		return fmt.Errorf("managed file exceeds 256 MiB: %s", source)
	}
	return i.fs.CopyRegularFileAtomic(source, destination, 256<<20)
}

func (i *Installer) restoreBackup(b *backup, private map[string]privateSnapshot, timer timerSnapshot, lockWait time.Duration) error {
	if !i.runner.LookPath("systemctl") {
		return failure("rollback", errors.New("systemctl disappeared during the installation transaction"))
	}
	if err := i.quiesceForRollback(lockWait, timer); err != nil {
		return err
	}
	for _, destination := range b.paths {
		snapshot := b.snapshots[destination]
		if err := i.fs.Remove(destination); err != nil {
			return failure("remove changed path during rollback", err)
		}
		if snapshot.exists {
			parentMode := fs.FileMode(0o755)
			if strings.HasPrefix(destination, "/etc/security-update-notify/") {
				parentMode = 0o750
			}
			if err := i.ensureDir(path.Dir(destination), parentMode); err != nil {
				return failure("restore parent directory", err)
			}
			if err := i.copyNode(snapshot.backupPath, destination); err != nil {
				return failure("restore "+destination, err)
			}
		}
	}
	for destination, snapshot := range private {
		if err := i.fs.Remove(destination); err != nil {
			return failure("remove changed credential during rollback", err)
		}
		if snapshot.exists {
			if err := i.fs.MkdirAll(path.Dir(destination), 0o700); err != nil {
				return failure("restore credential directory", err)
			}
			if err := i.fs.WriteFileAtomic(destination, snapshot.data, snapshot.mode); err != nil {
				return failure("restore credential", err)
			}
		}
	}
	if err := i.requiredCommand("reload systemd after rollback", Command{Name: "systemctl", Args: []string{"daemon-reload"}, Timeout: 30 * time.Second}); err != nil {
		return err
	}
	if timer.active {
		if err := i.requiredCommand("restart timer after rollback", Command{Name: "systemctl", Args: []string{"start", "security-update-notify.timer"}, Timeout: 30 * time.Second}); err != nil {
			return err
		}
	}
	if timer.enablement != "unknown" {
		result := i.run(Command{Name: "systemctl", Args: []string{"is-enabled", "security-update-notify.timer"}, Timeout: 30 * time.Second})
		if got := strings.TrimSpace(string(result.Stdout)); got != timer.enablement {
			return failure("verify timer enablement after rollback", fmt.Errorf("got %q, want %q", got, timer.enablement))
		}
	}
	active := i.run(Command{Name: "systemctl", Args: []string{"is-active", "--quiet", "security-update-notify.timer"}, Timeout: 30 * time.Second}).Code == 0
	if active != timer.active {
		return failure("verify timer activity after rollback", fmt.Errorf("got active=%t, want %t", active, timer.active))
	}
	return nil
}

func (i *Installer) snapshotPrivateCredentials() (map[string]privateSnapshot, error) {
	result := make(map[string]privateSnapshot, 2)
	for _, credentialPath := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath} {
		info, err := i.fs.Lstat(credentialPath)
		if errors.Is(err, fs.ErrNotExist) {
			result[credentialPath] = privateSnapshot{}
			continue
		}
		if err != nil {
			return nil, failure("inspect Feishu credential", err)
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, failure("inspect Feishu credential", errors.New("credential must be a regular file, not a symlink"))
		}
		if info.Size() < 0 || info.Size() > 128<<10 {
			return nil, failure("read Feishu credential", errors.New("credential exceeds 128 KiB"))
		}
		data, openedInfo, err := i.fs.ReadRegularFile(credentialPath, 128<<10)
		if err != nil {
			return nil, failure("read Feishu credential", err)
		}
		if len(data) > 128<<10 {
			return nil, failure("read Feishu credential", errors.New("credential exceeds 128 KiB"))
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
