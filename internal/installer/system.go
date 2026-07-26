package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"syscall"
	"time"
)

const aptPeriodicConfig = `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
`

const (
	aptPeriodicPath         = "/etc/apt/apt.conf.d/20auto-upgrades"
	aptStableBackupPath     = aptPeriodicPath + ".security-update-notify.bak"
	aptAbsentMarkerPath     = aptPeriodicPath + ".security-update-notify.absent.bak"
	aptLegacyAbsentPath     = aptPeriodicPath + ".security-update-notify.absent"
	aptAbsentMarkerContents = "security-update-notify: original file absent\n"
	dnfAutomaticPath        = "/etc/dnf/automatic.conf"
	dnfStableBackupPath     = dnfAutomaticPath + ".security-update-notify.bak"
)

const aptUnattendedPolicy = `// 本地策略：永不自动重启。发行版软件包保留其默认 Origins-Pattern 安全规则。
// Local policy: never reboot automatically. The distribution package keeps
// its default Origins-Pattern security rules.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::SyslogEnable "true";
`

type timerSnapshot struct {
	active     bool
	enablement string
}

func (i *Installer) ensureDir(directory string, mode fs.FileMode) error {
	info, err := i.fs.Lstat(directory)
	if errors.Is(err, fs.ErrNotExist) {
		if err := i.fs.MkdirAll(directory, mode); err != nil {
			return err
		}
		return i.fs.Chmod(directory, mode)
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a directory, not a symlink", directory)
	}
	return nil
}

func (i *Installer) ensureManagedDir(directory string, mode fs.FileMode) error {
	if err := i.ensureDir(directory, mode); err != nil {
		return err
	}
	return i.fs.Chmod(directory, mode)
}

func (i *Installer) requireSystemd() error {
	info, err := i.fs.Lstat("/run/systemd/system")
	if err != nil {
		return failure("detect systemd", errors.New("systemd is required; /run/systemd/system is unavailable"))
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return failure("detect systemd", errors.New("/run/systemd/system must be a real directory"))
	}
	if !i.runner.LookPath("systemctl") {
		return failure("detect systemd", errors.New("systemctl is required"))
	}
	return nil
}

func (i *Installer) snapshotTimer() timerSnapshot {
	enabled := i.run(Command{Name: "systemctl", Args: []string{"is-enabled", "security-update-notify.timer"}, Timeout: 30 * time.Second})
	enablement := strings.TrimSpace(string(enabled.Stdout))
	if enablement == "" {
		enablement = "unknown"
	}
	active := i.run(Command{Name: "systemctl", Args: []string{"is-active", "--quiet", "security-update-notify.timer"}, Timeout: 30 * time.Second}).Code == 0
	return timerSnapshot{active: active, enablement: enablement}
}

func (i *Installer) quiesceExisting(ctx context.Context, upgrade bool, wait time.Duration) error {
	if !upgrade {
		return nil
	}
	hasTimer := false
	for _, name := range []string{TimerPath, PersistentTimerLink, RuntimeTimerLink} {
		exists, err := i.exists(name)
		if err != nil {
			return failure("inspect timer before upgrade", err)
		}
		hasTimer = hasTimer || exists
	}
	if hasTimer {
		if err := i.requiredCommandContext(ctx, "disable old timer", Command{Name: "systemctl", Args: []string{"disable", "--now", "security-update-notify.timer"}, Timeout: 30 * time.Second}); err != nil {
			return err
		}
	}
	unlock, err := i.locker.Acquire(ctx, RuntimeLockPath, wait)
	if err != nil {
		if errors.Is(err, ErrLockBusy) || errors.Is(err, context.DeadlineExceeded) {
			return temporary("quiesce runtime", errors.New("timed out waiting for the existing security-update-notify run"))
		}
		return failure("acquire runtime lock", err)
	}
	defer func() { _ = unlock() }()
	serviceExists, err := i.exists(ServicePath)
	if err != nil {
		return failure("inspect service before upgrade", err)
	}
	if serviceExists {
		if err := i.requiredCommandContext(ctx, "stop queued service", Command{Name: "systemctl", Args: []string{"stop", "security-update-notify.service"}, Timeout: 30 * time.Second}); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) quiesceForRollback(wait time.Duration, timer timerSnapshot) error {
	hasTimer := timer.active
	for _, name := range []string{TimerPath, PersistentTimerLink, RuntimeTimerLink} {
		exists, err := i.exists(name)
		if err != nil {
			return failure("inspect timer during rollback", err)
		}
		hasTimer = hasTimer || exists
	}
	if hasTimer && i.runner.LookPath("systemctl") {
		if err := i.requiredCommand("disable timer during rollback", Command{Name: "systemctl", Args: []string{"disable", "--now", "security-update-notify.timer"}, Timeout: 30 * time.Second}); err != nil {
			return err
		}
	}
	unlock, err := i.locker.Acquire(context.Background(), RuntimeLockPath, wait)
	if err != nil {
		return failure("acquire runtime lock during rollback", err)
	}
	defer func() { _ = unlock() }()
	serviceExists, err := i.exists(ServicePath)
	if err != nil {
		return failure("inspect service during rollback", err)
	}
	if serviceExists && i.runner.LookPath("systemctl") {
		if err := i.requiredCommand("stop service during rollback", Command{Name: "systemctl", Args: []string{"stop", "security-update-notify.service"}, Timeout: 30 * time.Second}); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) installDependencies(ctx context.Context, plan installPlan, confirm ConfirmDependenciesFunc) error {
	var probe string
	var packages []string
	switch plan.backend {
	case "apt":
		if !i.runner.LookPath("apt-get") || !i.runner.LookPath("dpkg") {
			return failure("install dependencies", errors.New("apt-get and dpkg are required"))
		}
		probe = "dpkg"
		packages = []string{"unattended-upgrades", "needrestart", "apt-listchanges", "ca-certificates"}
	case "dnf":
		if !i.runner.LookPath("rpm") {
			return failure("install dependencies", errors.New("rpm is required for the dnf backend"))
		}
		probe = "rpm"
		packages = []string{"dnf-automatic", "ca-certificates"}
		if plan.osRelease.ID == "fedora" {
			packages = append(packages, "dnf-utils")
		} else {
			packages = append(packages, "yum-utils")
		}
	}
	missing := make([]string, 0, len(packages))
	for _, pkg := range packages {
		args := []string{"-s", pkg}
		if probe == "rpm" {
			args = []string{"-q", pkg}
		}
		result := i.runner.Run(ctx, Command{Name: probe, Args: args, Timeout: 30 * time.Second})
		installed := result.Err == nil && result.Code == 0
		if probe == "dpkg" {
			installed = installed && dpkgStatusInstalled(result.Stdout)
		}
		if !installed {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if confirm == nil {
		return failure("confirm dependency installation", errors.New("required packages are missing and no confirmation callback was provided"))
	}
	approved, err := confirm(ctx, DependencyRequest{Backend: plan.backend, Packages: append([]string(nil), missing...)})
	if err != nil {
		return failure("confirm dependency installation", err)
	}
	if !approved {
		return failure("confirm dependency installation", errors.New("required package installation was declined"))
	}
	if plan.backend == "apt" {
		if err := i.requiredCommandContext(ctx, "update apt package lists", Command{Name: "apt-get", Args: []string{"update"}, Timeout: 15 * time.Minute}); err != nil {
			return err
		}
		return i.requiredCommandContext(ctx, "install apt dependencies", Command{
			Name: "apt-get", Args: append([]string{"install", "-y"}, missing...),
			Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}, Timeout: 30 * time.Minute,
		})
	}
	manager := ""
	for _, candidate := range []string{"dnf", "microdnf", "yum"} {
		if i.runner.LookPath(candidate) {
			manager = candidate
			break
		}
	}
	if manager == "" {
		return failure("install dependencies", errors.New("dnf, microdnf, or yum is required"))
	}
	return i.requiredCommandContext(ctx, "install dnf dependencies", Command{Name: manager, Args: append([]string{"install", "-y"}, missing...), Timeout: 30 * time.Minute})
}

func dpkgStatusInstalled(output []byte) bool {
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "Status: install ok installed" {
			return true
		}
	}
	return false
}

// migrateAPTMetadata moves older SUN metadata to names ending in .bak. APT
// silently ignores that suffix; the former .absent and .bak.<timestamp> names
// produced a notice during every apt invocation.
func (i *Installer) migrateAPTMetadata(b *backup) error {
	if err := i.ensureDir(path.Dir(aptPeriodicPath), 0o755); err != nil {
		return failure("create apt configuration directory", err)
	}
	legacyMarker, err := i.validAPTAbsentMarkerAt(aptLegacyAbsentPath)
	if err != nil {
		return failure("inspect legacy apt absence marker", err)
	}
	if legacyMarker {
		currentMarker, err := i.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
		if err != nil {
			return failure("inspect apt absence marker", err)
		}
		if !currentMarker {
			if err := i.fs.WriteFileAtomic(aptAbsentMarkerPath, []byte(aptAbsentMarkerContents), 0o600); err != nil {
				return failure("migrate apt absence marker", err)
			}
			// This is a transaction-owned rename, not a package-created default.
			// Restoring it together with the legacy marker would leave both names.
			b.skipDependencyCapturePath[aptAbsentMarkerPath] = true
		}
		if err := i.fs.Remove(aptLegacyAbsentPath); err != nil {
			return failure("remove legacy apt absence marker", err)
		}
	}

	entries, err := i.fs.ReadDir(path.Dir(aptPeriodicPath))
	if err != nil {
		return failure("list apt configuration backups", err)
	}
	legacyPrefix := path.Base(aptStableBackupPath) + "."
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, legacyPrefix) || len(name) == len(legacyPrefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, legacyPrefix)
		if !validBackupTimestamp(suffix) {
			continue
		}
		source := path.Join(path.Dir(aptPeriodicPath), name)
		destination := aptPeriodicPath + ".security-update-notify." + suffix + ".bak"
		if err := i.snapshotAdditionalPath(b, source); err != nil {
			return err
		}
		if err := i.snapshotAdditionalPath(b, destination); err != nil {
			return err
		}
		sourceExists, err := i.validBaselineFile(source)
		if err != nil || !sourceExists {
			if err == nil {
				err = errors.New("legacy apt backup disappeared")
			}
			return failure("inspect legacy apt backup", err)
		}
		destinationExists, err := i.validBaselineFile(destination)
		if err != nil {
			return failure("inspect migrated apt backup", err)
		}
		if destinationExists {
			sourceData, _, sourceErr := i.fs.ReadRegularFile(source, 4<<20)
			destinationData, _, destinationErr := i.fs.ReadRegularFile(destination, 4<<20)
			if sourceErr != nil || destinationErr != nil || !bytes.Equal(sourceData, destinationData) {
				return failure("migrate apt backup", errors.New("legacy and migrated backups differ: "+name))
			}
		} else if err := i.copyNode(source, destination); err != nil {
			return failure("migrate apt backup", err)
		}
		if err := i.fs.Remove(source); err != nil {
			return failure("remove legacy apt backup", err)
		}
	}
	return nil
}

func (i *Installer) recordAPTAbsentBaseline() error {
	if err := i.ensureDir(path.Dir(aptAbsentMarkerPath), 0o755); err != nil {
		return failure("create apt configuration directory", err)
	}
	stable, err := i.validBaselineFile(aptStableBackupPath)
	if err != nil {
		return failure("inspect stable apt backup", err)
	}
	marker, err := i.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
	if err != nil {
		return failure("inspect apt absence marker", err)
	}
	if stable || marker {
		return nil
	}
	if err := i.fs.WriteFileAtomic(aptAbsentMarkerPath, []byte(aptAbsentMarkerContents), 0o600); err != nil {
		return failure("record absent apt periodic config", err)
	}
	return nil
}

func (i *Installer) validAPTAbsentMarkerAt(markerPath string) (bool, error) {
	exists, err := i.validBaselineFile(markerPath)
	if err != nil || !exists {
		return exists, err
	}
	data, _, err := i.fs.ReadRegularFile(markerPath, 256)
	if err != nil {
		return false, err
	}
	if string(data) != aptAbsentMarkerContents {
		return false, errors.New("apt absence marker has invalid contents")
	}
	return true, nil
}

func (i *Installer) validBaselineFile(name string) (bool, error) {
	info, err := i.fs.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 4<<20 {
		return false, fmt.Errorf("%s must be a regular file no larger than 4 MiB", name)
	}
	return true, nil
}

func (i *Installer) installFiles(ctx context.Context, plan installPlan, options Options, secret []byte) (string, error) {
	payload := options.Payload.withEmbeddedDefaults()
	for directory, mode := range map[string]fs.FileMode{
		"/usr/local/sbin":     0o755,
		"/var/log":            0o755,
		"/etc/systemd/system": 0o755,
	} {
		if err := i.ensureDir(directory, mode); err != nil {
			return "", failure("create install directory", err)
		}
	}
	for directory, mode := range map[string]fs.FileMode{
		"/etc/security-update-notify":     0o750,
		"/var/lib/security-update-notify": 0o750,
	} {
		if err := i.ensureManagedDir(directory, mode); err != nil {
			return "", failure("create managed install directory", err)
		}
	}
	logInfo, logErr := i.fs.Lstat(LogPath)
	if errors.Is(logErr, fs.ErrNotExist) {
		if err := i.fs.WriteFileAtomic(LogPath, nil, 0o640); err != nil {
			return "", failure("create log file", err)
		}
	} else if logErr != nil {
		return "", failure("inspect log file", logErr)
	} else if logInfo.Mode()&fs.ModeSymlink != 0 || !logInfo.Mode().IsRegular() {
		return "", failure("inspect log file", errors.New("log path must be a regular file, not a symlink"))
	}
	if err := i.fs.Chmod(LogPath, 0o640); err != nil {
		return "", failure("set log permissions", err)
	}
	if logrotateDir, err := i.fs.Lstat("/etc/logrotate.d"); err == nil && logrotateDir.IsDir() && logrotateDir.Mode()&fs.ModeSymlink == 0 {
		if err := i.fs.WriteFileAtomic(LogrotatePath, payload.Logrotate, 0o644); err != nil {
			return "", failure("install logrotate policy", err)
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", failure("inspect logrotate directory", err)
	} else if err == nil {
		return "", failure("inspect logrotate directory", errors.New("/etc/logrotate.d must be a real directory"))
	}
	if err := i.fs.WriteFileAtomic(BinaryPath, payload.Runtime, 0o755); err != nil {
		return "", failure("install runtime", err)
	}
	if err := i.fs.WriteFileAtomic(ServicePath, payload.Service, 0o644); err != nil {
		return "", failure("install service unit", err)
	}
	if err := i.installBackendPolicy(plan, payload); err != nil {
		return "", err
	}
	storage, err := i.installFeishuCredential(ctx, plan.values["NOTIFY_CHANNELS"], secret)
	if err != nil {
		return "", err
	}
	configData, err := renderConfig(plan.values)
	if err != nil {
		return "", failure("render config", err)
	}
	if err := i.fs.WriteFileAtomic(ConfigPath, configData, 0o600); err != nil {
		return "", failure("install config", err)
	}
	timerData := []byte(renderTimer(plan.checkTime))
	if err := i.fs.WriteFileAtomic(TimerPath, timerData, 0o644); err != nil {
		return "", failure("install timer unit", err)
	}
	return storage, nil
}

func (i *Installer) installBackendPolicy(plan installPlan, payload Payload) error {
	stamp := i.now().Format("20060102150405")
	if plan.backend == "apt" {
		if err := i.ensureDir("/etc/apt/apt.conf.d", 0o755); err != nil {
			return failure("create apt configuration directory", err)
		}
		if err := i.ensureDir("/etc/needrestart/conf.d", 0o755); err != nil {
			return failure("create needrestart directory", err)
		}
		if err := i.fs.WriteFileAtomic("/etc/needrestart/conf.d/99-security-update-notify-report-only.conf", payload.Needrestart, 0o644); err != nil {
			return failure("install needrestart policy", err)
		}
		if exists, err := i.exists(aptPeriodicPath); err != nil {
			return failure("inspect apt periodic config", err)
		} else if exists {
			info, err := i.fs.Lstat(aptPeriodicPath)
			if err != nil {
				return failure("inspect apt periodic config", err)
			}
			if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 4<<20 {
				return failure("inspect apt periodic config", errors.New("20auto-upgrades must be a regular file no larger than 4 MiB"))
			}
			timestampBackup := aptPeriodicPath + ".security-update-notify." + stamp + ".bak"
			if err := i.copyNode(aptPeriodicPath, timestampBackup); err != nil {
				return failure("backup apt periodic config", err)
			}
			stable, err := i.validBaselineFile(aptStableBackupPath)
			if err != nil {
				return failure("inspect stable apt backup", err)
			}
			marker, err := i.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
			if err != nil {
				return failure("inspect apt absence marker", err)
			}
			if !stable && !marker {
				if err := i.copyNode(aptPeriodicPath, aptStableBackupPath); err != nil {
					return failure("create stable apt backup", err)
				}
			}
		}
		if err := i.fs.WriteFileAtomic(aptPeriodicPath, []byte(aptPeriodicConfig), 0o644); err != nil {
			return failure("install apt periodic config", err)
		}
		if err := i.fs.WriteFileAtomic("/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify", []byte(aptUnattendedPolicy), 0o644); err != nil {
			return failure("install unattended-upgrades policy", err)
		}
		return nil
	}

	const automatic = dnfAutomaticPath
	exists, err := i.exists(automatic)
	if err != nil {
		return failure("inspect dnf automatic config", err)
	}
	if !exists {
		return nil
	}
	info, err := i.fs.Lstat(automatic)
	if err != nil {
		return failure("inspect dnf automatic config", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return failure("inspect dnf automatic config", errors.New("automatic.conf must be a regular file, not a symlink"))
	}
	if info.Size() < 0 || info.Size() > 4<<20 {
		return failure("inspect dnf automatic config", errors.New("automatic.conf exceeds 4 MiB"))
	}
	stable, err := i.validBaselineFile(dnfStableBackupPath)
	if err != nil {
		return failure("inspect stable dnf backup", err)
	}
	if !stable {
		baseline, err := i.oldestDNFProjectBackup()
		if err != nil {
			return failure("select original dnf backup", err)
		}
		if baseline == "" {
			baseline = automatic
		}
		if err := i.copyNode(baseline, dnfStableBackupPath); err != nil {
			return failure("create stable dnf backup", err)
		}
	}
	if err := i.copyNode(automatic, automatic+".security-update-notify.bak."+stamp); err != nil {
		return failure("backup dnf automatic config", err)
	}
	data, _, err := i.fs.ReadRegularFile(automatic, 4<<20)
	if err != nil {
		return failure("read dnf automatic config", err)
	}
	for _, setting := range [][3]string{
		{"commands", "upgrade_type", "security"},
		{"commands", "apply_updates", "yes"},
		{"emitters", "emit_via", "stdio"},
		{"base", "debuglevel", "1"},
	} {
		data = setINI(data, setting[0], setting[1], setting[2])
	}
	if err := i.fs.WriteFileAtomic(automatic, data, 0o644); err != nil {
		return failure("install dnf automatic policy", err)
	}
	return nil
}

func (i *Installer) oldestDNFProjectBackup() (string, error) {
	entries, err := i.fs.ReadDir(path.Dir(dnfAutomaticPath))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	prefix := path.Base(dnfStableBackupPath) + "."
	oldest := ""
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
			continue
		}
		if !validBackupTimestamp(strings.TrimPrefix(name, prefix)) {
			continue
		}
		candidate := path.Join(path.Dir(dnfAutomaticPath), name)
		info, err := i.fs.Lstat(candidate)
		if err != nil {
			return "", err
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 4<<20 {
			return "", fmt.Errorf("%s must be a regular file no larger than 4 MiB", candidate)
		}
		if oldest == "" || candidate < oldest {
			oldest = candidate
		}
	}
	return oldest, nil
}

func validBackupTimestamp(value string) bool {
	if len(value) != len("20060102150405") {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func setINI(data []byte, section, key, value string) []byte {
	trimmedData := strings.TrimSuffix(string(data), "\n")
	var lines []string
	if trimmedData != "" {
		lines = strings.Split(trimmedData, "\n")
	}
	output := make([]string, 0, len(lines)+2)
	inSection, seenSection, written := false, false, false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inSection && !written {
				output = append(output, key+" = "+value)
				written = true
			}
			inSection = trimmed == "["+section+"]"
			seenSection = seenSection || inSection
			output = append(output, line)
			continue
		}
		lineKey := ""
		if before, _, ok := strings.Cut(trimmed, "="); ok {
			lineKey = strings.TrimSpace(before)
		}
		if inSection && lineKey == key {
			output = append(output, key+" = "+value)
			written = true
		} else {
			output = append(output, line)
		}
	}
	if !seenSection {
		output = append(output, "["+section+"]", key+" = "+value)
	} else if inSection && !written {
		output = append(output, key+" = "+value)
	}
	return []byte(strings.Join(output, "\n") + "\n")
}

func (i *Installer) installFeishuCredential(ctx context.Context, channels string, secret []byte) (string, error) {
	if !channelSelected(channels, "feishu") {
		for _, name := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath, FeishuCredentialDropIn} {
			if err := i.fs.Remove(name); err != nil {
				return "", failure("remove disabled Feishu credential", err)
			}
		}
		return "disabled", nil
	}
	if len(secret) == 0 {
		if exists, err := i.regularCredentialExists(FeishuEncryptedCredPath); err != nil {
			return "", err
		} else if exists {
			if err := i.writeCredentialDropIn(); err != nil {
				return "", err
			}
			return "encrypted", nil
		}
		if exists, err := i.regularCredentialExists(FeishuPlainCredentialPath); err != nil {
			return "", err
		} else if exists {
			if err := i.fs.Remove(FeishuCredentialDropIn); err != nil {
				return "", failure("remove stale credential drop-in", err)
			}
			return "plain", nil
		}
		return "", invalid("missing Feishu App Secret credential")
	}
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	if i.runner.LookPath("systemd-creds") {
		_ = i.runner.Run(ctx, Command{Name: "systemd-creds", Args: []string{"setup"}, Timeout: 30 * time.Second})
		result := i.runner.Run(ctx, Command{
			Name: "systemd-creds", Args: []string{"encrypt", "--name=feishu_app_secret", "--with-key=host", "-", "-"},
			Stdin: secret, Timeout: 30 * time.Second,
		})
		if result.Err != nil || result.Code != 0 || len(result.Stdout) == 0 || len(result.Stdout) > 128<<10 {
			return "", failure("encrypt Feishu App Secret", commandResultError(result))
		}
		if err := i.ensureManagedDir(path.Dir(FeishuEncryptedCredPath), 0o700); err != nil {
			return "", failure("create encrypted credential directory", err)
		}
		if err := i.fs.WriteFileAtomic(FeishuEncryptedCredPath, result.Stdout, 0o600); err != nil {
			return "", failure("install encrypted credential", err)
		}
		if err := i.fs.Remove(FeishuPlainCredentialPath); err != nil {
			return "", failure("remove plaintext credential", err)
		}
		if err := i.writeCredentialDropIn(); err != nil {
			return "", err
		}
		return "encrypted", nil
	}
	if err := i.ensureManagedDir(path.Dir(FeishuPlainCredentialPath), 0o700); err != nil {
		return "", failure("create plaintext credential directory", err)
	}
	if err := i.fs.WriteFileAtomic(FeishuPlainCredentialPath, secret, 0o600); err != nil {
		return "", failure("install plaintext credential", err)
	}
	if err := i.fs.Remove(FeishuEncryptedCredPath); err != nil {
		return "", failure("remove encrypted credential", err)
	}
	if err := i.fs.Remove(FeishuCredentialDropIn); err != nil {
		return "", failure("remove encrypted credential drop-in", err)
	}
	return "plain", nil
}

func (i *Installer) writeCredentialDropIn() error {
	if err := i.ensureManagedDir(path.Dir(FeishuCredentialDropIn), 0o755); err != nil {
		return failure("create credential drop-in directory", err)
	}
	content := []byte("[Service]\nLoadCredentialEncrypted=feishu_app_secret:" + FeishuEncryptedCredPath + "\n")
	if err := i.fs.WriteFileAtomic(FeishuCredentialDropIn, content, 0o644); err != nil {
		return failure("install credential drop-in", err)
	}
	return nil
}

func (i *Installer) regularCredentialExists(name string) (bool, error) {
	info, err := i.fs.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, failure("inspect Feishu credential", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, failure("inspect Feishu credential", errors.New("credential must be a regular file, not a symlink"))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false, failure("inspect Feishu credential", errors.New("credential must not be accessible by group or other users"))
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != i.rootOwnerUID {
		return false, failure("inspect Feishu credential", errors.New("credential must be owned by root"))
	}
	limit := int64(64 << 10)
	if name == FeishuEncryptedCredPath {
		limit = 128 << 10
	}
	if info.Size() < 0 || info.Size() > limit {
		return false, failure("inspect Feishu credential", errors.New("credential is too large"))
	}
	return true, nil
}

func (i *Installer) loadFeishuSecret(ctx context.Context) ([]byte, error) {
	if exists, err := i.regularCredentialExists(FeishuEncryptedCredPath); err != nil {
		return nil, err
	} else if exists {
		if !i.runner.LookPath("systemd-creds") {
			return nil, failure("decrypt Feishu credential", errors.New("systemd-creds is required"))
		}
		result := i.runner.Run(ctx, Command{
			Name: "systemd-creds", Args: []string{"decrypt", "--name=feishu_app_secret", FeishuEncryptedCredPath, "-"},
			Timeout: 10 * time.Second,
		})
		if result.Err != nil || result.Code != 0 {
			return nil, failure("decrypt Feishu credential", commandResultError(result))
		}
		if err := validateSecret(result.Stdout); err != nil {
			return nil, err
		}
		return bytes.Clone(result.Stdout), nil
	}
	if exists, err := i.regularCredentialExists(FeishuPlainCredentialPath); err != nil {
		return nil, err
	} else if exists {
		data, _, err := i.fs.ReadRegularFile(FeishuPlainCredentialPath, 64<<10)
		if err != nil {
			return nil, failure("read Feishu credential", err)
		}
		if err := validateSecret(data); err != nil {
			return nil, err
		}
		return bytes.Clone(data), nil
	}
	return nil, invalid("missing Feishu App Secret credential")
}

func renderTimer(checkTime string) string {
	return `[Unit]
Description=安全更新每日重启/服务重启通知 / Daily security update reboot/service-restart notification

[Timer]
OnCalendar=*-*-* ` + checkTime + `:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
`
}

func (i *Installer) run(command Command) CommandResult {
	return i.runner.Run(context.Background(), command)
}

func (i *Installer) requiredCommand(op string, command Command) error {
	return i.requiredCommandContext(context.Background(), op, command)
}

func (i *Installer) requiredCommandContext(ctx context.Context, op string, command Command) error {
	result := i.runner.Run(ctx, command)
	if result.Err != nil || result.Code != 0 {
		return failure(op, commandResultError(result))
	}
	return nil
}

func commandResultError(result CommandResult) error {
	if result.Err != nil {
		return result.Err
	}
	detail := strings.TrimSpace(string(result.Stderr))
	if detail == "" {
		detail = strings.TrimSpace(string(result.Stdout))
	}
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	if detail == "" {
		detail = fmt.Sprintf("command exited with status %d", result.Code)
	}
	return errors.New(detail)
}
