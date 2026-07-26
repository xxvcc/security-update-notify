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
		if result.Err != nil || result.Code != 0 {
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
	manager := "dnf"
	if !i.runner.LookPath(manager) {
		manager = "yum"
	}
	if !i.runner.LookPath(manager) {
		return failure("install dependencies", errors.New("dnf or yum is required"))
	}
	return i.requiredCommandContext(ctx, "install dnf dependencies", Command{Name: manager, Args: append([]string{"install", "-y"}, missing...), Timeout: 30 * time.Minute})
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
		if exists, err := i.exists("/etc/apt/apt.conf.d/20auto-upgrades"); err != nil {
			return failure("inspect apt periodic config", err)
		} else if exists {
			info, err := i.fs.Lstat("/etc/apt/apt.conf.d/20auto-upgrades")
			if err != nil {
				return failure("inspect apt periodic config", err)
			}
			if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 4<<20 {
				return failure("inspect apt periodic config", errors.New("20auto-upgrades must be a regular file no larger than 4 MiB"))
			}
			if err := i.copyNode("/etc/apt/apt.conf.d/20auto-upgrades", "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak."+stamp); err != nil {
				return failure("backup apt periodic config", err)
			}
			if stable, err := i.exists("/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak"); err != nil {
				return failure("inspect stable apt backup", err)
			} else if !stable {
				if err := i.copyNode("/etc/apt/apt.conf.d/20auto-upgrades", "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak"); err != nil {
					return failure("create stable apt backup", err)
				}
			}
		}
		if err := i.fs.WriteFileAtomic("/etc/apt/apt.conf.d/20auto-upgrades", []byte(aptPeriodicConfig), 0o644); err != nil {
			return failure("install apt periodic config", err)
		}
		if err := i.fs.WriteFileAtomic("/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify", []byte(aptUnattendedPolicy), 0o644); err != nil {
			return failure("install unattended-upgrades policy", err)
		}
		return nil
	}

	const automatic = "/etc/dnf/automatic.conf"
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
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
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
