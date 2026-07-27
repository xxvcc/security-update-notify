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

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
	"github.com/xxvcc/security-update-notify/internal/dependencyproof"
	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
	"github.com/xxvcc/security-update-notify/internal/osrel"
)

const aptPeriodicConfig = aptconfig.Periodic

const (
	aptPeriodicPath          = "/etc/apt/apt.conf.d/20auto-upgrades"
	aptStableBackupPath      = aptPeriodicPath + ".security-update-notify.bak"
	aptAbsentMarkerPath      = aptPeriodicPath + ".security-update-notify.absent.bak"
	aptLegacyAbsentPath      = aptPeriodicPath + ".security-update-notify.absent"
	aptDependencyProofPath   = aptPeriodicPath + ".security-update-notify.dependency-default.bak"
	aptAbsentMarkerContents  = "security-update-notify: original file absent\n"
	dnfAutomaticPath         = "/etc/dnf/automatic.conf"
	dnfStableBackupPath      = dnfAutomaticPath + ".security-update-notify.bak"
	dnfAbsentMarkerPath      = dnfAutomaticPath + ".security-update-notify.absent.bak"
	dnfDependencyProofPath   = dnfAutomaticPath + ".security-update-notify.dependency-default.bak"
	dnfAbsentMarkerContents  = "security-update-notify: original file absent; engine=dnf4\n"
	dnf5AbsentMarkerContents = "security-update-notify: original file absent; engine=dnf5\n"
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

type unitSnapshot struct {
	name       string
	active     bool
	enablement string
}

var knownUnitEnablement = map[string]bool{
	"alias":           true,
	"bad":             true,
	"disabled":        true,
	"enabled":         true,
	"enabled-runtime": true,
	"generated":       true,
	"indirect":        true,
	"linked":          true,
	"linked-runtime":  true,
	"masked":          true,
	"masked-runtime":  true,
	"not-found":       true,
	"static":          true,
	"transient":       true,
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
	if info.Mode()&fs.ModeSymlink != 0 {
		if directory == "/usr/local/sbin" {
			return i.validateLocalSbinAlias(info)
		}
		return fmt.Errorf("%s must be a directory, not a symlink", directory)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory, not a symlink", directory)
	}
	return nil
}

func (i *Installer) validateLocalSbinAlias(linkInfo fs.FileInfo) error {
	target, err := i.fs.Readlink("/usr/local/sbin")
	if err != nil || target != "bin" {
		return errors.New("/usr/local/sbin must be a real directory or the exact relative symlink 'bin'")
	}
	if stat, ok := linkInfo.Sys().(*syscall.Stat_t); ok && stat.Uid != i.rootOwnerUID {
		return errors.New("/usr/local/sbin must be owned by root")
	}
	for _, name := range []string{"/usr/local", "/usr/local/bin"} {
		info, err := i.fs.Lstat(name)
		if err != nil {
			return fmt.Errorf("inspect standard /usr/local/sbin target %s: %w", name, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("standard /usr/local/sbin target %s must be a real directory", name)
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != i.rootOwnerUID {
			return fmt.Errorf("%s must be owned by root", name)
		}
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

func (i *Installer) snapshotTimer(ctx context.Context) (timerSnapshot, error) {
	exists, err := i.exists(TimerPath)
	if err != nil {
		return timerSnapshot{}, failure("snapshot project timer", err)
	}
	if !exists {
		// systemctl reports a missing unit through stderr on some supported
		// systemd versions. The managed unit file is the authoritative fresh-install
		// boundary, so avoid turning that expected state into a D-Bus failure.
		return timerSnapshot{enablement: "not-found"}, nil
	}
	snapshot, err := i.snapshotUnit(ctx, "security-update-notify.timer")
	if err != nil {
		return timerSnapshot{}, failure("snapshot project timer", err)
	}
	if !restorableProjectTimerEnablement(snapshot.enablement) {
		return timerSnapshot{}, failure("snapshot project timer", fmt.Errorf(
			"enablement state %q cannot be restored exactly; normalize it to disabled, enabled, enabled-runtime, or static before installation",
			snapshot.enablement))
	}
	return timerSnapshot{active: snapshot.active, enablement: snapshot.enablement}, nil
}

func restorableProjectTimerEnablement(enablement string) bool {
	switch enablement {
	case "disabled", "enabled", "enabled-runtime", "static":
		return true
	default:
		return false
	}
}

func automaticUnitNames(plan installPlan) []string {
	var candidates []string
	if plan.backend == "apt" {
		candidates = []string{"apt-daily.timer", plan.profile.AutomaticTimer, "unattended-upgrades.service"}
	} else {
		candidates = append([]string{plan.profile.AutomaticTimer}, plan.profile.AutomaticTimerVariants...)
	}
	seen := make(map[string]bool, len(candidates))
	units := make([]string, 0, len(candidates))
	for _, unit := range candidates {
		if unit != "" && !seen[unit] {
			seen[unit] = true
			units = append(units, unit)
		}
	}
	return units
}

func (i *Installer) snapshotAutomaticUnits(ctx context.Context, plan installPlan) ([]unitSnapshot, error) {
	units := automaticUnitNames(plan)
	if len(units) == 0 {
		return nil, failure("snapshot automatic-update units", errors.New("distribution profile does not define a timer"))
	}
	snapshots := make([]unitSnapshot, 0, len(units))
	for _, unit := range units {
		snapshot, err := i.snapshotUnit(ctx, unit)
		if err != nil {
			return nil, err
		}
		if !restorableAutomaticEnablement(snapshot.enablement) {
			return nil, failure("snapshot automatic-update unit "+unit,
				fmt.Errorf("enablement state %q cannot be restored without changing related units", snapshot.enablement))
		}
		if unit == plan.profile.AutomaticTimer && isMaskedEnablement(snapshot.enablement) {
			return nil, failure("snapshot automatic-update unit "+unit,
				fmt.Errorf("selected automatic-update timer is %s; unmask it before installation", snapshot.enablement))
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func restorableAutomaticEnablement(enablement string) bool {
	switch enablement {
	case "disabled", "enabled", "enabled-runtime", "masked", "masked-runtime", "not-found", "static":
		return true
	default:
		return false
	}
}

func (i *Installer) snapshotUnit(ctx context.Context, unit string) (unitSnapshot, error) {
	enabled := i.runner.Run(ctx, Command{Name: "systemctl", Args: []string{"is-enabled", unit}, Timeout: 30 * time.Second})
	if enabled.Err != nil {
		return unitSnapshot{}, failure("snapshot automatic-update unit "+unit, enabled.Err)
	}
	enablement := strings.TrimSpace(string(enabled.Stdout))
	if !knownUnitEnablement[enablement] || strings.TrimSpace(string(enabled.Stderr)) != "" ||
		!unitEnablementExitStatusMatches(enablement, enabled.Code) {
		if i.confirmUnitNotFound(ctx, unit, enabled) {
			enablement = "not-found"
		} else {
			return unitSnapshot{}, failure("snapshot automatic-update unit "+unit,
				fmt.Errorf("invalid enablement result for state %q: %w", enablement, commandResultError(enabled)))
		}
	}
	activityResult := i.runner.Run(ctx, Command{Name: "systemctl", Args: []string{"is-active", unit}, Timeout: 30 * time.Second})
	if activityResult.Err != nil {
		return unitSnapshot{}, failure("snapshot automatic-update unit "+unit, activityResult.Err)
	}
	activity := strings.TrimSpace(string(activityResult.Stdout))
	if strings.TrimSpace(string(activityResult.Stderr)) != "" ||
		(activity != "active" && activity != "inactive") ||
		(activity == "active") != (activityResult.Code == 0) ||
		(activity == "inactive" && activityResult.Code != 3) {
		return unitSnapshot{}, failure("snapshot automatic-update unit "+unit,
			fmt.Errorf("activity state %q cannot be restored exactly: %w", activity, commandResultError(activityResult)))
	}
	return unitSnapshot{name: unit, active: activity == "active", enablement: enablement}, nil
}

func (i *Installer) confirmUnitNotFound(ctx context.Context, unit string, enabled CommandResult) bool {
	// Real systemctl writes the missing-unit diagnostic to stderr and leaves
	// is-enabled stdout empty. Confirm that one special case through the stable
	// LoadState property; all other stderr and exit-status mismatches remain fatal.
	if enabled.Code == 0 || strings.TrimSpace(string(enabled.Stdout)) != "" ||
		strings.TrimSpace(string(enabled.Stderr)) == "" {
		return false
	}
	load := i.runner.Run(ctx, Command{
		Name: "systemctl", Args: []string{"show", "--property=LoadState", "--value", unit}, Timeout: 30 * time.Second,
	})
	return load.Err == nil && load.Code == 0 && strings.TrimSpace(string(load.Stderr)) == "" &&
		strings.TrimSpace(string(load.Stdout)) == "not-found"
}

func unitEnablementExitStatusMatches(enablement string, code int) bool {
	switch enablement {
	case "enabled", "enabled-runtime", "static":
		return code == 0
	case "disabled", "masked", "masked-runtime", "not-found":
		return code != 0
	default:
		// Read-only or relationship-derived states are rejected by the caller
		// before mutation. Their exit codes vary across systemd releases.
		return true
	}
}

func (i *Installer) disableAutomaticTimerVariants(ctx context.Context, plan installPlan, snapshots []unitSnapshot) error {
	if len(plan.profile.AutomaticTimerVariants) == 0 {
		return nil
	}
	byName := make(map[string]unitSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		byName[snapshot.name] = snapshot
	}
	for _, unit := range plan.profile.AutomaticTimerVariants {
		before, ok := byName[unit]
		if !ok {
			return failure("disable conflicting automatic-update timer "+unit, errors.New("unit was not included in the transaction snapshot"))
		}
		var args []string
		switch before.enablement {
		case "enabled":
			args = []string{"disable", "--now", unit}
		case "enabled-runtime":
			args = []string{"disable", "--runtime", "--now", unit}
		default:
			if before.active {
				args = []string{"stop", unit}
			}
		}
		if len(args) > 0 {
			if err := i.requiredCommandContext(ctx, "disable conflicting automatic-update timer "+unit, Command{
				Name: "systemctl", Args: args, Timeout: 30 * time.Second,
			}); err != nil {
				return err
			}
		}
		after, err := i.snapshotUnit(ctx, unit)
		if err != nil {
			return err
		}
		if after.active || after.enablement == "enabled" || after.enablement == "enabled-runtime" {
			return failure("verify conflicting automatic-update timer "+unit, fmt.Errorf(
				"has enablement=%q active=%t after disable", after.enablement, after.active))
		}
	}
	return nil
}

func (i *Installer) quiesceAutomaticUnits(snapshots []unitSnapshot) error {
	for _, snapshot := range snapshots {
		if snapshot.enablement == "not-found" {
			continue
		}
		if err := i.requiredCommand("stop automatic-update unit during rollback", Command{
			Name: "systemctl", Args: []string{"stop", snapshot.name}, Timeout: 30 * time.Second,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) restoreAutomaticUnits(snapshots []unitSnapshot) error {
	for _, want := range snapshots {
		got, err := i.snapshotUnit(context.Background(), want.name)
		if err != nil {
			return err
		}
		if want.active && isMaskedEnablement(want.enablement) {
			if err := i.restoreMaskedActiveUnit(want, got); err != nil {
				return err
			}
		} else {
			if got.enablement != want.enablement {
				if err := i.restoreUnitEnablement(want, got); err != nil {
					return err
				}
			}
			got, err = i.snapshotUnit(context.Background(), want.name)
			if err != nil {
				return err
			}
			if got.active != want.active {
				action := "stop"
				if want.active {
					action = "start"
				}
				if err := i.requiredCommand("restore automatic-update unit activity", Command{
					Name: "systemctl", Args: []string{action, want.name}, Timeout: 30 * time.Second,
				}); err != nil {
					return err
				}
			}
		}
		got, err = i.snapshotUnit(context.Background(), want.name)
		if err != nil {
			return err
		}
		if got.enablement != want.enablement || got.active != want.active {
			return failure("verify automatic-update unit after rollback", fmt.Errorf(
				"%s has enablement=%q active=%t, want enablement=%q active=%t",
				want.name, got.enablement, got.active, want.enablement, want.active))
		}
	}
	return nil
}

func isMaskedEnablement(enablement string) bool {
	return enablement == "masked" || enablement == "masked-runtime"
}

func unmaskUnitArgs(enablement, unit string) []string {
	args := []string{"unmask"}
	if enablement == "masked-runtime" {
		args = append(args, "--runtime")
	}
	return append(args, unit)
}

func (i *Installer) restoreMaskedActiveUnit(want, got unitSnapshot) error {
	command := func(op string, args ...string) error {
		return i.requiredCommand(op, Command{Name: "systemctl", Args: args, Timeout: 30 * time.Second})
	}
	if isMaskedEnablement(got.enablement) {
		if err := command("unmask unit before restoring activity", unmaskUnitArgs(got.enablement, want.name)...); err != nil {
			return err
		}
	}
	if err := command("restore automatic-update unit activity before mask", "start", want.name); err != nil {
		return err
	}
	args := []string{"mask"}
	if want.enablement == "masked-runtime" {
		args = append(args, "--runtime")
	}
	return command("mask active automatic-update unit after rollback", append(args, want.name)...)
}

func (i *Installer) restoreProjectTimer(timer timerSnapshot) error {
	if !timer.active {
		return nil
	}
	if !restorableProjectTimerEnablement(timer.enablement) {
		return failure("restart timer after rollback", fmt.Errorf(
			"project timer enablement state %q was not rollback-safe", timer.enablement))
	}
	return i.requiredCommand("restart timer after rollback", Command{
		Name: "systemctl", Args: []string{"start", "security-update-notify.timer"}, Timeout: 30 * time.Second,
	})
}

func (i *Installer) restoreUnitEnablement(want, got unitSnapshot) error {
	command := func(op string, args ...string) error {
		return i.requiredCommand(op, Command{Name: "systemctl", Args: args, Timeout: 30 * time.Second})
	}
	switch want.enablement {
	case "disabled":
		return command("disable automatic-update unit after rollback", "disable", want.name)
	case "enabled", "enabled-runtime":
		if isMaskedEnablement(got.enablement) {
			if err := command("unmask automatic-update unit after rollback", unmaskUnitArgs(got.enablement, want.name)...); err != nil {
				return err
			}
		}
		if err := command("clear automatic-update unit enablement after rollback", "disable", want.name); err != nil {
			return err
		}
		args := []string{"enable"}
		if want.enablement == "enabled-runtime" {
			args = append(args, "--runtime")
		}
		return command("enable automatic-update unit after rollback", append(args, want.name)...)
	case "masked", "masked-runtime":
		if err := command("disable automatic-update unit before restoring mask", "disable", want.name); err != nil {
			return err
		}
		args := []string{"mask"}
		if want.enablement == "masked-runtime" {
			args = append(args, "--runtime")
		}
		return command("mask automatic-update unit after rollback", append(args, want.name)...)
	default:
		return failure("restore automatic-update unit enablement", fmt.Errorf(
			"cannot restore %s from %q to non-writable state %q", want.name, got.enablement, want.enablement))
	}
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

// installDependencies reports whether the package installation command was
// attempted. A non-zero package-manager result may still leave installed packages
// and their configuration behind, so callers must snapshot those side effects
// before rolling back SUN-owned files.
func (i *Installer) installDependencies(ctx context.Context, plan installPlan, confirm ConfirmDependenciesFunc) (bool, error) {
	profile := plan.profile
	if profile.Backend != plan.backend || profile.PackageProbe.Name == "" || len(profile.PackageManagers) == 0 {
		return false, failure("install dependencies", errors.New("distribution profile is incomplete"))
	}
	switch plan.backend {
	case "apt":
		if !i.runner.LookPath("apt-get") || !i.runner.LookPath("dpkg") {
			return false, failure("install dependencies", errors.New("apt-get and dpkg are required"))
		}
	case "dnf":
		if !i.runner.LookPath("rpm") {
			return false, failure("install dependencies", errors.New("rpm is required for the dnf backend"))
		}
	}
	packages := append([]string(nil), profile.Packages...)
	missing := make([]string, 0, len(packages))
	for _, pkg := range packages {
		args := append(append([]string(nil), profile.PackageProbe.Args...), pkg)
		result := i.runner.Run(ctx, Command{Name: profile.PackageProbe.Name, Args: args, Timeout: 30 * time.Second})
		installed := result.Err == nil && result.Code == 0
		if profile.PackageProbe.Name == "dpkg" {
			installed = installed && dpkgStatusInstalled(result.Stdout)
		}
		if !installed {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return false, nil
	}
	if confirm == nil {
		return false, failure("confirm dependency installation", errors.New("required packages are missing and no confirmation callback was provided"))
	}
	approved, err := confirm(ctx, DependencyRequest{Backend: plan.backend, Packages: append([]string(nil), missing...)})
	if err != nil {
		return false, failure("confirm dependency installation", err)
	}
	if !approved {
		return false, failure("confirm dependency installation", errors.New("required package installation was declined"))
	}
	if plan.backend == "apt" {
		manager := profile.PackageManagers[0]
		if err := i.requiredCommandContext(ctx, "update apt package lists", Command{Name: manager, Args: []string{"update"}, Timeout: 15 * time.Minute}); err != nil {
			return false, err
		}
		return true, i.requiredCommandContext(ctx, "install apt dependencies", Command{
			Name: manager, Args: append([]string{"install", "-y"}, missing...),
			Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}, Timeout: 30 * time.Minute,
		})
	}
	manager := ""
	for _, candidate := range profile.PackageManagers {
		if i.runner.LookPath(candidate) {
			manager = candidate
			break
		}
	}
	if manager == "" {
		return false, failure("install dependencies", errors.New("dnf, microdnf, or yum is required"))
	}
	return true, i.requiredCommandContext(ctx, "install dnf dependencies", Command{Name: manager, Args: append([]string{"install", "-y"}, missing...), Timeout: 30 * time.Minute})
}

func (i *Installer) verifyBackendCommands(ctx context.Context, plan installPlan) error {
	for _, command := range plan.profile.RequiredCommands {
		if !i.runner.LookPath(command) {
			return failure("verify backend readiness", fmt.Errorf("required command is unavailable: %s", command))
		}
	}
	probe := plan.profile.AutomaticProbe
	if probe.Name == "" || !i.runner.LookPath(probe.Name) {
		return failure("verify backend readiness", errors.New("automatic-update command is unavailable"))
	}
	return i.requiredCommandContext(ctx, "verify automatic-update command", Command{
		Name: probe.Name, Args: append([]string(nil), probe.Args...), Timeout: 30 * time.Second,
	})
}

func (i *Installer) verifyBackendPolicyFile(plan installPlan) error {
	if plan.profile.AutomaticConfig == "" {
		return failure("verify backend readiness", errors.New("automatic-update configuration path is unavailable"))
	}
	info, err := i.fs.Lstat(plan.profile.AutomaticConfig)
	if err != nil {
		return failure("verify automatic-update configuration", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 4<<20 {
		return failure("verify automatic-update configuration", errors.New("configuration must be a regular file no larger than 4 MiB"))
	}
	if plan.backend == "dnf" {
		data, _, err := i.fs.ReadRegularFile(plan.profile.AutomaticConfig, 4<<20)
		if err != nil {
			return failure("verify automatic-update configuration", err)
		}
		values, err := parseStrictINI(data)
		if err != nil {
			return failure("verify automatic-update configuration", err)
		}
		for key, want := range map[string]string{
			"commands.upgrade_type":  "security",
			"commands.apply_updates": "yes",
			"commands.reboot":        "never",
		} {
			if values[key] != want {
				return failure("verify automatic-update configuration", fmt.Errorf("%s must equal %s", key, want))
			}
		}
	}
	return nil
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
	return i.validAbsentMarkerAt(markerPath, aptAbsentMarkerContents, "apt")
}

func (i *Installer) validDNFAbsentMarkerAt(markerPath, engine string) (bool, error) {
	contents, err := dnfAbsentMarkerContentsFor(engine)
	if err != nil {
		return false, err
	}
	return i.validAbsentMarkerAt(markerPath, contents, "dnf")
}

func (i *Installer) validAbsentMarkerAt(markerPath, contents, backend string) (bool, error) {
	exists, err := i.validBaselineFile(markerPath)
	if err != nil || !exists {
		return exists, err
	}
	data, _, err := i.fs.ReadRegularFile(markerPath, 256)
	if err != nil {
		return false, err
	}
	if string(data) != contents {
		return false, fmt.Errorf("%s absence marker has invalid contents", backend)
	}
	return true, nil
}

func dnfAbsentMarkerContentsFor(engine string) (string, error) {
	switch engine {
	case osrel.EngineDNF4:
		return dnfAbsentMarkerContents, nil
	case osrel.EngineDNF5:
		return dnf5AbsentMarkerContents, nil
	default:
		return "", fmt.Errorf("unsupported DNF engine %q", engine)
	}
}

func (i *Installer) recordDNFAbsentBaseline(plan installPlan) error {
	if err := i.ensureDir(path.Dir(dnfAbsentMarkerPath), 0o755); err != nil {
		return failure("create dnf configuration directory", err)
	}
	contents, err := dnfAbsentMarkerContentsFor(plan.profile.Engine)
	if err != nil {
		return failure("record absent dnf automatic config", err)
	}
	stable, err := i.validBaselineFile(dnfStableBackupPath)
	if err != nil {
		return failure("inspect stable dnf backup", err)
	}
	marker, err := i.validDNFAbsentMarkerAt(dnfAbsentMarkerPath, plan.profile.Engine)
	if err != nil {
		return failure("inspect dnf absence marker", err)
	}
	if stable || marker {
		return nil
	}
	if err := i.fs.WriteFileAtomic(dnfAbsentMarkerPath, []byte(contents), 0o600); err != nil {
		return failure("record absent dnf automatic config", err)
	}
	return nil
}

// recordAPTDependencyProof binds a newly retained unattended-upgrades default
// to the package transaction that created it. A retry or immediate purge can
// then preserve the exact bytes without guessing from the file's presence.
func (i *Installer) recordAPTDependencyProof() error {
	exists, err := i.validBaselineFile(aptPeriodicPath)
	if err != nil {
		return failure("inspect partial apt dependency config", err)
	}
	if !exists {
		return nil
	}
	data, _, err := i.fs.ReadRegularFile(aptPeriodicPath, 4<<20)
	if err != nil {
		return failure("read partial apt dependency config", err)
	}
	matched, err := i.validAPTDependencyProof(data)
	if err != nil {
		return failure("inspect apt dependency proof", err)
	}
	if matched {
		return nil
	}
	if err := i.fs.WriteFileAtomic(aptDependencyProofPath, aptDependencyProofContents(data), 0o600); err != nil {
		return failure("record apt dependency proof", err)
	}
	return nil
}

func aptDependencyProofContents(data []byte) []byte {
	return dependencyproof.Contents("apt", data)
}

func (i *Installer) validAPTDependencyProof(config []byte) (bool, error) {
	info, err := i.fs.Lstat(aptDependencyProofPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 256 {
		return false, fmt.Errorf("%s must be a regular file no larger than 256 bytes", aptDependencyProofPath)
	}
	proof, _, err := i.fs.ReadRegularFile(aptDependencyProofPath, 256)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(proof, aptDependencyProofContents(config)) {
		return false, errors.New("apt dependency proof does not match 20auto-upgrades")
	}
	return true, nil
}

// persistAPTDependencyBaseline keeps the vendor periodic configuration created
// by the retained unattended-upgrades package. Current-file promotion requires
// either this transaction's provenance or a proof matching the exact content;
// older SUN installs can recover from their earliest non-SUN timestamp.
func (i *Installer) persistAPTDependencyBaseline(b *backup, configOriginallyAbsent, packageInstallAttempted bool) error {
	marker, err := i.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
	if err != nil {
		return failure("inspect apt absence marker after dependencies", err)
	}
	if !marker {
		return nil
	}
	configExists, err := i.validBaselineFile(aptPeriodicPath)
	if err != nil {
		return failure("inspect dependency-created apt periodic config", err)
	}
	stable, err := i.validBaselineFile(aptStableBackupPath)
	if err != nil {
		return failure("inspect stable apt backup after dependencies", err)
	}
	if !stable {
		baseline, err := i.oldestAPTProjectBackup(true)
		if err != nil {
			return failure("select original apt backup after dependencies", err)
		}
		if baseline == "" {
			if !configExists {
				proofExists, proofErr := i.validBaselineFile(aptDependencyProofPath)
				if proofErr != nil {
					return failure("inspect apt dependency proof", proofErr)
				}
				if proofExists {
					return failure("persist apt vendor baseline", errors.New("20auto-upgrades is missing but its dependency proof remains"))
				}
				return nil
			}
			data, _, err := i.fs.ReadRegularFile(aptPeriodicPath, 4<<20)
			if err != nil {
				return failure("read apt vendor baseline", err)
			}
			if !configOriginallyAbsent || !packageInstallAttempted {
				// A marker plus the exact SUN policy and no timestamp history is the
				// normal state when the package was already installed but this file was
				// absent. Keep the absence baseline for purge.
				if bytes.Equal(data, []byte(aptPeriodicConfig)) {
					return nil
				}
				proven, err := i.validAPTDependencyProof(data)
				if err != nil {
					return failure("validate apt dependency proof", err)
				}
				if !proven {
					return failure("persist apt vendor baseline", errors.New(
						"cannot prove that 20auto-upgrades is a retained dependency default; restore a trusted vendor baseline before retrying"))
				}
			}
			baseline = aptPeriodicPath
		}
		if err := i.copyNode(baseline, aptStableBackupPath); err != nil {
			return failure("persist apt vendor baseline", err)
		}
		if err := i.captureDependencyDefaults(b); err != nil {
			return err
		}
	}
	for _, metadata := range []struct {
		path string
		op   string
	}{
		{path: aptAbsentMarkerPath, op: "replace apt absence marker with vendor baseline"},
		{path: aptLegacyAbsentPath, op: "remove superseded legacy apt absence marker"},
		{path: aptDependencyProofPath, op: "remove promoted apt dependency proof"},
	} {
		if err := i.fs.Remove(metadata.path); err != nil {
			return failure(metadata.op, err)
		}
		if err := i.keepPathAbsentOnRollback(b, metadata.path); err != nil {
			return err
		}
	}
	return nil
}

// recordDNF4DependencyProof binds a retained configuration to the DNF4 package
// transaction that created it. A retry can then promote the exact bytes
// without inferring provenance from INI values.
func (i *Installer) recordDNF4DependencyProof(plan installPlan) error {
	if plan.profile.Engine != osrel.EngineDNF4 {
		return nil
	}
	exists, err := i.validBaselineFile(dnfAutomaticPath)
	if err != nil {
		return failure("inspect partial dnf dependency config", err)
	}
	if !exists {
		return nil
	}
	data, _, err := i.fs.ReadRegularFile(dnfAutomaticPath, 4<<20)
	if err != nil {
		return failure("read partial dnf dependency config", err)
	}
	if _, err := parseStrictINI(data); err != nil {
		return failure("validate partial dnf dependency config", err)
	}
	matched, err := i.validDNFDependencyProof(data)
	if err != nil {
		return failure("inspect dnf dependency proof", err)
	}
	if matched {
		return nil
	}
	if err := i.fs.WriteFileAtomic(dnfDependencyProofPath, dnfDependencyProofContents(data), 0o600); err != nil {
		return failure("record dnf dependency proof", err)
	}
	return nil
}

func dnfDependencyProofContents(data []byte) []byte {
	return dnfconfig.DependencyDefaultProof(data)
}

func (i *Installer) validDNFDependencyProof(config []byte) (bool, error) {
	info, err := i.fs.Lstat(dnfDependencyProofPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 256 {
		return false, fmt.Errorf("%s must be a regular file no larger than 256 bytes", dnfDependencyProofPath)
	}
	proof, _, err := i.fs.ReadRegularFile(dnfDependencyProofPath, 256)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(proof, dnfDependencyProofContents(config)) {
		return false, errors.New("dnf dependency proof does not match automatic.conf")
	}
	return true, nil
}

// persistDNF4DependencyBaseline keeps the vendor configuration created by the
// retained dnf-automatic package. Older SUN installations can already have an
// absence marker beside a managed current file; their earliest timestamped
// backup is the only safe source because the current file is no longer vendor
// state. DNF5 intentionally keeps its absence marker and packaged fallback.
func (i *Installer) persistDNF4DependencyBaseline(plan installPlan, b *backup, configOriginallyAbsent bool) error {
	if plan.profile.Engine != osrel.EngineDNF4 {
		return nil
	}
	marker, err := i.validDNFAbsentMarkerAt(dnfAbsentMarkerPath, plan.profile.Engine)
	if err != nil {
		return failure("inspect dnf absence marker after dependencies", err)
	}
	if !marker {
		return nil
	}
	configExists, err := i.validBaselineFile(dnfAutomaticPath)
	if err != nil {
		return failure("inspect dependency-created dnf automatic config", err)
	}
	stable, err := i.validBaselineFile(dnfStableBackupPath)
	if err != nil {
		return failure("inspect stable dnf backup after dependencies", err)
	}
	if !stable {
		baseline, err := i.oldestDNFProjectBackup()
		if err != nil {
			return failure("select original dnf backup after dependencies", err)
		}
		if baseline == "" {
			if !configExists {
				return failure("persist dnf vendor baseline", errors.New(
					"/etc/dnf/automatic.conf is missing after dependency verification; purge the incomplete SUN metadata, then reinstall dnf-automatic or restore a trusted vendor baseline before retrying"))
			}
			baseline = dnfAutomaticPath
		}
		data, _, err := i.fs.ReadRegularFile(baseline, 4<<20)
		if err != nil {
			return failure("read dnf vendor baseline", err)
		}
		if _, err := parseStrictINI(data); err != nil {
			return failure("validate dnf vendor baseline", err)
		}
		if baseline == dnfAutomaticPath && !configOriginallyAbsent {
			proven, err := i.validDNFDependencyProof(data)
			if err != nil {
				return failure("validate dnf dependency proof", err)
			}
			if !proven {
				return failure("persist dnf vendor baseline", errors.New(
					"cannot prove that /etc/dnf/automatic.conf is a retained dependency default; restore a trusted vendor baseline before retrying"))
			}
		}
		if err := i.copyNode(baseline, dnfStableBackupPath); err != nil {
			return failure("persist dnf vendor baseline", err)
		}
		// The stable file did not exist in the pre-install snapshot. Capture it
		// now so a later SUN failure keeps the retained package usable.
		if err := i.captureDependencyDefaults(b); err != nil {
			return err
		}
	}
	for _, metadata := range []struct {
		path string
		op   string
	}{
		{path: dnfAbsentMarkerPath, op: "replace dnf absence marker with vendor baseline"},
		{path: dnfDependencyProofPath, op: "remove promoted dnf dependency proof"},
	} {
		if err := i.fs.Remove(metadata.path); err != nil {
			return failure(metadata.op, err)
		}
		if err := i.keepPathAbsentOnRollback(b, metadata.path); err != nil {
			return err
		}
	}
	return nil
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

func (i *Installer) installFiles(ctx context.Context, plan installPlan, options Options, secret []byte, b *backup) (string, error) {
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
	if err := i.installBackendPolicy(plan, payload, b); err != nil {
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

func (i *Installer) installBackendPolicy(plan installPlan, payload Payload, b *backup) error {
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
			if err := i.snapshotAdditionalPath(b, timestampBackup); err != nil {
				return err
			}
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
				baseline, err := i.oldestAPTProjectBackup(false)
				if err != nil {
					return failure("select original apt backup", err)
				}
				if baseline == "" {
					baseline = aptPeriodicPath
				}
				if err := i.copyNode(baseline, aptStableBackupPath); err != nil {
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
	if err := i.ensureDir(path.Dir(automatic), 0o755); err != nil {
		return failure("create dnf configuration directory", err)
	}
	marker, err := i.validDNFAbsentMarkerAt(dnfAbsentMarkerPath, plan.profile.Engine)
	if err != nil {
		return failure("inspect dnf absence marker", err)
	}
	stable, err := i.validBaselineFile(dnfStableBackupPath)
	if err != nil {
		return failure("inspect stable dnf backup", err)
	}
	var data []byte
	if !exists && stable {
		data, _, err = i.fs.ReadRegularFile(dnfStableBackupPath, 4<<20)
		if err != nil {
			return failure("read stable dnf backup", err)
		}
		if _, err := parseStrictINI(data); err != nil {
			return failure("validate stable dnf backup", err)
		}
	}
	if exists {
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
		data, _, err = i.fs.ReadRegularFile(automatic, 4<<20)
		if err != nil {
			return failure("read dnf automatic config", err)
		}
		// Validate before creating any persistent baseline or timestamp. Otherwise a failed first
		// install can leave a malformed timestamp that a later retry mistakes for the original baseline.
		if _, err := parseStrictINI(data); err != nil {
			return failure("validate dnf automatic config", err)
		}
		if !stable && !marker {
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
		timestampBackup := automatic + ".security-update-notify.bak." + stamp
		if err := i.snapshotAdditionalPath(b, timestampBackup); err != nil {
			return err
		}
		if err := i.copyNode(automatic, timestampBackup); err != nil {
			return failure("backup dnf automatic config", err)
		}
	}
	for _, setting := range [][3]string{
		{"commands", "upgrade_type", "security"},
		{"commands", "apply_updates", "yes"},
		{"commands", "reboot", "never"},
		{"emitters", "emit_via", "stdio"},
		{"base", "debuglevel", "1"},
	} {
		data = setINI(data, setting[0], setting[1], setting[2])
	}
	if _, err := parseStrictINI(data); err != nil {
		return failure("validate managed dnf automatic config", err)
	}
	if err := i.fs.WriteFileAtomic(automatic, data, 0o644); err != nil {
		return failure("install dnf automatic policy", err)
	}
	return nil
}

func (i *Installer) oldestAPTProjectBackup(skipManagedPolicy bool) (string, error) {
	entries, err := i.fs.ReadDir(path.Dir(aptPeriodicPath))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	prefix := path.Base(aptPeriodicPath) + ".security-update-notify."
	suffix := ".bak"
	oldest := ""
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
		if !validBackupTimestamp(stamp) {
			continue
		}
		candidate := path.Join(path.Dir(aptPeriodicPath), name)
		info, err := i.fs.Lstat(candidate)
		if err != nil {
			return "", err
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 4<<20 {
			return "", fmt.Errorf("%s must be a regular file no larger than 4 MiB", candidate)
		}
		if skipManagedPolicy {
			data, _, err := i.fs.ReadRegularFile(candidate, 4<<20)
			if err != nil {
				return "", err
			}
			if bytes.Equal(data, []byte(aptPeriodicConfig)) {
				continue
			}
		}
		if oldest == "" || candidate < oldest {
			oldest = candidate
		}
	}
	return oldest, nil
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
			inSection = strings.EqualFold(trimmed, "["+section+"]")
			seenSection = seenSection || inSection
			output = append(output, line)
			continue
		}
		lineKey := ""
		if before, _, ok := strings.Cut(trimmed, "="); ok {
			lineKey = strings.TrimSpace(before)
		}
		if inSection && strings.EqualFold(lineKey, key) {
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

func parseStrictINI(data []byte) (map[string]string, error) {
	return dnfconfig.ParseStrict(data)
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
