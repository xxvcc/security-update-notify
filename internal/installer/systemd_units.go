package installer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"strings"

	"time"
)

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

func (i *Installer) requireSystemd() error {
	info, err := i.fs.Lstat("/run/systemd/system")
	if err != nil {
		return failure("detect systemd", errors.New("systemd is required; /run/systemd/system is unavailable"))
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return failure("detect systemd", errors.New("/run/systemd/system must be a real directory"))
	}
	if err := i.validateTrustedDirectory("/run/systemd/system", info); err != nil {
		return failure("detect systemd", err)
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
	if enabled.Err != nil || commandResultIncomplete(enabled) {
		return unitSnapshot{}, failure("snapshot automatic-update unit "+unit, commandResultError(enabled))
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
	if activityResult.Err != nil || commandResultIncomplete(activityResult) {
		return unitSnapshot{}, failure("snapshot automatic-update unit "+unit, commandResultError(activityResult))
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
	if commandResultIncomplete(enabled) || enabled.Code == 0 || strings.TrimSpace(string(enabled.Stdout)) != "" ||
		strings.TrimSpace(string(enabled.Stderr)) == "" {
		return false
	}
	load := i.runner.Run(ctx, Command{
		Name: "systemctl", Args: []string{"show", "--property=LoadState", "--value", unit}, Timeout: 30 * time.Second,
	})
	return !commandResultIncomplete(load) && load.Err == nil && load.Code == 0 && strings.TrimSpace(string(load.Stderr)) == "" &&
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
	var errs []error
	for _, snapshot := range snapshots {
		if snapshot.enablement == "not-found" {
			continue
		}
		if err := i.requiredCommand("stop automatic-update unit during rollback: "+snapshot.name, Command{
			Name: "systemctl", Args: []string{"stop", snapshot.name}, Timeout: 30 * time.Second,
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (i *Installer) containIncompleteRollback(snapshots []unitSnapshot) error {
	var errs []error
	for _, args := range [][]string{
		{"disable", "--now", "security-update-notify.timer"},
		{"disable", "--runtime", "security-update-notify.timer"},
	} {
		if err := i.requiredCommand("disable project timer after incomplete rollback", Command{
			Name: "systemctl", Args: args, Timeout: 30 * time.Second,
		}); err != nil {
			errs = append(errs, err)
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.enablement == "not-found" {
			continue
		}
		for _, args := range [][]string{
			{"disable", "--now", snapshot.name},
			{"disable", "--runtime", snapshot.name},
		} {
			if err := i.requiredCommand("disable automatic-update unit after incomplete rollback: "+snapshot.name, Command{
				Name: "systemctl", Args: args, Timeout: 30 * time.Second,
			}); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (i *Installer) restoreAutomaticUnits(snapshots []unitSnapshot) error {
	var errs []error
	for _, want := range snapshots {
		if err := i.restoreAutomaticUnit(want); err != nil {
			errs = append(errs, fmt.Errorf("restore automatic-update unit %s: %w", want.name, err))
		}
	}
	return errors.Join(errs...)
}

func (i *Installer) restoreAutomaticUnit(want unitSnapshot) error {
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

func (i *Installer) acquireRuntimeLock(ctx context.Context, wait time.Duration) (UnlockFunc, error) {
	unlock, err := i.locker.Acquire(ctx, RuntimeLockPath, wait)
	if err == nil {
		return unlock, nil
	}
	if errors.Is(err, ErrLockBusy) || errors.Is(err, context.DeadlineExceeded) {
		return nil, temporary("quiesce runtime", errors.New("timed out waiting for the existing security-update-notify run"))
	}
	return nil, failure("acquire runtime lock", err)
}

func (i *Installer) quiesceExisting(ctx context.Context, upgrade bool) error {
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

func (i *Installer) quiesceForRollback(timer timerSnapshot) error {
	var errs []error
	hasTimer := timer.active
	for _, name := range []string{TimerPath, PersistentTimerLink, RuntimeTimerLink} {
		exists, err := i.exists(name)
		if err != nil {
			errs = append(errs, failure("inspect timer during rollback: "+name, err))
			continue
		}
		hasTimer = hasTimer || exists
	}
	if hasTimer {
		if err := i.requiredCommand("disable timer during rollback", Command{Name: "systemctl", Args: []string{"disable", "--now", "security-update-notify.timer"}, Timeout: 30 * time.Second}); err != nil {
			errs = append(errs, err)
		}
	}
	serviceExists, err := i.exists(ServicePath)
	if err != nil {
		errs = append(errs, failure("inspect service during rollback", err))
	} else if serviceExists {
		if err := i.requiredCommand("stop service during rollback", Command{Name: "systemctl", Args: []string{"stop", "security-update-notify.service"}, Timeout: 30 * time.Second}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
