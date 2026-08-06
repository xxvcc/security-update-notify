package installer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"strings"

	"time"
)

// installDependencies reports whether the package installation command was
// attempted. A non-zero package-manager result may still leave installed packages
// and their configuration behind, so callers must snapshot those side effects
// before rolling back SUN-owned files.
func (i *Installer) installDependencies(ctx context.Context, plan installPlan, confirm ConfirmDependenciesFunc, beforeMutation func() error) (bool, error) {
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
		installed := !commandResultIncomplete(result) && result.Err == nil && result.Code == 0
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
	manager := profile.PackageManagers[0]
	if plan.backend == "dnf" {
		manager = ""
		for _, candidate := range profile.PackageManagers {
			if i.runner.LookPath(candidate) {
				manager = candidate
				break
			}
		}
		if manager == "" {
			return false, failure("install dependencies", errors.New("dnf, microdnf, or yum is required"))
		}
	}
	if beforeMutation == nil {
		return false, failure("prepare dependency installation", errors.New("transaction phase callback is required"))
	}
	if err := beforeMutation(); err != nil {
		return false, err
	}
	if plan.backend == "apt" {
		if err := i.requiredCommandContext(ctx, "update apt package lists", Command{Name: manager, Args: []string{"update"}, Timeout: 15 * time.Minute}); err != nil {
			return false, err
		}
		return true, i.requiredCommandContext(ctx, "install apt dependencies", Command{
			Name: manager, Args: append([]string{"install", "-y"}, missing...),
			Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}, Timeout: 30 * time.Minute,
		})
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
	data, exists, err := i.readTrustedRegularFile(plan.profile.AutomaticConfig, 4<<20)
	if err != nil {
		return failure("verify automatic-update configuration", err)
	}
	if !exists {
		return failure("verify automatic-update configuration", fs.ErrNotExist)
	}
	if plan.backend == "dnf" {
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
