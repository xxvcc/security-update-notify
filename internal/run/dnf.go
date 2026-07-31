package run

import (
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

// dnfRuntime keeps BACKEND=dnf stable while selecting the installed command generation internally.
type dnfRuntime struct {
	Command         string
	Generation      backend.DNFGeneration
	GenerationKnown bool
	Available       bool
}

func detectDNFRuntime(timeout time.Duration) dnfRuntime {
	runtime := dnfRuntime{Command: "dnf", Generation: backend.DNF4}
	for _, candidate := range []string{"dnf", "dnf5", "yum"} {
		if !sysexec.Look(candidate) {
			continue
		}
		if !runtime.Available {
			runtime.Command = candidate
			runtime.Available = true
		}
		if generation, known := backend.ProbeDNFGeneration(candidate, ""); known {
			return dnfRuntime{Command: candidate, Generation: generation, GenerationKnown: true, Available: true}
		}
		version := sysexec.RunTimeout(timeout, candidate, "--version")
		if version.Err != nil || version.Code != 0 || version.StdoutTruncated || version.StderrTruncated {
			continue
		}
		if generation, known := backend.ProbeDNFGeneration(candidate, version.Stdout+version.Stderr); known {
			return dnfRuntime{Command: candidate, Generation: generation, GenerationKnown: true, Available: true}
		}
	}
	return runtime
}

func (runtime dnfRuntime) isDNF5() bool {
	return runtime.GenerationKnown && runtime.Generation == backend.DNF5
}

func (runtime dnfRuntime) advisoryArgs(unrestricted bool) []string {
	if !runtime.isDNF5() {
		args := []string{"-q"}
		if unrestricted {
			args = append(args, "--disableplugin=versionlock", "--disableexcludes=all")
		}
		return append(args, "updateinfo", "list", "security")
	}
	args := []string{"-q"}
	if unrestricted {
		// DNF5 has no --disableexcludes. Clear main and per-repository aliases; advisory queries
		// deliberately ignore versionlock, so no plugin/config mutation is needed.
		args = append(args, "--setopt=exclude=", "--setopt=excludepkgs=", "--setopt=*.excludepkgs=")
	}
	return append(args, "advisory", "list", "--security", "--updates", "--json")
}

func (runtime dnfRuntime) checkUpgradeArgs(unrestricted bool) []string {
	args := []string{"-q"}
	if unrestricted {
		// DNF5 implements versionlock inside PackageSack filtering rather than as a
		// plugin. This per-query option bypasses every exclude source without changing
		// versionlock.toml or persistent DNF configuration.
		args = append(args, "--setopt=disable_excludes=*")
	}
	return append(args, "check-upgrade", "--security")
}

type dnfAutomaticUnit struct {
	Timer   string
	Service string
	Enabled bool
}

// selectDNFAutomaticUnit prefers DNF5's native unit, accepts the compatibility alias shipped by
// Fedora, and falls back to the native name in diagnostics when neither is enabled.
func selectDNFAutomaticUnit(generation backend.DNFGeneration, isEnabled func(string) bool) dnfAutomaticUnit {
	if generation == backend.DNF5 {
		if isEnabled("dnf5-automatic.timer") {
			return dnfAutomaticUnit{Timer: "dnf5-automatic.timer", Service: "dnf5-automatic.service", Enabled: true}
		}
		if isEnabled("dnf-automatic.timer") {
			return dnfAutomaticUnit{Timer: "dnf-automatic.timer", Service: "dnf-automatic.service", Enabled: true}
		}
		return dnfAutomaticUnit{Timer: "dnf5-automatic.timer", Service: "dnf5-automatic.service"}
	}
	return dnfAutomaticUnit{
		Timer:   "dnf-automatic.timer",
		Service: "dnf-automatic.service",
		Enabled: isEnabled("dnf-automatic.timer"),
	}
}

func rewriteDNFHealthUnitNames(text string, unit dnfAutomaticUnit) string {
	if unit.Timer == "dnf-automatic.timer" {
		return text
	}
	text = strings.ReplaceAll(text, "dnf-automatic.timer", unit.Timer)
	return strings.ReplaceAll(text, "dnf-automatic.service", unit.Service)
}
