package backend

import (
	"fmt"
	"sort"
	"strings"
)

// ParseDNF4CheckUpgrades reads check-update's locale-C candidate table. Unlike
// updateinfo, check-update explicitly enables the versionlock plugin's filters.
func ParseDNF4CheckUpgrades(output string) ([]DNF5Upgrade, error) {
	byKey := make(map[string]DNF5Upgrade)
	obsoleting := false
	wrappedName := ""
	wrappedIndented := false
	for number, raw := range splitLines(output) {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "Obsoleting Packages" && !obsoleting && wrappedName == "" {
			obsoleting = true
			continue
		}
		fields := strings.Fields(line)
		indented := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		if wrappedName != "" {
			fields = append([]string{wrappedName}, fields...)
			indented = wrappedIndented
			wrappedName = ""
		} else if len(fields) == 1 && archRe.MatchString(fields[0]) {
			wrappedName = fields[0]
			wrappedIndented = indented
			continue
		}
		if len(fields) != 3 || !archRe.MatchString(fields[0]) {
			return nil, fmt.Errorf("invalid dnf4 check-update row on line %d", number+1)
		}
		idx := strings.LastIndexByte(fields[0], '.')
		candidate := DNF5Upgrade{Key: fields[0], NEVRA: fields[0][:idx] + "-" + fields[1] + fields[0][idx:]}
		if dnf5PackageKey(candidate.NEVRA) != candidate.Key {
			return nil, fmt.Errorf("invalid dnf4 check-update package on line %d", number+1)
		}
		if strings.HasPrefix(fields[2], "@") {
			if !obsoleting || !indented {
				return nil, fmt.Errorf("unexpected installed dnf4 package on line %d", number+1)
			}
			continue
		}
		if previous, exists := byKey[candidate.Key]; exists && (!obsoleting || previous != candidate) {
			return nil, fmt.Errorf("duplicate dnf4 check-update package %q", candidate.Key)
		}
		byKey[candidate.Key] = candidate
	}
	if wrappedName != "" || obsoleting && len(byKey) == 0 {
		return nil, fmt.Errorf("incomplete dnf4 check-update output")
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]DNF5Upgrade, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result, nil
}

// BlockedDNF4 compares versionlock-aware candidates with unrestricted security
// advisories. EVR coverage avoids flagging a newer eligible build as blocked.
func BlockedDNF4(advisoryOutput, restrictedOutput, unrestrictedOutput string) ([]string, error) {
	var advisories []DNF5Advisory
	for number, line := range splitLines(advisoryOutput) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 || !validDNF5AdvisoryName(fields[0]) || dnf5PackageKey(fields[2]) == "" {
			return nil, fmt.Errorf("invalid dnf4 security advisory on line %d", number+1)
		}
		switch fields[1] {
		case "Critical/Sec.", "Important/Sec.", "Moderate/Sec.", "Low/Sec.", "Unknown/Sec.":
		default:
			return nil, fmt.Errorf("invalid dnf4 security advisory severity on line %d", number+1)
		}
		advisories = append(advisories, DNF5Advisory{Name: fields[0], NEVRA: fields[2]})
	}
	restricted, err := ParseDNF4CheckUpgrades(restrictedOutput)
	if err != nil {
		return nil, err
	}
	unrestricted, err := ParseDNF4CheckUpgrades(unrestrictedOutput)
	if err != nil {
		return nil, err
	}
	// DNF4's available advisories also include the running kernel, even when a
	// fixed kernel is already installed. Only an unrestricted upgrade candidate
	// proves that versionlock/excludes could be preventing this advisory's fix.
	unrestrictedEVRs := make(map[string]string, len(unrestricted))
	for _, candidate := range unrestricted {
		key, evr, _ := parseDNF5NEVRA(candidate.NEVRA)
		unrestrictedEVRs[key] = evr
	}
	applicable := make([]DNF5Advisory, 0, len(advisories))
	covered := make(map[string]bool)
	for _, advisory := range advisories {
		key, evr, _ := parseDNF5NEVRA(advisory.NEVRA)
		candidate, exists := unrestrictedEVRs[key]
		if !exists {
			continue
		}
		comparison, err := rpmEVRCompare(evr, candidate)
		if err != nil {
			return nil, err
		}
		if comparison <= 0 {
			applicable = append(applicable, advisory)
			covered[key] = true
		}
	}
	for _, candidate := range append(append([]DNF5Upgrade(nil), unrestricted...), restricted...) {
		if !covered[candidate.Key] {
			return nil, fmt.Errorf("dnf4 security candidate %q has no corresponding advisory", candidate.Key)
		}
	}
	return blockedDNFAdvisories(applicable, restricted, unrestricted)
}
