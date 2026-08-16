package backend

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DNFGeneration distinguishes the two command-line interfaces hidden behind the public BACKEND=dnf.
type DNFGeneration uint8

const (
	DNF4 DNFGeneration = iota
	DNF5

	maxDNF5AdvisoryNameBytes = 256
)

var (
	dnf4VersionRe           = regexp.MustCompile(`^4(?:\.[0-9]+)+$`)
	dnf5VersionRe           = regexp.MustCompile(`(?i)^dnf5 version 5(?:\.[0-9]+)+$`)
	dnf5NoSecurityUpdatesRe = regexp.MustCompile(`^No security updates needed, but [0-9]+ update\(s\) available$`)
)

// ProbeDNFGeneration identifies an installed DNF command only from unambiguous command or version
// output. The boolean is false when callers must not assume either command-line generation.
func ProbeDNFGeneration(command, versionOutput string) (DNFGeneration, bool) {
	base := command
	if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
		base = base[idx+1:]
	}
	if base == "dnf5" {
		return DNF5, true
	}
	first, _, _ := strings.Cut(strings.TrimSpace(versionOutput), "\n")
	first = strings.TrimSpace(first)
	if dnf5VersionRe.MatchString(first) {
		return DNF5, true
	}
	if dnf4VersionRe.MatchString(first) {
		return DNF4, true
	}
	return DNF4, false
}

// DetectDNFGeneration preserves the original compatibility API. Runtime command execution must use
// ProbeDNFGeneration and honor its known result instead of treating this fallback as evidence of DNF4.
func DetectDNFGeneration(command, versionOutput string) DNFGeneration {
	generation, _ := ProbeDNFGeneration(command, versionOutput)
	return generation
}

// DNF5Advisory is the stable subset of `dnf5 advisory list --json` consumed by the watchdog.
type DNF5Advisory struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	NEVRA    string `json:"nevra"`
}

// DNF5Upgrade is one transaction-eligible package from `dnf5 check-upgrade --security`.
type DNF5Upgrade struct {
	Key   string // name.arch
	NEVRA string
}

// ParseDNF5Advisories validates DNF5's structured advisory output. A malformed security entry is an
// error rather than an empty result so repository/output changes cannot become a false green status.
func ParseDNF5Advisories(output string) ([]DNF5Advisory, error) {
	if !utf8.ValidString(output) {
		return nil, fmt.Errorf("parse dnf5 advisory JSON: input is not valid UTF-8")
	}
	var all []DNF5Advisory
	if err := json.Unmarshal([]byte(output), &all); err != nil {
		return nil, fmt.Errorf("parse dnf5 advisory JSON: %w", err)
	}
	if all == nil {
		return nil, fmt.Errorf("parse dnf5 advisory JSON: root must be an array")
	}
	out := make([]DNF5Advisory, 0, len(all))
	for _, advisory := range all {
		kind := strings.ToLower(advisory.Type)
		if !validDNF5AdvisoryName(advisory.Name) || kind == "" || !validDNF5Severity(advisory.Severity) || dnf5PackageKey(advisory.NEVRA) == "" {
			return nil, fmt.Errorf("invalid dnf5 advisory entry")
		}
		switch kind {
		case "security", "bugfix", "enhancement", "newpackage":
		default:
			return nil, fmt.Errorf("unknown dnf5 advisory type %q", advisory.Type)
		}
		if !strings.EqualFold(advisory.Type, "security") {
			continue
		}
		out = append(out, advisory)
	}
	return out, nil
}

// ParseDNF5CheckUpgrades strictly parses the quiet, locale-C output emitted by DNF5. Fedora 43 omits
// the table heading, Fedora 44 includes section headings, and exit status 0 can carry a precise
// informational line when only non-security updates exist. Obsoleting package children are installed
// packages, not transaction candidates. Unknown lines are errors so output drift cannot hide packages.
func ParseDNF5CheckUpgrades(output string) ([]DNF5Upgrade, error) {
	trimmedOutput := strings.TrimSpace(output)
	if trimmedOutput == "" || dnf5NoSecurityUpdatesRe.MatchString(trimmedOutput) {
		return []DNF5Upgrade{}, nil
	}
	type section uint8
	const (
		sectionUpgrades section = iota
		sectionObsoleting
	)
	byKey := make(map[string]DNF5Upgrade)
	obsoletingParents := make(map[string]bool)
	current := sectionUpgrades
	seenUpgradesHeading := false
	seenObsoletingHeading := false
	seenRow := false
	haveObsoletingParent := false
	haveObsoletingChild := false
	for number, rawLine := range splitLines(output) {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		switch line {
		case "Upgrades":
			if seenUpgradesHeading || seenObsoletingHeading || seenRow {
				return nil, fmt.Errorf("invalid dnf5 check-upgrade heading on line %d", number+1)
			}
			seenUpgradesHeading = true
			current = sectionUpgrades
			continue
		case "Obsoleting packages":
			if seenObsoletingHeading {
				return nil, fmt.Errorf("invalid dnf5 check-upgrade heading on line %d", number+1)
			}
			seenObsoletingHeading = true
			current = sectionObsoleting
			haveObsoletingParent = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || !archRe.MatchString(fields[0]) {
			return nil, fmt.Errorf("invalid dnf5 check-upgrade row on line %d", number+1)
		}
		indented := len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t')
		if indented {
			if current != sectionObsoleting || !haveObsoletingParent {
				return nil, fmt.Errorf("unexpected indented dnf5 check-upgrade row on line %d", number+1)
			}
			if fields[2] != "@System" {
				return nil, fmt.Errorf("invalid obsoleted dnf5 package source on line %d", number+1)
			}
			idx := strings.LastIndexByte(fields[0], '.')
			if idx <= 0 || idx == len(fields[0])-1 {
				return nil, fmt.Errorf("invalid obsoleted dnf5 package key on line %d", number+1)
			}
			name, arch := fields[0][:idx], fields[0][idx+1:]
			if dnf5PackageKey(name+"-"+fields[1]+"."+arch) != fields[0] {
				return nil, fmt.Errorf("invalid obsoleted dnf5 package EVR on line %d", number+1)
			}
			haveObsoletingChild = true
			continue
		}
		if current == sectionObsoleting && haveObsoletingParent && !haveObsoletingChild {
			return nil, fmt.Errorf("dnf5 obsoleting package has no installed child on line %d", number+1)
		}
		idx := strings.LastIndexByte(fields[0], '.')
		if idx <= 0 || idx == len(fields[0])-1 {
			return nil, fmt.Errorf("invalid dnf5 package key on line %d", number+1)
		}
		name, arch := fields[0][:idx], fields[0][idx+1:]
		upgrade := DNF5Upgrade{
			Key:   fields[0],
			NEVRA: name + "-" + fields[1] + "." + arch,
		}
		if dnf5PackageKey(upgrade.NEVRA) != upgrade.Key {
			return nil, fmt.Errorf("invalid dnf5 package EVR on line %d", number+1)
		}
		if current == sectionObsoleting {
			previous, present := byKey[upgrade.Key]
			if !present || previous.NEVRA != upgrade.NEVRA || obsoletingParents[upgrade.Key] {
				return nil, fmt.Errorf("duplicate dnf5 check-upgrade package %q", upgrade.Key)
			}
			obsoletingParents[upgrade.Key] = true
		} else {
			if _, duplicate := byKey[upgrade.Key]; duplicate {
				return nil, fmt.Errorf("duplicate dnf5 check-upgrade package %q", upgrade.Key)
			}
			byKey[upgrade.Key] = upgrade
		}
		haveObsoletingParent = current == sectionObsoleting
		haveObsoletingChild = false
		seenRow = true
	}
	if current == sectionObsoleting && haveObsoletingParent && !haveObsoletingChild {
		return nil, fmt.Errorf("dnf5 obsoleting package has no installed child")
	}
	if !seenRow || len(byKey) == 0 {
		return nil, fmt.Errorf("dnf5 check-upgrade output contained no package rows")
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]DNF5Upgrade, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out, nil
}

// NormalizeDNF5Pending joins advisory severity metadata with the transaction-eligible package set.
// The result intentionally resembles DNF4 updateinfo output so watchdog.CollectPending can consume it.
func NormalizeDNF5Pending(advisoryJSON, checkUpgradeOutput string) (string, error) {
	advisories, err := ParseDNF5Advisories(advisoryJSON)
	if err != nil {
		return "", err
	}
	upgrades, err := ParseDNF5CheckUpgrades(checkUpgradeOutput)
	if err != nil {
		return "", err
	}
	advisoriesByKey := make(map[string][]DNF5Advisory)
	for _, advisory := range advisories {
		key := dnf5PackageKey(advisory.NEVRA)
		advisoriesByKey[key] = append(advisoriesByKey[key], advisory)
	}
	var lines []string
	for _, upgrade := range upgrades {
		_, upgradeEVR, ok := parseDNF5NEVRA(upgrade.NEVRA)
		if !ok {
			return "", fmt.Errorf("invalid dnf5 transaction NEVRA %q", upgrade.NEVRA)
		}
		candidates := make([]DNF5Advisory, 0, len(advisoriesByKey[upgrade.Key]))
		for _, advisory := range advisoriesByKey[upgrade.Key] {
			_, advisoryEVR, parsed := parseDNF5NEVRA(advisory.NEVRA)
			if !parsed {
				return "", fmt.Errorf("invalid dnf5 advisory NEVRA %q", advisory.NEVRA)
			}
			comparison, compareErr := rpmEVRCompare(advisoryEVR, upgradeEVR)
			if compareErr != nil {
				return "", fmt.Errorf("compare dnf5 advisory EVR: %w", compareErr)
			}
			if comparison <= 0 {
				candidates = append(candidates, advisory)
			}
		}
		if len(candidates) == 0 {
			return "", fmt.Errorf("dnf5 security transaction package %q has no covered advisory", upgrade.Key)
		}
		selected := candidates[0]
		for _, advisory := range candidates[1:] {
			if dnf5AdvisoryPreferred(advisory, selected) {
				selected = advisory
			}
		}
		lines = append(lines, selected.Name+" "+selected.Severity+"/Sec. "+upgrade.NEVRA)
	}
	return strings.Join(lines, "\n"), nil
}

// NormalizeDNF5Advisories is the conservative fallback when DNF5 cannot produce a transaction
// candidate table. It can over-report versionlocked packages, but it does not hide known advisories.
func NormalizeDNF5Advisories(advisoryJSON string) (string, error) {
	advisories, err := ParseDNF5Advisories(advisoryJSON)
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, len(advisories))
	for _, advisory := range advisories {
		lines = append(lines, advisory.Name+" "+advisory.Severity+"/Sec. "+advisory.NEVRA)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}

// BlockedDNF5 marks an advisory blocked unless both the restricted and unrestricted transactions contain
// a candidate whose EVR covers it. A newer ordinary build can cover an older advisory even when the two
// transaction NEVRAs differ.
func BlockedDNF5(unrestrictedAdvisoryJSON, checkUpgradeOutput, unrestrictedCheckUpgradeOutput string) ([]string, error) {
	advisories, err := ParseDNF5Advisories(unrestrictedAdvisoryJSON)
	if err != nil {
		return nil, err
	}
	upgrades, err := ParseDNF5CheckUpgrades(checkUpgradeOutput)
	if err != nil {
		return nil, err
	}
	unrestricted, err := ParseDNF5CheckUpgrades(unrestrictedCheckUpgradeOutput)
	if err != nil {
		return nil, err
	}
	eligibleByKey := make(map[string]string)
	for _, upgrade := range upgrades {
		_, evr, ok := parseDNF5NEVRA(upgrade.NEVRA)
		if !ok {
			return nil, fmt.Errorf("invalid restricted dnf5 transaction NEVRA %q", upgrade.NEVRA)
		}
		eligibleByKey[upgrade.Key] = evr
	}
	blocked := make(map[string]bool)
	unrestrictedByKey := make(map[string]string)
	for _, upgrade := range unrestricted {
		_, evr, ok := parseDNF5NEVRA(upgrade.NEVRA)
		if !ok {
			return nil, fmt.Errorf("invalid unrestricted dnf5 transaction NEVRA %q", upgrade.NEVRA)
		}
		unrestrictedByKey[upgrade.Key] = evr
	}
	for _, advisory := range advisories {
		key, advisoryEVR, ok := parseDNF5NEVRA(advisory.NEVRA)
		if !ok {
			return nil, fmt.Errorf("invalid dnf5 advisory NEVRA %q", advisory.NEVRA)
		}
		unrestrictedEVR, unrestrictedPresent := unrestrictedByKey[key]
		eligibleEVR, eligiblePresent := eligibleByKey[key]
		if !unrestrictedPresent || !eligiblePresent {
			blocked[key] = true
			continue
		}
		unrestrictedComparison, err := rpmEVRCompare(advisoryEVR, unrestrictedEVR)
		if err != nil {
			return nil, fmt.Errorf("compare unrestricted dnf5 EVR: %w", err)
		}
		eligibleComparison, err := rpmEVRCompare(advisoryEVR, eligibleEVR)
		if err != nil {
			return nil, fmt.Errorf("compare restricted dnf5 EVR: %w", err)
		}
		if unrestrictedComparison > 0 || eligibleComparison > 0 {
			blocked[key] = true
		}
	}
	out := make([]string, 0, len(blocked))
	for key := range blocked {
		out = append(out, key)
	}
	sort.Strings(out)
	return out, nil
}

func dnf5PackageKey(nevra string) string {
	key, _, ok := parseDNF5NEVRA(nevra)
	if !ok {
		return ""
	}
	return key
}

func parseDNF5NEVRA(nevra string) (key, evr string, ok bool) {
	archIdx := strings.LastIndexByte(nevra, '.')
	if archIdx <= 0 || !archRe.MatchString(nevra) {
		return "", "", false
	}
	withoutArch := nevra[:archIdx]
	releaseIdx := strings.LastIndexByte(withoutArch, '-')
	if releaseIdx <= 0 {
		return "", "", false
	}
	versionIdx := strings.LastIndexByte(withoutArch[:releaseIdx], '-')
	if versionIdx <= 0 {
		return "", "", false
	}
	name := withoutArch[:versionIdx]
	if !validDNF5PackageName(name) {
		return "", "", false
	}
	evr = withoutArch[versionIdx+1:]
	if _, err := parseRPMEVR(evr); err != nil {
		return "", "", false
	}
	return name + nevra[archIdx:], evr, true
}

func validDNF5PackageName(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		c := name[i]
		if !asciiAlnum(c) && c != '+' && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func dnf5AdvisoryPreferred(candidate, current DNF5Advisory) bool {
	candidateRank, currentRank := severityRank(candidate.Severity), severityRank(current.Severity)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	_, candidateEVR, _ := parseDNF5NEVRA(candidate.NEVRA)
	_, currentEVR, _ := parseDNF5NEVRA(current.NEVRA)
	comparison, err := rpmEVRCompare(candidateEVR, currentEVR)
	if err != nil {
		return false
	}
	if comparison != 0 {
		return comparison > 0
	}
	return candidate.Name < current.Name
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "important":
		return 4
	case "moderate":
		return 3
	case "low":
		return 2
	case "none":
		return 1
	default:
		return 0
	}
}

func validDNF5Severity(severity string) bool {
	return severityRank(severity) > 0
}

func validDNF5AdvisoryName(name string) bool {
	if name == "" || len(name) > maxDNF5AdvisoryNameBytes || !utf8.ValidString(name) {
		return false
	}
	for _, char := range name {
		if char == unicode.ReplacementChar || !unicode.IsPrint(char) {
			return false
		}
	}
	return true
}
