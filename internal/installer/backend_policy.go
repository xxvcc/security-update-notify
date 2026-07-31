package installer

import (
	"bytes"

	"errors"
	"fmt"
	"io/fs"

	"path"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
)

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
		var baselineExists bool
		data, baselineExists, err = i.readTrustedRegularFile(dnfStableBackupPath, 4<<20)
		if err != nil || !baselineExists {
			if err == nil {
				err = fs.ErrNotExist
			}
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
		var currentExists bool
		data, currentExists, err = i.readTrustedRegularFile(automatic, 4<<20)
		if err != nil || !currentExists {
			if err == nil {
				err = fs.ErrNotExist
			}
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
			data, exists, err := i.readTrustedRegularFile(candidate, 4<<20)
			if err != nil || !exists {
				if err == nil {
					err = fs.ErrNotExist
				}
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
		if len(trimmed) >= 2 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inSection && !written {
				output = append(output, key+" = "+value)
				written = true
			}
			// Normalize the header exactly like dnfconfig.ParseStrict. Both run as a pair over the
			// same file, so a shape one accepts and the other misses (e.g. the padded "[ commands ]")
			// would append a second "[commands]" and make the managed config fail its own duplicate
			// -section validation, aborting the install.
			inSection = strings.EqualFold(strings.TrimSpace(trimmed[1:len(trimmed)-1]), section)
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
