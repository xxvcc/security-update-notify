// Package commandpath resolves privileged helper commands without consulting
// the caller's PATH. Production search order matches the systemd service unit.
package commandpath

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const TrustedPATH = "/usr/sbin:/usr/bin:/sbin:/bin"

const (
	containerTestFlagEnv        = "SUN_CONTAINER_TEST"
	containerTestCommandPathEnv = "SUN_CONTAINER_TEST_COMMAND_PATH"
)

var trustedDirectories = strings.Split(TrustedPATH, ":")

var inheritedEnvironmentKeys = [...]string{
	"TERM", "TZ",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "no_proxy", "all_proxy",
}

// Resolve returns an executable regular file from the trusted search path.
// Absolute paths are accepted for repository-owned binaries and test hooks;
// relative paths containing a slash are rejected.
func Resolve(name string) (string, error) {
	return resolve(name, guardedContainerTestDirectory())
}

// EffectivePATH returns the PATH inherited by privileged child processes. A
// guarded container fixture directory is prepended only when every test-only
// safety condition has been satisfied.
func EffectivePATH() string {
	return effectivePATH(guardedContainerTestDirectory())
}

// SanitizedEnvironment returns the small environment allowlist inherited by
// privileged helpers, plus caller-supplied fixed overrides. PATH and LC_ALL
// are authoritative and cannot be replaced through overrides.
func SanitizedEnvironment(path string, overrides map[string]string) []string {
	source := os.Environ()
	if guardedContainerTestDirectory() != "" {
		overrides = mergePrefixedEnvironment(source, overrides, "SUN_")
	}
	return sanitizedEnvironmentFrom(source, path, overrides)
}

// SanitizedEnvironmentFrom is the slice-based form used before replacing the
// current process image, where the caller has already captured its environment.
func SanitizedEnvironmentFrom(source []string, path string, overrides map[string]string) []string {
	return sanitizedEnvironmentFrom(source, path, overrides)
}

func sanitizedEnvironmentFrom(source []string, path string, overrides map[string]string) []string {
	inherited := make(map[string]string, len(inheritedEnvironmentKeys))
	for _, item := range source {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		for _, allowed := range inheritedEnvironmentKeys {
			if key == allowed {
				inherited[key] = value
				break
			}
		}
	}

	env := make([]string, 0, len(inherited)+len(overrides)+2)
	for _, key := range inheritedEnvironmentKeys {
		if value, ok := inherited[key]; ok {
			if _, replaced := overrides[key]; !replaced {
				env = append(env, key+"="+value)
			}
		}
	}
	env = append(env, "LC_ALL=C", "PATH="+path)

	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		if key != "LC_ALL" && key != "PATH" && validEnvironmentKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+overrides[key])
	}
	return env
}

func mergePrefixedEnvironment(source []string, overrides map[string]string, prefix string) map[string]string {
	merged := make(map[string]string, len(overrides))
	for key, value := range overrides {
		merged[key] = value
	}
	for _, item := range source {
		key, value, ok := strings.Cut(item, "=")
		if !ok || !strings.HasPrefix(key, prefix) || !validEnvironmentKey(key) {
			continue
		}
		if _, explicitlySet := merged[key]; !explicitlySet {
			merged[key] = value
		}
	}
	return merged
}

func validEnvironmentKey(key string) bool {
	if key == "" || key[0] == '=' || strings.ContainsRune(key, '=') {
		return false
	}
	for _, c := range key {
		if c == 0 {
			return false
		}
	}
	return true
}

func effectivePATH(containerTestDirectory string) string {
	if containerTestDirectory == "" {
		return TrustedPATH
	}
	return containerTestDirectory + string(os.PathListSeparator) + TrustedPATH
}

func resolve(name, containerTestDirectory string) (string, error) {
	if name == "" {
		return "", errors.New("empty command name")
	}
	if filepath.IsAbs(name) {
		if executableRegular(name) {
			return name, nil
		}
		return "", errors.New("command is unavailable: " + name)
	}
	if strings.ContainsRune(name, filepath.Separator) {
		return "", errors.New("command name must not contain a path separator")
	}
	if containerTestDirectory != "" {
		candidate := filepath.Join(containerTestDirectory, name)
		if executableRegular(candidate) {
			return candidate, nil
		}
	}
	for _, directory := range trustedDirectories {
		candidate := filepath.Join(directory, name)
		if executableRegular(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("command is unavailable on trusted system PATH: " + name)
}

func executableRegular(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func guardedContainerTestDirectory() string {
	commandDirectory := os.Getenv(containerTestCommandPathEnv)
	if commandDirectory == "" || os.Getenv(containerTestFlagEnv) != "1" {
		return ""
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return ""
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || !mountPointReadOnly(mountInfo, "/src") {
		return ""
	}
	return selectContainerTestDirectory(commandDirectory, "1", true, true, os.Geteuid())
}

func selectContainerTestDirectory(commandDirectory, flag string, dockerEnvironment, sourceReadOnly bool, effectiveUID int) string {
	if commandDirectory == "" || flag != "1" || !dockerEnvironment || !sourceReadOnly ||
		!trustedContainerTestDirectory(commandDirectory, effectiveUID) {
		return ""
	}
	return commandDirectory
}

func trustedContainerTestDirectory(directory string, effectiveUID int) bool {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return false
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && effectiveUID >= 0 && stat.Uid == uint32(effectiveUID)
}

func mountPointReadOnly(mountInfo []byte, mountPoint string) bool {
	found := false
	for _, line := range bytes.Split(mountInfo, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) < 6 || string(fields[4]) != mountPoint {
			continue
		}
		if !commaListContains(string(fields[5]), "ro") {
			return false
		}
		found = true
	}
	return found
}

func commaListContains(list, item string) bool {
	for _, candidate := range strings.Split(list, ",") {
		if candidate == item {
			return true
		}
	}
	return false
}
