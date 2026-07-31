package commandpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveIgnoresCallerPATH(t *testing.T) {
	directory := t.TempDir()
	stub := filepath.Join(directory, "sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)

	resolved, err := Resolve("sh")
	if err != nil {
		t.Fatal(err)
	}
	if resolved == stub || !strings.HasPrefix(resolved, "/") {
		t.Fatalf("resolved caller-controlled command: %q", resolved)
	}
}

func TestResolveIgnoresContainerCommandPathWithoutFlag(t *testing.T) {
	directory := t.TempDir()
	name := "security-update-notify-environment-only-command"
	stub := filepath.Join(directory, name)
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(containerTestCommandPathEnv, directory)
	t.Setenv(containerTestFlagEnv, "")

	if resolved, err := Resolve(name); err == nil {
		t.Fatalf("environment-only command path resolved %q", resolved)
	}
}

func TestGuardedContainerCommandPathRequiresEveryGuard(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name     string
		path     string
		flag     string
		docker   bool
		sourceRO bool
		want     bool
	}{
		{name: "all guards", path: directory, flag: "1", docker: true, sourceRO: true, want: true},
		{name: "missing path", flag: "1", docker: true, sourceRO: true},
		{name: "missing flag", path: directory, docker: true, sourceRO: true},
		{name: "not docker", path: directory, flag: "1", sourceRO: true},
		{name: "writable source", path: directory, flag: "1", docker: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := selectContainerTestDirectory(test.path, test.flag, test.docker, test.sourceRO, os.Geteuid())
			if (got != "") != test.want {
				t.Fatalf("guarded directory = %q, want enabled=%v", got, test.want)
			}
		})
	}
}

func TestFullyGuardedContainerCommandPathTakesPrecedence(t *testing.T) {
	directory := t.TempDir()
	stub := filepath.Join(directory, "sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	guarded := selectContainerTestDirectory(directory, "1", true, true, os.Geteuid())
	resolved, err := resolve("sh", guarded)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != stub {
		t.Fatalf("resolved %q, want guarded fixture %q", resolved, stub)
	}
}

func TestEffectivePATHIncludesOnlyGuardedFixtureAndTrustedDirectories(t *testing.T) {
	directory := t.TempDir()
	if got := effectivePATH(""); got != TrustedPATH {
		t.Fatalf("production PATH = %q, want %q", got, TrustedPATH)
	}
	want := directory + string(os.PathListSeparator) + TrustedPATH
	if got := effectivePATH(directory); got != want {
		t.Fatalf("guarded test PATH = %q, want %q", got, want)
	}
}

func TestSanitizedEnvironmentDropsCommandAndLoaderConfiguration(t *testing.T) {
	source := []string{
		"TERM=xterm-256color", "TZ=Asia/Shanghai", "HTTPS_PROXY=http://proxy.example:8080",
		"LD_PRELOAD=/tmp/attack.so", "BASH_ENV=/tmp/attack.sh", "ENV=/tmp/attack.sh",
		"APT_CONFIG=/tmp/apt.conf", "RPM_CONFIGDIR=/tmp/rpm", "SYSTEMD_UNIT_PATH=/tmp/units",
		"GIT_CONFIG_GLOBAL=/tmp/gitconfig", "PATH=/tmp/bin", "LC_ALL=hostile",
	}
	env := sanitizedEnvironmentFrom(source, TrustedPATH, map[string]string{
		"DEBIAN_FRONTEND": "noninteractive", "PATH": "/tmp/override", "LC_ALL": "hostile",
	})
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{
		"LD_PRELOAD=", "BASH_ENV=", "ENV=", "APT_CONFIG=", "RPM_CONFIGDIR=",
		"SYSTEMD_UNIT_PATH=", "GIT_CONFIG_GLOBAL=", "/tmp/bin", "/tmp/override", "hostile",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("unsafe environment %q survived:\n%s", forbidden, joined)
		}
	}
	for _, want := range []string{
		"TERM=xterm-256color", "TZ=Asia/Shanghai", "HTTPS_PROXY=http://proxy.example:8080",
		"LC_ALL=C", "PATH=" + TrustedPATH, "DEBIAN_FRONTEND=noninteractive",
	} {
		if strings.Count(joined, want) != 1 {
			t.Fatalf("environment entry %q missing or duplicated:\n%s", want, joined)
		}
	}
}

func TestSanitizedEnvironmentRejectsMalformedOverrideKeys(t *testing.T) {
	env := sanitizedEnvironmentFrom(nil, TrustedPATH, map[string]string{
		"": "empty", "BAD=NAME": "bad", "GOOD_NAME": "ok",
	})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "empty") || strings.Contains(joined, "BAD=NAME") ||
		!strings.Contains(joined, "GOOD_NAME=ok") {
		t.Fatalf("malformed override filtering failed:\n%s", joined)
	}
}

func TestMergePrefixedEnvironmentKeepsOnlyFixtureVariables(t *testing.T) {
	merged := mergePrefixedEnvironment([]string{
		"SUN_CONTAINER_TEST=1",
		"SUN_FIXTURE_STATE=/tmp/state",
		"FAIL_LIST_TIMERS=1",
		"LD_PRELOAD=/tmp/attack.so",
	}, map[string]string{
		"SUN_FIXTURE_STATE": "explicit",
		"DEBIAN_FRONTEND":   "noninteractive",
	}, "SUN_")

	want := map[string]string{
		"SUN_CONTAINER_TEST": "1",
		"SUN_FIXTURE_STATE":  "explicit",
		"DEBIAN_FRONTEND":    "noninteractive",
	}
	if len(merged) != len(want) {
		t.Fatalf("merged environment = %#v, want %#v", merged, want)
	}
	for key, value := range want {
		if merged[key] != value {
			t.Fatalf("merged[%q] = %q, want %q", key, merged[key], value)
		}
	}
}

func TestResolveRejectsUntrustedRelativePathsAndNonExecutables(t *testing.T) {
	if _, err := Resolve("tmp/tool"); err == nil {
		t.Fatal("relative path with a separator was accepted")
	}
	file := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(file); err == nil {
		t.Fatal("non-executable absolute file was accepted")
	}
}

func TestTrustedContainerTestDirectory(t *testing.T) {
	directory := t.TempDir()
	if !trustedContainerTestDirectory(directory, os.Geteuid()) {
		t.Fatal("secure temporary directory was rejected")
	}
	if trustedContainerTestDirectory(directory+string(filepath.Separator)+".", os.Geteuid()) {
		t.Fatal("unclean directory path was accepted")
	}
	if trustedContainerTestDirectory(directory, os.Geteuid()^1) {
		t.Fatal("directory owned by a different uid was accepted")
	}

	symlink := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(directory, symlink); err != nil {
		t.Fatal(err)
	}
	if trustedContainerTestDirectory(symlink, os.Geteuid()) {
		t.Fatal("symlinked directory was accepted")
	}

	if err := os.Chmod(directory, 0o775); err != nil {
		t.Fatal(err)
	}
	if trustedContainerTestDirectory(directory, os.Geteuid()) {
		t.Fatal("group-writable directory was accepted")
	}
}

func TestMountPointReadOnly(t *testing.T) {
	const readOnly = "36 25 0:32 / /src ro,nosuid,nodev - ext4 /dev/root rw\n"
	tests := []struct {
		name string
		data string
		want bool
	}{
		{name: "read only", data: readOnly, want: true},
		{name: "read write", data: "36 25 0:32 / /src rw,nosuid - ext4 /dev/root ro\n"},
		{name: "different mount", data: "36 25 0:32 / /source ro - ext4 /dev/root ro\n"},
		{name: "malformed", data: "36 25 /src ro\n"},
		{name: "conflicting overmount", data: readOnly + "37 25 0:33 / /src rw - tmpfs tmpfs rw\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mountPointReadOnly([]byte(test.data), "/src"); got != test.want {
				t.Fatalf("mountPointReadOnly() = %v, want %v", got, test.want)
			}
		})
	}
}
