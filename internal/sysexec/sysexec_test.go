package sysexec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunCapturesAndNonZeroNotFatal(t *testing.T) {
	r := Run("sh", "-c", "printf hi; printf err >&2; exit 3")
	if r.Stdout != "hi" || r.Stderr != "err" {
		t.Errorf("stdout=%q stderr=%q", r.Stdout, r.Stderr)
	}
	if r.Code != 3 {
		t.Errorf("code=%d want 3", r.Code)
	}
	if r.Err != nil {
		t.Errorf("non-zero exit must not be Err: %v", r.Err)
	}
}

func TestRunForcesLCAllC(t *testing.T) {
	t.Setenv("LC_ALL", "en_US.UTF-8")
	r := Run("sh", "-c", "printf %s \"$LC_ALL\"")
	if r.Stdout != "C" {
		t.Errorf("LC_ALL in child = %q want C", r.Stdout)
	}
}

func TestForcedEnvironmentDropsInheritedCommandConfiguration(t *testing.T) {
	t.Setenv("APT_CONFIG", "/tmp/attacker-apt.conf")
	t.Setenv("RPM_CONFIGDIR", "/tmp/attacker-rpm")
	t.Setenv("SYSTEMD_UNIT_PATH", "/tmp/attacker-units")
	t.Setenv("BASH_ENV", "/tmp/attacker.sh")
	env := strings.Join(forcedEnv(), "\n")
	for _, forbidden := range []string{"APT_CONFIG=", "RPM_CONFIGDIR=", "SYSTEMD_UNIT_PATH=", "BASH_ENV="} {
		if strings.Contains(env, forbidden) {
			t.Fatalf("unsafe environment %q survived:\n%s", forbidden, env)
		}
	}
}

func TestRunCommandNotFound(t *testing.T) {
	r := Run("definitely-not-a-real-command-xyz")
	if r.Err == nil || r.Code != -1 {
		t.Errorf("expected start error and code -1, got code=%d err=%v", r.Code, r.Err)
	}
}

func TestRunReportsCapturedOutputTruncation(t *testing.T) {
	r := Run("sh", "-c", "head -c 8388609 /dev/zero; head -c 8388609 /dev/zero >&2")
	if r.Err != nil || r.Code != 0 {
		t.Fatalf("command result: code=%d err=%v", r.Code, r.Err)
	}
	if len(r.Stdout) != maxCapturedBytes || len(r.Stderr) != maxCapturedBytes {
		t.Fatalf("captured lengths stdout=%d stderr=%d", len(r.Stdout), len(r.Stderr))
	}
	if !r.StdoutTruncated || !r.StderrTruncated {
		t.Fatalf("truncation flags stdout=%v stderr=%v", r.StdoutTruncated, r.StderrTruncated)
	}
}

func TestRunTimeoutReportsDeadline(t *testing.T) {
	started := time.Now()
	r := RunTimeout(25*time.Millisecond, "sh", "-c", "sleep 2 & wait")
	if r.Code != -1 || !errors.Is(r.Err, context.DeadlineExceeded) {
		t.Fatalf("timeout result: code=%d err=%v", r.Code, r.Err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timed command returned after %s", elapsed)
	}
}

func TestSignalForwardingKillsDescendantProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "descendant-survived")
	ready := marker + ".ready"
	cleanupMarker := marker + ".cleanup"
	cmd := exec.Command(os.Args[0], "-test.run=^TestSignalForwardingHelper$")
	cmd.Env = append(os.Environ(),
		"SUN_SYSEXEC_SIGNAL_HELPER=1",
		"SUN_SYSEXEC_SIGNAL_MARKER="+marker,
		"SUN_SYSEXEC_SIGNAL_READY="+ready,
		"SUN_SYSEXEC_SIGNAL_CLEANUP="+cleanupMarker,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
			t.Fatal("signal helper did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("helper exit=%v, want signal termination", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("helper wait status=%v, want SIGTERM", exitErr.Sys())
	}
	if contents, err := os.ReadFile(cleanupMarker); err != nil || string(contents) != "restored" {
		t.Fatalf("termination cleanup did not run before signal exit: contents=%q err=%v", contents, err)
	}
	time.Sleep(700 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descendant survived forwarded termination signal: %v", err)
	}
}

func TestSignalForwardingHelper(t *testing.T) {
	if os.Getenv("SUN_SYSEXEC_SIGNAL_HELPER") != "1" {
		return
	}
	InstallSignalForwarding()
	marker := os.Getenv("SUN_SYSEXEC_SIGNAL_MARKER")
	ready := os.Getenv("SUN_SYSEXEC_SIGNAL_READY")
	cleanupMarker := os.Getenv("SUN_SYSEXEC_SIGNAL_CLEANUP")
	unregister := RegisterTerminationCleanup(func() {
		_ = os.WriteFile(cleanupMarker, []byte("restored"), 0o600)
	})
	defer unregister()
	cmd := CommandContext(context.Background(), "/bin/sh", "-c",
		`trap '' INT TERM; (trap '' INT TERM; sleep 0.6; printf survived >"$1") & wait`, "sh", marker)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child command ended before the helper was signaled: %v", err)
	}
}

func TestTerminationCleanupCanBeUnregistered(t *testing.T) {
	called := 0
	unregister := RegisterTerminationCleanup(func() { called++ })
	unregister()
	runTerminationCleanups()
	if called != 0 {
		t.Fatalf("unregistered termination cleanup ran %d times", called)
	}

	RegisterTerminationCleanup(func() { called++ })
	runTerminationCleanups()
	runTerminationCleanups()
	if called != 1 {
		t.Fatalf("registered termination cleanup ran %d times, want once", called)
	}
}

func TestLook(t *testing.T) {
	if !Look("sh") {
		t.Error("sh should be found")
	}
	if Look("definitely-not-a-real-command-xyz") {
		t.Error("bogus command should not be found")
	}
}

func TestCommandsIgnoreCallerPATH(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	stub := filepath.Join(dir, "sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	result := Run("sh", "-c", "printf trusted")
	if result.Code != 0 || result.Stdout != "trusted" {
		t.Fatalf("trusted command result=%+v", result)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("caller PATH stub executed: %v", err)
	}
}

func TestCommandContextForcesTrustedPATHForIndirectCommands(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "indirect-command-ran")
	stub := filepath.Join(dir, "id")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf attacked >'"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", "id >/dev/null")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("indirect command used caller PATH: %v", err)
	}
}

func TestInjectedCommandPathIsExplicitAndBounded(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "fixture-command")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf fixture\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	restore := SetCommandPathForTest(dir)
	t.Cleanup(restore)
	result := Run("fixture-command")
	if result.Code != 0 || result.Stdout != "fixture" {
		t.Fatalf("fixture result=%+v", result)
	}
	if Look("sh") {
		t.Fatal("injected lookup unexpectedly fell through to the production PATH")
	}
}

func TestInjectedCommandPathCarriesOnlyFixtureEnvironment(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "fixture-command")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s|%s' \"$SUN_FIXTURE_VALUE\" \"${APT_CONFIG-unset}\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUN_FIXTURE_VALUE", "expected")
	t.Setenv("APT_CONFIG", "/tmp/attacker-apt.conf")
	restore := SetCommandPathForTest(dir)
	t.Cleanup(restore)
	result := Run("fixture-command")
	if result.Code != 0 || result.Stdout != "expected|unset" {
		t.Fatalf("fixture environment result=%+v", result)
	}
}
