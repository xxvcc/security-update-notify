package sysexec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

func TestRunCommandNotFound(t *testing.T) {
	r := Run("definitely-not-a-real-command-xyz")
	if r.Err == nil || r.Code != -1 {
		t.Errorf("expected start error and code -1, got code=%d err=%v", r.Code, r.Err)
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestSignalForwardingHelper$")
	cmd.Env = append(os.Environ(),
		"SUN_SYSEXEC_SIGNAL_HELPER=1",
		"SUN_SYSEXEC_SIGNAL_MARKER="+marker,
		"SUN_SYSEXEC_SIGNAL_READY="+ready,
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

func TestLook(t *testing.T) {
	if !Look("sh") {
		t.Error("sh should be found")
	}
	if Look("definitely-not-a-real-command-xyz") {
		t.Error("bogus command should not be found")
	}
}
