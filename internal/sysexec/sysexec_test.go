package sysexec

import "testing"

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

func TestLook(t *testing.T) {
	if !Look("sh") {
		t.Error("sh should be found")
	}
	if Look("definitely-not-a-real-command-xyz") {
		t.Error("bogus command should not be found")
	}
}
