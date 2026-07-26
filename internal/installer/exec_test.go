package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExecRunnerTimeoutKillsDescendantProcess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "descendant-survived")
	result := (ExecRunner{}).Run(context.Background(), Command{
		Name:    "/bin/sh",
		Args:    []string{"-c", "(sleep 0.2; printf survived >\"$1\") & wait", "sh", marker},
		Timeout: 25 * time.Millisecond,
	})
	if result.Code != -1 || !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("timeout result: code=%d err=%v", result.Code, result.Err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installer descendant survived timeout: %v", err)
	}
}
