package run

import (
	"path/filepath"
	"testing"

	runlock "github.com/xxvcc/security-update-notify/internal/lock"
)

func TestExecuteMakesRequiredLockContentionExplicit(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "notify.lock")
	release, acquired, err := runlock.Acquire(lockPath)
	if err != nil || !acquired {
		t.Fatalf("hold lock: acquired=%v err=%v", acquired, err)
	}
	defer release()
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", lockPath)
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", t.TempDir())

	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=feishu\n")
	if got := Execute(cfg, DryRunFlags{}); got != 0 {
		t.Fatalf("default lock contention exit=%d want 0", got)
	}
	if got := Execute(cfg, DryRunFlags{RequireLock: true}); got != 75 {
		t.Fatalf("required lock contention exit=%d want 75", got)
	}
}
