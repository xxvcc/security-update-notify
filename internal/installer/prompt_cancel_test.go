package installer

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCancellationWhileWaitingForInteractiveCallbackRollsBack(t *testing.T) {
	for _, stage := range []string{"dependencies", "preflight"} {
		t.Run(stage, func(t *testing.T) {
			instance, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			options := telegramOptions()
			options.SkipPostInstallCheck = true
			if _, err := instance.Install(context.Background(), options); err != nil {
				t.Fatal(err)
			}
			oldConfig := readFile(t, root, ConfigPath)
			oldRuntime := readFile(t, root, BinaryPath)
			oldTimer := readFile(t, root, TimerPath)
			waiting := make(chan struct{})
			wait := func(ctx context.Context) error {
				if runner.timerActive || !locker.held[InstallLockPath] || !locker.held[RuntimeLockPath] {
					return fmt.Errorf("callback ran without quiescing and holding both transaction locks")
				}
				close(waiting)
				<-ctx.Done()
				return ctx.Err()
			}
			if stage == "dependencies" {
				runner.missingPackages["needrestart"] = true
				options.ConfirmDependencies = func(ctx context.Context, _ DependencyRequest) (bool, error) {
					return false, wait(ctx)
				}
			} else {
				options.Preflight = func(ctx context.Context, _ *Prepared) error { return wait(ctx) }
			}
			options.Config["HOST_LABEL"] = "canceled-change"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := instance.Install(ctx, options)
				done <- err
			}()
			select {
			case <-waiting:
			case err := <-done:
				t.Fatalf("install ended before callback: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("install did not reach callback")
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled install error = %v", err)
			}
			for path, want := range map[string]string{ConfigPath: oldConfig, BinaryPath: oldRuntime, TimerPath: oldTimer} {
				if got := readFile(t, root, path); got != want {
					t.Errorf("rollback changed %s", path)
				}
			}
			if !runner.timerActive || !existsNoErr(root, PersistentTimerLink) {
				t.Error("rollback did not restore the old timer")
			}
			if locker.held[InstallLockPath] || locker.held[RuntimeLockPath] {
				t.Error("rollback retained transaction locks")
			}
			if tx, _, err := instance.loadTransaction(); err != nil || tx != nil {
				t.Fatalf("rollback retained active transaction: %v, %v", tx, err)
			}
		})
	}
}
