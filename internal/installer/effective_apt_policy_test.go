package installer

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"strings"
	"testing"
)

func TestEffectiveAPTPolicyFailureRollsBackWhenDoctorSkipped(t *testing.T) {
	for _, test := range []struct {
		name   string
		result CommandResult
	}{
		{"administrator override", CommandResult{Stdout: []byte("APT::Periodic::Enable \"0\";\n")}},
		{"invalid switch", CommandResult{Stdout: []byte("APT::Periodic::Enable \"invalid\";\n")}},
		{"failed query", CommandResult{Code: 100, Stderr: []byte("invalid apt configuration")}},
		{"incomplete query", CommandResult{Stdout: []byte("APT::Periodic::Enable \"1\";\n"), StdoutTruncated: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			i, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			original := "APT::Periodic::Update-Package-Lists \"7\";\n"
			override := "APT::Periodic::Enable \"0\";\n"
			write(t, root, aptPeriodicPath, original, 0o644)
			write(t, root, "/etc/apt/apt.conf.d/99administrator", override, 0o644)
			write(t, root, BinaryPath, "old-runtime", 0o755)
			write(t, root, TimerPath, "old timer\n", 0o644)
			if err := root.MkdirAll(path.Dir(PersistentTimerLink), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := root.Symlink("../security-update-notify.timer", PersistentTimerLink); err != nil {
				t.Fatal(err)
			}
			runner.timerActive = true
			runner.failedCommands["apt-config dump"] = test.result
			options := telegramOptions()
			options.SkipPostInstallCheck = true
			_, err := i.Install(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), "verify effective APT configuration") {
				t.Fatalf("expected effective-policy failure, got %v", err)
			}
			for name, want := range map[string]string{
				aptPeriodicPath: original, BinaryPath: "old-runtime", TimerPath: "old timer\n",
				"/etc/apt/apt.conf.d/99administrator": override,
			} {
				if got := readFile(t, root, name); got != want {
					t.Fatalf("%s changed after rollback: %q", name, got)
				}
			}
			if !runner.timerActive || !existsNoErr(root, PersistentTimerLink) {
				t.Fatal("existing timer was not restored")
			}
			if locker.isHeld(InstallLockPath) || locker.isHeld(RuntimeLockPath) {
				t.Fatal("transaction locks were not released")
			}
			if _, err := root.Lstat("/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("new policy remains after rollback: %v", err)
			}
		})
	}
}
