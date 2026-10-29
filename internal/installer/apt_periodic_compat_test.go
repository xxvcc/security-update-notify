package installer

import (
	"context"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/uninstaller"
)

func TestLegacyAPTPeriodicUpgradePreservesOriginalAbsence(t *testing.T) {
	for _, history := range []bool{false, true} {
		name := "without-history"
		if history {
			name = "with-history"
		}
		t.Run(name, func(t *testing.T) {
			instance, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, aptPeriodicPath, aptconfig.LegacyPeriodic, 0o644)
			write(t, root, aptAbsentMarkerPath, aptAbsentMarkerContents, 0o600)
			if history {
				write(t, root, aptPeriodicPath+".security-update-notify.20260725010203.bak", aptconfig.LegacyPeriodic, 0o644)
			}
			options := telegramOptions()
			options.SkipPostInstallCheck = true
			if _, err := instance.Install(context.Background(), options); err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, root, aptPeriodicPath); got != aptconfig.Periodic {
				t.Fatalf("upgraded APT policy = %q", got)
			}
			if existsNoErr(root, aptStableBackupPath) {
				t.Fatal("old managed policy was adopted as an administrator baseline")
			}
			if _, err := uninstaller.Uninstall(uninstaller.Options{
				RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
				RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
			}); err != nil {
				t.Fatal(err)
			}
			if existsNoErr(root, aptPeriodicPath) || existsNoErr(root, aptAbsentMarkerPath) {
				t.Fatal("purge did not restore the original absence after upgrading the old policy")
			}
		})
	}
}
