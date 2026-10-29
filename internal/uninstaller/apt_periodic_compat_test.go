package uninstaller

import (
	"testing"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
)

func TestPurgeRecognizesLegacyAPTPeriodicPolicy(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, aptconfig.LegacyPeriodic)
	writeFixture(t, root, aptAbsentLogical, aptAbsentContents)
	backup := aptPeriodicLogical + ".security-update-notify.20260726000000.bak"
	writeFixture(t, root, backup, aptconfig.LegacyPeriodic)
	if _, err := uninstallAsRoot(Options{RootDir: root, PurgeConfig: true, RunCommand: successfulRunner}); err != nil {
		t.Fatal(err)
	}
	assertMissing(t, root, aptPeriodicLogical)
	assertMissing(t, root, aptAbsentLogical)
	assertMissing(t, root, backup)
}
