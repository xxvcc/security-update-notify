package uninstaller

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedTreeRecoveryPreservesUnverifiedNestedQuarantines(t *testing.T) {
	for _, prefix := range []string{uninstallRemovalPendingPrefix, uninstallRemovalPrefix} {
		t.Run(prefix, func(t *testing.T) {
			root := t.TempDir()
			logical := "/etc/security-update-notify"
			writeFixture(t, root, logical+"/ordinary", "ordinary")
			parent, name, err := openLogicalParent(root, logical)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			info, err := readRemovalEntry(parent, name)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := ownedRemovalName("."+uninstallRemovalPendingPrefix+"."+strings.Repeat("a", 32), info, removalTree)
			if err != nil {
				t.Fatal(err)
			}
			ownedPath := filepath.Join(parent.Name(), owned)
			if err := os.Rename(filepath.Join(parent.Name(), name), ownedPath); err != nil {
				t.Fatal(err)
			}
			pendingChild := filepath.Join(ownedPath, "."+prefix+"."+strings.Repeat("b", 32))
			if err := os.WriteFile(pendingChild, []byte("unverified replacement"), 0o600); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := removeLogicalTree(root, logical); err == nil || !strings.Contains(err.Error(), "unverified") {
					t.Fatalf("recovery %d error = %v, want preserved unverified child", attempt, err)
				}
				assertPathContent(t, pendingChild, "unverified replacement")
				assertPathContent(t, filepath.Join(ownedPath, "ordinary"), "ordinary")
			}
		})
	}
}

func TestNestedClaimValidationFailureSurvivesRetry(t *testing.T) {
	root := t.TempDir()
	logical := "/etc/security-update-notify"
	writeFixture(t, root, logical+"/telegram.env", "administrator replacement")
	parent, name, err := openLogicalParent(root, logical)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	info, err := readRemovalEntry(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	forced := errors.New("interrupted before child identity validation")
	pendingChild := ""
	err = removeValidatedEntryAtWithHook(parent, name, info, removalTree, func(owned string) error {
		directory, err := openRemovalDirectory(parent, owned)
		if err != nil {
			return err
		}
		defer directory.Close()
		childInfo, err := readRemovalEntry(directory, "telegram.env")
		if err != nil {
			return err
		}
		return removeValidatedEntryAtWithHooks(directory, "telegram.env", childInfo, removalLeaf, removalHooks{
			afterPendingClaim: func(pending string) error {
				pendingChild = filepath.Join(directory.Name(), pending)
				return forced
			},
		})
	})
	if !errors.Is(err, forced) {
		t.Fatalf("first attempt = %v", err)
	}
	assertPathContent(t, pendingChild, "administrator replacement")
	if err := removeLogicalTree(root, logical); err == nil || !strings.Contains(err.Error(), "unverified uninstall quarantine") {
		t.Fatalf("retry = %v, want unverified child refusal", err)
	}
	assertPathContent(t, pendingChild, "administrator replacement")
}
