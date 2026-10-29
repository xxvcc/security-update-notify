package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/statefile"
)

func TestDNF4VersionlockDetectedWhenAdvisoryListsAreIdentical(t *testing.T) {
	for _, mode := range []string{"locked", "query-failed", "invalid-output", "status-mismatch", "advisory-empty"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' '4.14.0' ;;
  *"updateinfo list security")
    if [ "$SUN_DNF4_FIXTURE_MODE" != advisory-empty ]; then
      printf '%s\n' 'RHSA-2026:1 Important/Sec. openssl-1:3.0.7-50.el9.x86_64'
    fi ;;
  "-q --setopt=autocheck_running_kernel=False check-update --security")
    case "$SUN_DNF4_FIXTURE_MODE" in
      query-failed) exit 2 ;;
      invalid-output) printf '%s\n' 'unknown output' ;;
      status-mismatch) exit 100 ;;
    esac ;;
  "-q --setopt=autocheck_running_kernel=False --disableplugin=versionlock --disableexcludes=all check-update --security")
    printf '%s\n' 'openssl.x86_64 1:3.0.7-50.el9 baseos'
    exit 100 ;;
  "-q check") exit 0 ;;
  *) exit 3 ;;
esac
`)
			t.Setenv("PATH", dir)
			t.Setenv("SUN_DNF4_FIXTURE_MODE", mode)
			setHealthyAutomaticConfig(t)
			pending, blocked, issues := collectDNFPackageFacts(true)
			if mode != "advisory-empty" && pending.Count != 1 {
				t.Fatalf("pending=%+v", pending)
			}
			if mode == "locked" {
				if strings.Join(blocked, ",") != "openssl.x86_64" || len(issues) != 0 {
					t.Fatalf("blocked=%v issues=%v", blocked, issues)
				}
			} else if len(blocked) != 0 || !hasIssueCode(issues, "dnf-blocked-query-failed") {
				t.Fatalf("failed candidate query did not remain unknown: blocked=%v issues=%v", blocked, issues)
			}
			if mode != "locked" && pending.Known {
				t.Fatal("failed/inconsistent candidate query proved recovery")
			}
		})
	}
}

func TestDNF5InconsistentQueriesPreserveAgeAndReportUnknown(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  *"advisory list --security --updates --json") printf '%s\n' '[]' ;;
  *"check-upgrade --security")
    printf '%s\n' 'openssl.x86_64 2-1.fc44 updates'
    exit 100 ;;
  "-q check") exit 0 ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)
	setHealthyAutomaticConfig(t)
	stateDir := t.TempDir()
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", stateDir)
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	firstSeen := now.Add(-5 * 24 * time.Hour).Unix()
	store := statefile.Store{Dir: stateDir}
	if err := store.WriteInt("pending-security.first_seen", firstSeen); err != nil {
		t.Fatal(err)
	}
	cfg := patchTestConfig(t, "CHECK_SELF_UPDATE=0\n")
	patch, pending := collectPatchWatchdog(cfg, "dnf", backend.RestartState{}, "3.3.3", patchCollectOptions{PersistState: true, Now: now})
	if pending.Known || pending.Count != 0 || !patch.RiskAttention || !strings.Contains(patch.Sig, "dnf-security-transaction-invalid") {
		t.Fatalf("inconsistent empty advisory became healthy: pending=%+v patch=%+v", pending, patch)
	}
	if got, err := store.ReadInt("pending-security.first_seen"); err != nil || got != firstSeen {
		t.Fatalf("unknown observation cleared age: first=%d err=%v", got, err)
	}
	_, observation, _, issues := collectDNFPackageFactsObserved(false)
	if observation != statefile.ObservationUnknown || len(issues) != 0 {
		t.Fatalf("disabled health checks changed unknown observation: observation=%v issues=%v", observation, issues)
	}
}

func setHealthyAutomaticConfig(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "automatic.conf")
	if err := os.WriteFile(path, []byte("[commands]\nupgrade_type=security\napply_updates=yes\nreboot=never\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", path)
}

func TestAPTSecurityPolicyUsesReleaseCodenameMetadata(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	content := "Valid-Until: " + now.Add(24*time.Hour).Format(time.RFC1123Z) + "\nCodename: bookworm-security\n"
	if err := os.WriteFile(filepath.Join(dir, "debian-security_InRelease"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bullseye-security,label=Debian-Security";`
	issues := inspectAPTMetadataWithPolicy(dir, now, 7, policy)
	if len(issues) != 1 || !hasIssueCode(issues, "apt-security-origin-release-mismatch") {
		t.Fatalf("issues=%v", issues)
	}
}
