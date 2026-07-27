package run

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/statefile"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

func TestCollectAPTPackageFactsClassifiesCommandAndRepositoryFailures(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "apt-get", `
case "$*" in
  "-s upgrade")
    printf '%s\n' 'Inst openssl [1] (2 Debian-Security:stable-security [amd64])'
    exit 1
    ;;
  "-s --ignore-hold upgrade")
    printf '%s\n' \
      'Inst openssl [1] (2 Debian-Security:stable-security [amd64])' \
      'Inst linux-image [1] (2 Debian-Security:stable-security [amd64])'
    ;;
  "check -qq") exit 1 ;;
  *) exit 2 ;;
esac
`)
	writeTestCommand(t, dir, "apt-mark", "printf '%s\\n' linux-image\n")
	writeTestCommand(t, dir, "apt-config", "exit 1\n")
	writeTestCommand(t, dir, "dpkg", "printf '%s\\n' 'packages are only half configured'\n")
	writeTestCommand(t, dir, "systemctl", "printf '%s\\n' failed\n")
	writeTestCommand(t, dir, "journalctl", "printf '%s\\n' 'NO_PUBKEY DEADBEEF'\n")
	t.Setenv("PATH", dir)
	t.Setenv("SECURITY_UPDATE_NOTIFY_APT_LISTS_DIR", filepath.Join(t.TempDir(), "missing-lists"))

	pending, blocked, issues := collectAPTPackageFacts(true, time.Now(), 7)
	if pending.Count != 1 || len(blocked) != 1 || blocked[0] != "linux-image" {
		t.Fatalf("pending=%+v blocked=%v", pending, blocked)
	}
	for _, code := range []string{
		"apt-simulation-failed", "apt-config-unreadable", "dpkg-audit", "apt-check",
		"apt-repository-signature", "apt-metadata-missing",
	} {
		if !hasIssueCode(issues, code) {
			t.Errorf("missing issue %q in %v", code, issues)
		}
	}
}

func TestCollectDNFPackageFactsClassifiesSignatureAndBlockedUpdates(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
	"--version") printf '%s\n' '4.14.0' ;;
  "-q updateinfo list security")
    printf '%s\n' 'RHSA-2026:1 Important/Sec. visible.x86_64'
    printf '%s\n' 'certificate verification failed' >&2
    exit 1
    ;;
  "-q --disableplugin=versionlock --disableexcludes=all updateinfo list security")
    printf '%s\n' \
      'RHSA-2026:1 Important/Sec. visible.x86_64' \
      'RHSA-2026:2 Critical/Sec. blocked.noarch'
    ;;
  "-q check") exit 1 ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)
	t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", filepath.Join(t.TempDir(), "missing.conf"))

	pending, blocked, issues := collectDNFPackageFacts(true)
	if pending.Count != 1 || len(blocked) != 1 || blocked[0] != "blocked.noarch" {
		t.Fatalf("pending=%+v blocked=%v", pending, blocked)
	}
	for _, code := range []string{"dnf-repository-signature", "dnf-automatic-config", "dnf-check"} {
		if !hasIssueCode(issues, code) {
			t.Errorf("missing issue %q in %v", code, issues)
		}
	}
}

func TestCollectDNF5PackageFactsUsesAdvisoryJSONAndTransactionConstraints(t *testing.T) {
	dir := t.TempDir()
	callLog := filepath.Join(t.TempDir(), "dnf.calls")
	writeTestCommand(t, dir, "dnf", `
printf '%s\n' "$*" >> "$SUN_DNF_CALL_LOG"
case "$*" in
  "--version")
    printf '%s\n' 'dnf5 version 5.2.18.0'
    ;;
  "-q advisory list --security --updates --json")
    printf '%s\n' '[{"name":"FEDORA-2026-visible","type":"security","severity":"Important","nevra":"visible-2-1.fc43.x86_64"},{"name":"FEDORA-2026-locked","type":"security","severity":"Moderate","nevra":"locked-2-1.fc43.noarch"}]'
    ;;
  "-q check-upgrade --security")
	printf '%s\n' 'Upgrades' 'visible.x86_64 2-1.fc43 updates'
    exit 100
    ;;
	"-q --setopt=disable_excludes=* check-upgrade --security")
	printf '%s\n' 'Upgrades' \
	  'visible.x86_64 2-1.fc43 updates' \
	  'locked.noarch 2-1.fc43 updates' \
	  'excluded.aarch64 2-1.fc43 updates'
	  exit 100
	  ;;
  "-q --setopt=exclude= --setopt=excludepkgs= --setopt=*.excludepkgs= advisory list --security --updates --json")
    printf '%s\n' '[{"name":"FEDORA-2026-visible","type":"security","severity":"Important","nevra":"visible-2-1.fc43.x86_64"},{"name":"FEDORA-2026-locked","type":"security","severity":"Moderate","nevra":"locked-2-1.fc43.noarch"},{"name":"FEDORA-2026-excluded","type":"security","severity":"Low","nevra":"excluded-2-1.fc43.aarch64"}]'
    ;;
  "-q check") exit 0 ;;
  *) exit 2 ;;
esac
`)
	conf := filepath.Join(t.TempDir(), "automatic.conf")
	if err := os.WriteFile(conf, []byte("[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SUN_DNF_CALL_LOG", callLog)
	t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", conf)

	pending, blocked, issues := collectDNFPackageFacts(true)
	if pending.Count != 1 || pending.Crit != 1 || len(pending.Packages) != 1 || pending.Packages[0] != "visible-2-1.fc43.x86_64" {
		t.Fatalf("pending=%+v", pending)
	}
	if got := strings.Join(blocked, ","); got != "excluded.aarch64,locked.noarch" {
		t.Fatalf("blocked=%q", got)
	}
	if len(issues) != 0 {
		t.Fatalf("issues=%v", issues)
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"-q advisory list --security --updates --json",
		"-q check-upgrade --security",
		"-q --setopt=disable_excludes=* check-upgrade --security",
		"-q --setopt=exclude= --setopt=excludepkgs= --setopt=*.excludepkgs= advisory list --security --updates --json",
		"-q check",
	} {
		if strings.Count(string(calls), want+"\n") != 1 {
			t.Fatalf("DNF5 command missing or repeated %q:\n%s", want, calls)
		}
	}
}

func TestCollectDNF5PackageFactsAcceptsNoSecurityUpdatesMessage(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  "-q advisory list --security --updates --json"|"-q --setopt=exclude= --setopt=excludepkgs= --setopt=*.excludepkgs= advisory list --security --updates --json")
    printf '%s\n' '[]'
    ;;
  "-q check-upgrade --security")
    printf '%s\n' 'No security updates needed, but 16 update(s) available'
    ;;
	"-q --setopt=disable_excludes=* check-upgrade --security")
	  printf '%s\n' 'No security updates needed, but 16 update(s) available'
	  ;;
  "-q check") ;;
  *) exit 2 ;;
esac
`)
	conf := filepath.Join(t.TempDir(), "automatic.conf")
	if err := os.WriteFile(conf, []byte("[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", conf)

	pending, blocked, issues := collectDNFPackageFacts(true)
	if pending.Count != 0 || len(blocked) != 0 || len(issues) != 0 {
		t.Fatalf("pending=%+v blocked=%v issues=%v", pending, blocked, issues)
	}
}

func TestCollectDNF5PackageFactsFallsBackToAdvisoriesWhenAssociationFails(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  "-q advisory list --security --updates --json")
    printf '%s\n' '[{"name":"FEDORA-2026-openssl","type":"security","severity":"Critical","nevra":"openssl-2-1.fc44.x86_64"}]'
    ;;
  "-q check-upgrade --security")
    printf '%s\n' 'kernel.x86_64 2-1.fc44 updates'
    exit 100
    ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)

	pending, blocked, issues := collectDNFPackageFacts(false)
	if pending.Count != 1 || pending.Crit != 1 || len(pending.Packages) != 1 || pending.Packages[0] != "openssl-2-1.fc44.x86_64" {
		t.Fatalf("advisory fallback pending=%+v", pending)
	}
	if len(blocked) != 0 || len(issues) != 0 {
		t.Fatalf("blocked=%v issues=%v", blocked, issues)
	}
}

func TestCollectDNF5PackageFactsReportsUnrestrictedQueryFailures(t *testing.T) {
	for _, failingCommand := range []string{"advisory", "transaction"} {
		t.Run(failingCommand, func(t *testing.T) {
			dir := t.TempDir()
			writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' 'dnf5 version 5.4.2.1' ;;
  "-q advisory list --security --updates --json"|"-q --setopt=exclude= --setopt=excludepkgs= --setopt=*.excludepkgs= advisory list --security --updates --json")
    if [ "$SUN_FAIL_DNF_QUERY" = advisory ] && [ "$*" != "-q advisory list --security --updates --json" ]; then
      printf '%s\n' 'failed to download metadata' >&2
      exit 2
    fi
    printf '%s\n' '[{"name":"FEDORA-2026-visible","type":"security","severity":"Important","nevra":"visible-2-1.fc44.x86_64"}]'
    ;;
  "-q check-upgrade --security")
    printf '%s\n' 'visible.x86_64 2-1.fc44 updates'
    exit 100
    ;;
  "-q --setopt=disable_excludes=* check-upgrade --security")
    if [ "$SUN_FAIL_DNF_QUERY" = transaction ]; then
      printf '%s\n' 'failed to download metadata' >&2
      exit 2
    fi
    printf '%s\n' 'visible.x86_64 2-1.fc44 updates'
    exit 100
    ;;
  "-q check") ;;
  *) exit 2 ;;
esac
`)
			conf := filepath.Join(t.TempDir(), "automatic.conf")
			if err := os.WriteFile(conf, []byte("[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			t.Setenv("SUN_FAIL_DNF_QUERY", failingCommand)
			t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", conf)

			pending, blocked, issues := collectDNFPackageFacts(true)
			if pending.Count != 1 || len(blocked) != 0 {
				t.Fatalf("pending=%+v blocked=%v", pending, blocked)
			}
			for _, code := range []string{"dnf-repository-failed", "dnf-blocked-query-failed"} {
				if !hasIssueCode(issues, code) {
					t.Fatalf("missing issue %q in %v", code, issues)
				}
			}
		})
	}
}

func TestCollectDNFPackageFactsReportsSuccessfulButIncompleteRepositoryQueries(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
case "$*" in
  "--version") printf '%s\n' '4.14.0' ;;
  "-q updateinfo list security")
    printf '%s\n' 'Ignoring repositories: security' >&2
    ;;
  "-q --disableplugin=versionlock --disableexcludes=all updateinfo list security")
    printf '%s\n' 'failed to download metadata for repo security' >&2
    exit 1
    ;;
  "-q check") ;;
  *) exit 2 ;;
esac
`)
	conf := filepath.Join(t.TempDir(), "automatic.conf")
	if err := os.WriteFile(conf, []byte("[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", conf)

	_, _, issues := collectDNFPackageFacts(true)
	for _, code := range []string{"dnf-repository-failed", "dnf-blocked-query-failed"} {
		if !hasIssueCode(issues, code) {
			t.Fatalf("missing issue %q in %v", code, issues)
		}
	}
}

func TestCollectDNFPackageFactsFailsClosedOnUnknownGeneration(t *testing.T) {
	for _, test := range []struct {
		name          string
		probe         string
		healthEnabled bool
		wantIssue     bool
	}{
		{name: "unknown output with health enabled", probe: "printf '%s\\n' 'dnf version future'", healthEnabled: true, wantIssue: true},
		{name: "failed probe with health enabled", probe: "printf '%s\\n' '4.14.0'; exit 2", healthEnabled: true, wantIssue: true},
		{name: "unknown output with health disabled", probe: "printf '%s\\n' 'dnf version future'", healthEnabled: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			callLog := filepath.Join(t.TempDir(), "dnf.calls")
			writeTestCommand(t, dir, "dnf", `
printf '%s\n' "$*" >> "$SUN_DNF_CALL_LOG"
if [ "$*" = "--version" ]; then
  `+test.probe+`
  exit 0
fi
printf '%s\n' 'unexpected non-probe command' >&2
exit 99
`)
			t.Setenv("PATH", dir)
			t.Setenv("SUN_DNF_CALL_LOG", callLog)

			pending, blocked, issues := collectDNFPackageFacts(test.healthEnabled)
			if pending.Count != 0 || len(blocked) != 0 {
				t.Fatalf("pending=%+v blocked=%v", pending, blocked)
			}
			if got := hasIssueCode(issues, "dnf-generation-probe-failed"); got != test.wantIssue {
				t.Fatalf("generation issue=%v want %v; issues=%v", got, test.wantIssue, issues)
			}
			calls, err := os.ReadFile(callLog)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(calls); got != "--version\n" {
				t.Fatalf("calls=%q; advisory or DNF4 fallback command executed", got)
			}
		})
	}
}

func TestCollectPatchWatchdogDeduplicatesStateFailures(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(statePath, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", statePath)
	cfg := patchTestConfig(t, "CHECK_UPDATE_HEALTH=0\nCHECK_SELF_UPDATE=0\n")
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)

	patch, pending := collectPatchWatchdog(cfg, "unsupported", backend.RestartState{
		RebootRequired:   true,
		RestartAttention: true,
	}, "2.7.3", patchCollectOptions{PersistState: true, Now: now})
	if pending.Count != 0 || !patch.RiskAttention {
		t.Fatalf("pending=%+v patch=%+v", pending, patch)
	}
	if strings.Count(patch.Sig, "patch-state-write") != 1 {
		t.Fatalf("state failure was not deduplicated: %q", patch.Sig)
	}
}

func TestCollectPatchWatchdogReportsRestartProbeFailure(t *testing.T) {
	cfg := patchTestConfig(t, "CHECK_UPDATE_HEALTH=0\nCHECK_SELF_UPDATE=0\n")
	patch, _ := collectPatchWatchdog(cfg, "unsupported", backend.RestartState{
		ProbeIssue: "dnf-restart-probe-failed",
	}, "3.0.2", patchCollectOptions{Now: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)})
	if !patch.RiskAttention || !strings.Contains(patch.Sig, "dnf-restart-probe-failed") {
		t.Fatalf("patch=%+v", patch)
	}
}

func TestCollectSelfUpdateReportsLookupAndStateErrors(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(statePath, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := patchTestConfig(t, "CHECK_SELF_UPDATE=1\n")
	wantLookupErr := errors.New("release endpoint unavailable")
	latest, available, checkErr, stateErr := collectSelfUpdate(cfg, "2.7.3", statefile.Store{Dir: statePath}, patchCollectOptions{
		PersistState: true,
		Now:          time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC),
		LatestRelease: func(*http.Client, string) (string, error) {
			return "", wantLookupErr
		},
	})
	if latest != "" || available || !errors.Is(checkErr, wantLookupErr) || stateErr == nil {
		t.Fatalf("latest=%q available=%v checkErr=%v stateErr=%v", latest, available, checkErr, stateErr)
	}
}

func TestInspectAPTMetadata(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	write := func(t *testing.T, name, validUntil string, modTime time.Time) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, name)
		body := "Origin: Debian\nValid-Until: " + validUntil + "\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("fresh security metadata", func(t *testing.T) {
		dir := write(t, "deb.debian.org_debian-security_dists_trixie-security_InRelease", now.Add(24*time.Hour).Format(time.RFC1123Z), now)
		if got := inspectAPTMetadata(dir, now, 7); len(got) != 0 {
			t.Fatalf("issues=%v", got)
		}
	})
	t.Run("expired", func(t *testing.T) {
		dir := write(t, "security_InRelease", now.Add(-time.Hour).Format(time.RFC1123Z), now)
		if !hasIssueCode(inspectAPTMetadata(dir, now, 7), "apt-metadata-expired") {
			t.Fatal("expired metadata was not reported")
		}
	})
	t.Run("stale", func(t *testing.T) {
		dir := write(t, "security_InRelease", now.Add(24*time.Hour).Format(time.RFC1123Z), now.Add(-8*24*time.Hour))
		if !hasIssueCode(inspectAPTMetadata(dir, now, 7), "apt-metadata-stale") {
			t.Fatal("stale metadata was not reported")
		}
	})
	t.Run("fresh non-security metadata does not mask stale security metadata", func(t *testing.T) {
		dir := t.TempDir()
		security := filepath.Join(dir, "debian-security_InRelease")
		main := filepath.Join(dir, "debian-main_InRelease")
		body := []byte("Valid-Until: " + now.Add(24*time.Hour).Format(time.RFC1123Z) + "\n")
		for _, path := range []string{security, main} {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chtimes(security, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(main, now, now); err != nil {
			t.Fatal(err)
		}
		if !hasIssueCode(inspectAPTMetadata(dir, now, 7), "apt-metadata-stale") {
			t.Fatal("fresh non-security metadata masked stale security metadata")
		}
	})
}

func TestCollectSelfUpdateCacheForceAndSkip(t *testing.T) {
	cfg := patchTestConfig(t, "CHECK_SELF_UPDATE=1\nSELF_UPDATE_CHECK_DAYS=7\n")
	store := statefile.Store{Dir: t.TempDir()}
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	calls := 0
	lookup := func(_ *http.Client, repo string) (string, error) {
		calls++
		if repo != Repo {
			t.Fatalf("repo=%q", repo)
		}
		return "2.2.5", nil
	}

	latest, available, checkErr, stateErr := collectSelfUpdate(cfg, "2.2.4", store, patchCollectOptions{
		PersistState: true, Now: now, LatestRelease: lookup,
	})
	if latest != "2.2.5" || !available || checkErr != nil || stateErr != nil || calls != 1 {
		t.Fatalf("first check latest=%q available=%v checkErr=%v stateErr=%v calls=%d", latest, available, checkErr, stateErr, calls)
	}

	latest, available, checkErr, stateErr = collectSelfUpdate(cfg, "2.2.4", store, patchCollectOptions{
		PersistState: true, Now: now.Add(6 * 24 * time.Hour), LatestRelease: lookup,
	})
	if latest != "2.2.5" || !available || checkErr != nil || stateErr != nil || calls != 1 {
		t.Fatalf("cached check latest=%q available=%v checkErr=%v stateErr=%v calls=%d", latest, available, checkErr, stateErr, calls)
	}

	latest, available, checkErr, stateErr = collectSelfUpdate(cfg, "2.2.4", store, patchCollectOptions{
		ForceSelfUpdate: true, Now: now.Add(6 * 24 * time.Hour), LatestRelease: lookup,
	})
	if latest != "2.2.5" || !available || checkErr != nil || stateErr != nil || calls != 2 {
		t.Fatalf("forced check latest=%q available=%v checkErr=%v stateErr=%v calls=%d", latest, available, checkErr, stateErr, calls)
	}

	latest, available, checkErr, stateErr = collectSelfUpdate(cfg, "2.2.4", store, patchCollectOptions{
		SkipSelfUpdate: true, Now: now.Add(8 * 24 * time.Hour), LatestRelease: lookup,
	})
	if latest != "" || available || checkErr != nil || stateErr != nil || calls != 2 {
		t.Fatalf("skipped check latest=%q available=%v checkErr=%v stateErr=%v calls=%d", latest, available, checkErr, stateErr, calls)
	}
}

func TestTrackedAgeReadOnlyDoesNotWriteOrRemove(t *testing.T) {
	dir := t.TempDir()
	store := statefile.Store{Dir: dir}
	now := int64(1_722_000_000)
	if age, err := trackedAgeDays(store, "pending-security.first_seen", true, now, false); err != nil || age != 0 {
		t.Fatalf("missing read-only state age=%d err=%v", age, err)
	}
	path := filepath.Join(dir, "pending-security.first_seen")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only tracking created state: %v", err)
	}
	if err := store.WriteInt("pending-security.first_seen", now-4*86400); err != nil {
		t.Fatal(err)
	}
	if age, err := trackedAgeDays(store, "pending-security.first_seen", false, now, false); err != nil || age != 0 {
		t.Fatalf("inactive read-only state age=%d err=%v", age, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("read-only tracking removed state: %v", err)
	}
}

func patchTestConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func hasIssueCode(issues []watchdog.Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
