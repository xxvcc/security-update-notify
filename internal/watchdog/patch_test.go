package watchdog

import (
	"strings"
	"testing"
)

func TestCheckPatchAllSignals(t *testing.T) {
	p := CheckPatch(PatchInput{
		Pending: Pending{Count: 3}, PendingAgeDays: 4, PendingAlertDays: 3,
		BlockedPackages: []string{"openssl", "kernel", "openssl"},
		Issues:          []Issue{{Code: "apt-policy", ZH: "APT 策略漂移", EN: "APT policy drift"}},
		RebootAgeDays:   8, ServiceAgeDays: 7, RestartAlertDays: 7,
		CurrentVersion: "2.2.4", LatestVersion: "2.2.5", SelfUpdateAvailable: true,
	})
	if !p.RiskAttention || !p.UpdateAvailable {
		t.Fatalf("risk=%v update=%v", p.RiskAttention, p.UpdateAvailable)
	}
	for _, reason := range []string{"pending-stale", "apt-policy", "reboot-stale", "service-restart-stale", "blocked-packages-", "sun-update-"} {
		if !strings.Contains(p.Sig, reason) {
			t.Errorf("Sig %q missing %q", p.Sig, reason)
		}
	}
	if !strings.HasSuffix(p.Sig, ",") {
		t.Errorf("Sig=%q has no trailing comma", p.Sig)
	}
	if !strings.Contains(p.TxtZH, "连续存在 4 天") || !strings.Contains(p.UpdateTxtEN, "2.2.5") {
		t.Errorf("unexpected text zh=%q update=%q", p.TxtZH, p.UpdateTxtEN)
	}
}

func TestCheckPatchBelowThresholdIsInformational(t *testing.T) {
	p := CheckPatch(PatchInput{Pending: Pending{Count: 1}, PendingAgeDays: 2, PendingAlertDays: 3})
	if p.RiskAttention || p.Sig != "" {
		t.Fatalf("risk=%v sig=%q", p.RiskAttention, p.Sig)
	}
}

func TestMergeSignals(t *testing.T) {
	if got := MergeSignals("disk,disabled,", "pending-stale,disk,"); got != "disabled,disk,pending-stale," {
		t.Fatalf("MergeSignals=%q", got)
	}
}

func TestStableReasonWireValue(t *testing.T) {
	if got := StableReason("blocked-packages", []string{"openssl"}); got != "blocked-packages-41ffca929b95" {
		t.Fatalf("StableReason=%q", got)
	}
}
