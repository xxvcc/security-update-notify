package dedup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/golden"
)

// TestHashMatchesGolden 是全 Go 端口的核心不变量：对每个受控场景，用 Go 重建其 11 个字段并计算
// alert_hash，必须逐字节等于“真·Bash 运行时”写入 STATE_FILE 的 hash。任一不符即字节漂移回归。
// 各场景的派生字段（restart_signal 等）取值已由 internal/backend 的解析器测试独立守护。
func TestHashMatchesGolden(t *testing.T) {
	want, err := golden.ByName()
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]Fields{
		// --test-reboot：check_apt/check_dnf 直接置固定值，restart_signal 未设 -> 空。
		"apt-test-reboot-zh": {Host: "golden-host", Backend: "apt", NotifyLang: "zh",
			RebootRequired: true, RebootPkgs: "linux-image-amd64\nTEST-MODE-no-real-reboot", RestartAttention: true},
		"apt-test-reboot-en": {Host: "golden-host", Backend: "apt", NotifyLang: "en",
			RebootRequired: true, RebootPkgs: "linux-image-amd64\nTEST-MODE-no-real-reboot", RestartAttention: true},
		"dnf-test-reboot-zh": {Host: "golden-host", Backend: "dnf", NotifyLang: "zh",
			RebootRequired: true, RebootPkgs: "kernel\nTEST-MODE-no-real-reboot", RestartAttention: true},
		"dnf-test-reboot-en": {Host: "golden-host", Backend: "dnf", NotifyLang: "en",
			RebootRequired: true, RebootPkgs: "kernel\nTEST-MODE-no-real-reboot", RestartAttention: true},
		// needrestart 服务场景：signal = 成帧后 TrimRight（见 backend 测试）。
		"apt-needrestart-svc-zh": {Host: "golden-host", Backend: "apt", NotifyLang: "zh",
			RestartAttention: true,
			RestartSignal:    "KCUR=6.1.0-43-amd64\nKEXP=6.1.0-44-amd64\nKSTA=3\nnginx.service\nssh.service"},
		// dnf 服务场景：signal = 排序去重的服务列表。
		"dnf-services-zh": {Host: "golden-host", Backend: "dnf", NotifyLang: "zh",
			RestartAttention: true, RestartSignal: "crond.service\nsshd.service"},
		// 看门狗：定时器禁用 -> HEALTH_SIG 带尾逗号；needrestart 空输出 -> signal="KCUR=\nKEXP=\nKSTA=".
		"apt-health-disabled-zh": {Host: "golden-host", Backend: "apt", NotifyLang: "zh",
			RestartSignal: "KCUR=\nKEXP=\nKSTA=", HealthAttention: true, HealthSig: "disabled,"},
		// ok 路径：无任何关注信号。
		"dnf-ok-pubip-zh": {Host: "golden-host", Backend: "dnf", NotifyLang: "zh"},
	}
	if len(fields) != len(want) {
		t.Fatalf("test covers %d scenarios but golden has %d", len(fields), len(want))
	}
	for name, f := range fields {
		v, ok := want[name]
		if !ok {
			t.Errorf("golden missing scenario %q", name)
			continue
		}
		if got := Hash(f); got != v.Hash {
			t.Errorf("scenario %s: Hash=\n  %s\nwant golden\n  %s", name, got, v.Hash)
		}
	}
}

func TestShouldSend(t *testing.T) {
	base := time.Date(2026, 1, 15, 12, 0, 0, 0, time.Local).Unix()
	sameDay := time.Date(2026, 1, 15, 13, 30, 0, 0, time.Local).Unix()
	nextDay := time.Date(2026, 1, 16, 12, 0, 0, 0, time.Local).Unix()
	cases := []struct {
		name        string
		noDedupe    bool
		cur, last   string
		lastSent    int64
		now         int64
		mode        string
		intervalDay int
		want        bool
	}{
		{"no-dedupe", true, "h", "h", base, sameDay, "once", 3, true},
		{"hash-changed", false, "h2", "h1", base, sameDay, "once", 3, true},
		{"once-same", false, "h", "h", base, sameDay, "once", 3, false},
		{"always-alias", false, "h", "h", base, nextDay, "always", 3, false},
		{"daily-same-day", false, "h", "h", base, sameDay, "daily", 3, false},
		{"daily-next-day", false, "h", "h", base, nextDay, "daily", 3, true},
		{"interval-within", false, "h", "h", base, base + 86400, "interval", 3, false},
		{"interval-beyond", false, "h", "h", base, base + 3*86400, "interval", 3, true},
		{"interval-bad-days-defaults-3", false, "h", "h", base, base + 2*86400, "interval", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ShouldSend(c.noDedupe, c.cur, c.last, c.lastSent, c.now, c.mode, c.intervalDay); got != c.want {
				t.Errorf("ShouldSend=%v want %v", got, c.want)
			}
		})
	}
}

func TestStoreRoundTripAndAtomicity(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	const h = "00a3b010b6e4c28057bef281ca8e4241002807c170998e4191466e919aa43415"
	if err := s.Write(h, 1737000000); err != nil {
		t.Fatal(err)
	}
	gotH, gotT := s.ReadLast()
	if gotH != h || gotT != 1737000000 {
		t.Errorf("readback hash=%q t=%d want %q 1737000000", gotH, gotT, gotT)
	}
	// 状态文件应无尾部多余换行以外的内容，且不留临时文件。
	raw, _ := os.ReadFile(s.HashFile)
	if string(raw) != h+"\n" {
		t.Errorf("hash file = %q want %q", raw, h+"\n")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".state.*"))
	if len(leftovers) != 0 {
		t.Errorf("leftover temp files: %v", leftovers)
	}
}

func TestReadLastTrimsNewlines(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	// 模拟带尾换行的旧状态文件（Bash printf '%s\n'）。
	os.WriteFile(s.HashFile, []byte("deadbeef\n\n"), 0o600)
	os.WriteFile(s.TimeFile, []byte("1737000000\n"), 0o600)
	h, ts := s.ReadLast()
	if h != "deadbeef" || ts != 1737000000 {
		t.Errorf("ReadLast=%q,%d want deadbeef,1737000000", h, ts)
	}
}
