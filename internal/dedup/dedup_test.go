package dedup

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
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
		{"daily-clock-rollback", false, "h", "h", base + 3600, base, "daily", 3, true},
		{"interval-clock-rollback", false, "h", "h", base + 3600, base, "interval", 3, true},
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

func TestShouldSendDoesNotOverflowHugeInterval(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	if int64(maxInt) <= math.MaxInt64/86400 {
		t.Skip("int is too narrow to construct an overflowing day interval")
	}
	if ShouldSend(false, "same", "same", 1, math.MaxInt64, "interval", maxInt) {
		t.Fatal("an interval too large to elapse was treated as expired")
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
		t.Errorf("readback hash=%q t=%d want %q 1737000000", gotH, gotT, h)
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

func TestStoreSyncsEachFileBeforeRenameAndDirectoryAfterRename(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if err := os.WriteFile(store.HashFile, []byte("old-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.TimeFile, []byte("100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	phase := 0
	store.fileSync = func(file *os.File) error {
		phase++
		contents, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		switch phase {
		case 1:
			if string(contents) != "200\n" {
				t.Fatalf("first temporary file=%q, want timestamp", contents)
			}
		case 3:
			if string(contents) != "new-hash\n" {
				t.Fatalf("second temporary file=%q, want hash", contents)
			}
		default:
			t.Fatalf("temporary file sync occurred at phase %d", phase)
		}
		return file.Sync()
	}
	store.directorySync = func(directory *os.File) error {
		phase++
		hash, hashErr := os.ReadFile(store.HashFile)
		sentAt, timeErr := os.ReadFile(store.TimeFile)
		if hashErr != nil || timeErr != nil {
			t.Fatalf("read committed state: hashErr=%v timeErr=%v", hashErr, timeErr)
		}
		switch phase {
		case 2:
			if string(hash) != "old-hash\n" || string(sentAt) != "200\n" {
				t.Fatalf("first rename state=(%q,%q), want old hash and new timestamp", hash, sentAt)
			}
		case 4:
			if string(hash) != "new-hash\n" || string(sentAt) != "200\n" {
				t.Fatalf("second rename state=(%q,%q), want new hash and timestamp", hash, sentAt)
			}
		default:
			t.Fatalf("directory sync occurred at phase %d", phase)
		}
		return directory.Sync()
	}
	if err := store.Write("new-hash", 200); err != nil {
		t.Fatal(err)
	}
	if phase != 4 {
		t.Fatalf("completed at phase %d, want 4", phase)
	}
}

func TestStoreHashSyncFailureKeepsCrashBiasTowardResending(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if err := os.WriteFile(store.HashFile, []byte("old-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.TimeFile, []byte("100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("hash sync failed")
	syncs := 0
	store.fileSync = func(file *os.File) error {
		syncs++
		if syncs == 2 {
			return wantErr
		}
		return file.Sync()
	}
	if err := store.Write("new-hash", 200); !errors.Is(err, wantErr) {
		t.Fatalf("Write error=%v, want %v", err, wantErr)
	}
	hash, sentAt := NewStore(dir).ReadLast()
	if hash != "old-hash" || sentAt != 200 {
		t.Fatalf("failed hash sync state=(%q,%d), want old hash and new timestamp", hash, sentAt)
	}
	if !ShouldSend(false, "new-hash", hash, sentAt, 200, "daily", 3) {
		t.Fatal("failed hash sync could silently suppress the delivered alert")
	}
	if leftovers, err := filepath.Glob(filepath.Join(dir, ".state.*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("hash sync failure left temporary files: files=%v err=%v", leftovers, err)
	}
}

func TestStoreWriteFailurePreservesExistingState(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Write("old-hash", 1737000000); err != nil {
		t.Fatal(err)
	}
	store.Dir = filepath.Join(dir, "missing", "state")
	if err := store.Write("new-hash", 1738000000); err == nil {
		t.Fatal("expected state write failure")
	}
	hash, sentAt := NewStore(dir).ReadLast()
	if hash != "old-hash" || sentAt != 1737000000 {
		t.Fatalf("failed write changed state to %q,%d", hash, sentAt)
	}
}

func TestStoreCommitsTimestampBeforeHash(t *testing.T) {
	dir := t.TempDir()
	hashTarget := filepath.Join(dir, "hash-target")
	if err := os.Mkdir(hashTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	timeTarget := filepath.Join(dir, "sent-at")
	if err := os.WriteFile(timeTarget, []byte("100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &Store{Dir: dir, HashFile: hashTarget, TimeFile: timeTarget}
	if err := store.Write("new-hash", 200); err == nil {
		t.Fatal("expected hash rename failure")
	}
	b, err := os.ReadFile(timeTarget)
	if err != nil || string(b) != "200\n" {
		t.Fatalf("timestamp was not committed before hash: %q err=%v", b, err)
	}
	if !ShouldSend(false, "new-hash", "old-hash", 200, 200, "daily", 3) {
		t.Fatal("old hash plus new timestamp suppressed a newly delivered alert")
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

func TestReadLastIgnoresOversizedStateFiles(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := os.WriteFile(s.HashFile, []byte(string(make([]byte, 257))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.TimeFile, []byte(string(make([]byte, 65))), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, sentAt := s.ReadLast()
	if hash != "" || sentAt != 0 {
		t.Fatalf("oversized state accepted: hash=%q sentAt=%d", hash, sentAt)
	}
}

func TestReadLastRejectsSymlinksAndFIFOsWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("attacker-controlled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.HashFile); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(store.TimeFile, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		hash, sentAt := store.ReadLast()
		if hash != "" || sentAt != 0 {
			t.Errorf("special-file state accepted: hash=%q sentAt=%d", hash, sentAt)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadLast blocked on a FIFO")
	}
}

func TestStateFileMetadataRequiresOwnerAndProtectedModeButAllowsHardlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateFile(path, 64, os.Geteuid()+1); err == nil {
		t.Fatal("wrong-owner state file was accepted")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateFile(path, 64, os.Geteuid()); err == nil {
		t.Fatal("group/other-writable state file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state-link")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if got, err := readStateFile(link, 64, os.Geteuid()); err != nil || string(got) != "value\n" {
		t.Fatalf("protected hardlinked state=(%q, %v)", got, err)
	}
}

func TestStoreRejectsUnsafeDirectoryForReadAndWrite(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if err := os.WriteFile(store.HashFile, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.TimeFile, []byte("100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if hash, sentAt := store.ReadLast(); hash != "" || sentAt != 0 {
		t.Fatalf("unsafe directory state was read: %q,%d", hash, sentAt)
	}
	if err := store.Write("new", 200); err == nil {
		t.Fatal("unsafe directory accepted a state write")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("unsafe directory was chmodded to %#o", info.Mode().Perm())
	}
}

func TestStoreOperationsStayBoundToValidatedDirectoryAfterPathExchange(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "state")
			replacement := filepath.Join(root, "replacement")
			openedDirectory := filepath.Join(root, "opened-state")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(replacement, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, fixture := range []struct {
				name, validated, replaced string
			}{
				{name: "last-alert.sha256", validated: "validated-hash\n", replaced: "replacement-hash\n"},
				{name: "last-alert.sent_at", validated: "100\n", replaced: "200\n"},
			} {
				if err := os.WriteFile(filepath.Join(directory, fixture.name), []byte(fixture.validated), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(replacement, fixture.name), []byte(fixture.replaced), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			store := NewStore(directory)
			store.afterDirectoryOpen = func() {
				if err := os.Rename(directory, openedDirectory); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(replacement, directory); err != nil {
					t.Fatal(err)
				}
			}

			if operation == "read" {
				hash, sentAt := store.ReadLast()
				if hash != "validated-hash" || sentAt != 100 {
					t.Fatalf("ReadLast()=(%q, %d), want validated directory state", hash, sentAt)
				}
			} else {
				if err := store.Write("new-hash", 300); err != nil {
					t.Fatal(err)
				}
				opened := NewStore(openedDirectory)
				if hash, sentAt := opened.ReadLast(); hash != "new-hash" || sentAt != 300 {
					t.Fatalf("validated directory state=(%q, %d)", hash, sentAt)
				}
			}

			replaced := NewStore(replacement)
			if hash, sentAt := replaced.ReadLast(); hash != "replacement-hash" || sentAt != 200 {
				t.Fatalf("replacement directory was modified: (%q, %d)", hash, sentAt)
			}
		})
	}
}

func TestChannelStoreUsesIndependentFiles(t *testing.T) {
	dir := t.TempDir()
	legacy := NewStore(dir)
	feishu := NewChannelStore(dir, "feishu")
	if legacy.HashFile == feishu.HashFile || legacy.TimeFile == feishu.TimeFile ||
		legacy.TargetFile == feishu.TargetFile || legacy.TargetPendingFile == feishu.TargetPendingFile {
		t.Fatal("channel store must not share legacy Telegram files")
	}
	if filepath.Base(feishu.HashFile) != "last-alert.feishu.sha256" || filepath.Base(feishu.TimeFile) != "last-alert.feishu.sent_at" {
		t.Errorf("unexpected channel paths: %s %s", feishu.HashFile, feishu.TimeFile)
	}
}

func TestTargetFingerprintUsesStableIdentityParts(t *testing.T) {
	first := TargetFingerprint("telegram", "123456", "-100123")
	second := TargetFingerprint("telegram", "123456", "-100123")
	if first != second || !validFingerprint(first) {
		t.Fatalf("unstable target fingerprint: %q %q", first, second)
	}
	for _, changed := range []string{
		TargetFingerprint("telegram", "654321", "-100123"),
		TargetFingerprint("telegram", "123456", "-100999"),
		TargetFingerprint("feishu", "123456", "-100123"),
	} {
		if changed == first {
			t.Fatal("distinct target identity produced the same fingerprint")
		}
	}
}

func TestTargetStatusPreservesLegacyStateAndDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	current := TargetFingerprint("telegram", "123456", "-100123")
	if got := store.ReadTargetStatus(current); got != TargetLegacy {
		t.Fatalf("missing upgrade fingerprint status=%v want legacy", got)
	}
	if err := store.WriteDelivery("alert-hash", 100, current); err != nil {
		t.Fatal(err)
	}
	if got := store.ReadTargetStatus(current); got != TargetCurrent {
		t.Fatalf("persisted target status=%v want current", got)
	}
	if got := store.ReadTargetStatus(TargetFingerprint("telegram", "123456", "-100999")); got != TargetChanged {
		t.Fatalf("changed target status=%v want changed", got)
	}
	if _, err := os.Stat(store.TargetPendingFile); !os.IsNotExist(err) {
		t.Fatalf("completed delivery left pending marker: %v", err)
	}
}

func TestTargetPendingMarkerForcesDeliveryWithoutContainingIdentity(t *testing.T) {
	store := NewChannelStore(t.TempDir(), "feishu")
	current := TargetFingerprint("feishu", "cli_app", "ou_recipient")
	if err := os.WriteFile(store.TargetPendingFile, []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := store.ReadTargetStatus(current); got != TargetChanged {
		t.Fatalf("pending target status=%v want changed", got)
	}
	b, err := os.ReadFile(store.TargetPendingFile)
	if err != nil || string(b) != "pending\n" {
		t.Fatalf("pending marker=%q err=%v", b, err)
	}
}

func TestAdoptLegacyTargetDoesNotChangeAlertState(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := store.Write("old-hash", 100); err != nil {
		t.Fatal(err)
	}
	current := TargetFingerprint("telegram", "123456", "-100123")
	if err := store.AdoptLegacyTarget(current); err != nil {
		t.Fatal(err)
	}
	if got := store.ReadTargetStatus(current); got != TargetCurrent {
		t.Fatalf("adopted status=%v want current", got)
	}
	if hash, sentAt := store.ReadLast(); hash != "old-hash" || sentAt != 100 {
		t.Fatalf("adoption changed alert state=(%q,%d)", hash, sentAt)
	}
	if err := store.AdoptLegacyTarget(current); err != nil {
		t.Fatalf("idempotent adoption failed: %v", err)
	}
	if err := os.WriteFile(store.TargetPendingFile, []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.AdoptLegacyTarget(current); err == nil {
		t.Fatal("adoption ignored a pending target change")
	}
}

func TestWriteDeliveryFailureLeavesPendingMarkerToBiasTowardResend(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Write("old-hash", 100); err != nil {
		t.Fatal(err)
	}
	current := TargetFingerprint("telegram", "123456", "-100999")
	wantErr := errors.New("timestamp sync failed")
	syncs := 0
	store.fileSync = func(file *os.File) error {
		syncs++
		if syncs == 3 {
			return wantErr
		}
		return file.Sync()
	}
	if err := store.WriteDelivery("new-hash", 200, current); !errors.Is(err, wantErr) {
		t.Fatalf("WriteDelivery error=%v want %v", err, wantErr)
	}
	if got := store.ReadTargetStatus(current); got != TargetChanged {
		t.Fatalf("interrupted delivery status=%v want changed", got)
	}
	if _, err := os.Stat(store.TargetPendingFile); err != nil {
		t.Fatalf("interrupted delivery lost pending marker: %v", err)
	}
	hash, sentAt := store.ReadLast()
	if hash != "old-hash" || sentAt != 100 {
		t.Fatalf("interrupted alert state=(%q,%d), want old state", hash, sentAt)
	}
}
