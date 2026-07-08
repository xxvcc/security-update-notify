package golden

import (
	"regexp"
	"testing"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Phase 0 的守卫：黄金向量文件结构良好且非空。Phase 1 的 internal/dedup / internal/notify 会新增
// 真正复刻 Hash / Message 的测试；此测试只保证 oracle 本身没被损坏或清空。
//
// Phase 0 guard: the golden file is well-formed and non-empty. Phase 1's internal/dedup / internal/notify
// add the tests that actually reproduce Hash / Message; this only guarantees the oracle itself is intact.
func TestGoldenVectorsWellFormed(t *testing.T) {
	vs, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) < 8 {
		t.Fatalf("expected >=8 golden vectors, got %d", len(vs))
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if v.Name == "" {
			t.Error("vector with empty name")
		}
		if seen[v.Name] {
			t.Errorf("duplicate vector name %q", v.Name)
		}
		seen[v.Name] = true
		if !hex64.MatchString(v.Hash) {
			t.Errorf("%s: hash is not 64 lowercase hex: %q", v.Name, v.Hash)
		}
		// 只有发送了通知的场景才有正文；OK-silent 场景无 message 但仍有 hash。这里覆盖的都发送了。
		if v.Message == "" {
			t.Errorf("%s: expected a captured message", v.Name)
		}
	}
	// 锁定几个具名的 landmine 场景确实在集合里。
	for _, must := range []string{"apt-test-reboot-zh", "apt-test-reboot-en", "apt-needrestart-svc-zh", "apt-health-disabled-zh", "dnf-ok-pubip-zh"} {
		if !seen[must] {
			t.Errorf("missing required scenario %q", must)
		}
	}
}
