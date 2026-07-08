package version

import "testing"

// 与 CI 里 is_newer_version 的表用例一一对应，锁定 Go 实现与 Bash/Python 行为等价。
// Mirrors the is_newer_version CI table so the Go implementation stays equivalent to Bash/Python.
func TestIsNewer(t *testing.T) {
	cases := []struct {
		cur, lat string
		want     bool
	}{
		{"1.0.0-rc1", "1.0.0", true},     // rc -> 正式版是升级（sort -V 的 bug）
		{"1.0.0", "1.0.0-rc1", false},    // 正式版不低于自身预发布
		{"1.0.0-rc1", "1.0.0-rc2", true}, // rc 递增
		{"1.0.0-rc2", "1.0.0-rc1", false},
		{"1.9.3", "1.9.4", true},
		{"1.9.4", "1.9.3", false},
		{"1.9.3", "1.9.3", false},  // 相等 -> 非更新
		{"1.7.0", "1.7.0.1", true}, // 多段（旧 %08d 截断 bug）
		{"1.7.0.1", "1.7.0", false},
		{"1.7.0", "1.7.0.0", false}, // 补零相等
		{"v1.2.3", "v1.2.4", true},  // 容忍前导 v
		{"1.2.3", "v1.2.3", false},
		{"1.2.9", "1.3.0", true},
		{"2.0.0", "1.9.9", false},
		{"1.0.0-1", "1.0.0-alpha", true}, // 数字标识符 < 字母标识符
		{"1.0.0-alpha", "1.0.0-alpha.1", true},
		{"1.0.0-alpha.1", "1.0.0-alpha", false},
		{"1.0.junk", "2.0.0", false}, // 畸形 -> fail-closed
		{"1.0.0", "not-a-ver", false},
		{"1.9.3", "1_0.0.0", false}, // 下划线不得解析为伪数值
		{"", "1.0.0", false},        // 空串 -> 非更新
		{"1.0.0", "", false},
	}
	for _, c := range cases {
		if got := IsNewer(c.cur, c.lat); got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", c.cur, c.lat, got, c.want)
		}
	}
}

// 相等版本在两种写法下都应判为非更新。
func TestCompareEquivalence(t *testing.T) {
	for _, p := range [][2]string{{"1.9.4", "v1.9.4"}, {"1.0.0+build1", "1.0.0+build2"}} {
		c, err := Compare(p[0], p[1])
		if err != nil || c != 0 {
			t.Errorf("Compare(%q,%q)=%d,%v want 0,nil", p[0], p[1], c, err)
		}
	}
}
