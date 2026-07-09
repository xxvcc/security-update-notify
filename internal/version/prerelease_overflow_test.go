package version

import "testing"

// TestCmpNumericStr 守护数字标识符按值比较且不受 int64 溢出影响（旧代码用 strconv.Atoi，>int64
// 会 clamp 到 MaxInt64，把不同大数误判为相等）。
func TestCmpNumericStr(t *testing.T) {
	cases := []struct {
		x, y string
		want int
	}{
		{"11111111111111111111", "99999999999999999999", -1}, // 20 位，均 >int64
		{"99999999999999999999", "11111111111111111111", 1},
		{"01", "1", 0}, // 前导零，数值相等
		{"10", "9", 1}, // 位数不同
		{"9", "10", -1},
		{"007", "7", 0},
	}
	for _, c := range cases {
		if got := cmpNumericStr(c.x, c.y); got != c.want {
			t.Errorf("cmpNumericStr(%q,%q) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
}

// TestComparePrereleaseMatchesPythonReference 守护与 Bash 内嵌 python cmp_pre 的一致：数字段值相等
// 即返回相等（0），不再比后续段；且大数不因溢出误判相等。
func TestComparePrereleaseMatchesPythonReference(t *testing.T) {
	// ("1","01") 值相等 -> python 立即 return 0（忽略后续 alpha/beta），Go 必须一致
	if c, err := Compare("1.0.0-1.alpha", "1.0.0-01.beta"); err != nil || c != 0 {
		t.Errorf("Compare(1.0.0-1.alpha,1.0.0-01.beta) = %d,%v; want 0,nil", c, err)
	}
	// 20 位大数不同 -> 必须区分方向（不因溢出判等）
	if c, err := Compare("1.0.0-99999999999999999999", "1.0.0-11111111111111111111"); err != nil || c <= 0 {
		t.Errorf("Compare(big-9s,big-1s) = %d,%v; want >0,nil", c, err)
	}
}
