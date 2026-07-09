package config

import "testing"

// TestParseValueDoubleWrappedSingle 守护与 Bash load_config_file 的字节级一致：值的引号剥离必须
// 顺序进行（先双后单），"'x'" -> x。早返回只剥一层，会让 Go 与 Bash 回退运行时读出不同值。
func TestParseValueDoubleWrappedSingle(t *testing.T) {
	cases := map[string]string{
		`"'web'"`: "web",   // 双包单：两层都剥（与 Bash 一致）
		`"web"`:   "web",   // 仅双引号
		`'web'`:   "web",   // 仅单引号
		`'"web"'`: `"web"`, // 单包双：只剥外层单引号
		`web`:     "web",   // 无引号
	}
	for in, want := range cases {
		if got := parseValue(in); got != want {
			t.Errorf("parseValue(%q) = %q, want %q", in, got, want)
		}
	}
}
