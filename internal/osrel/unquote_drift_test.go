package osrel

import "testing"

// TestUnquoteDoubleWrapped 守护与 Bash/lib.sh os-release 解析一致：顺序剥离引号（先双后单），
// "'debian'" -> debian。早返回只剥一层会导致 Go 与 Bash 的 BACKEND（去重 hash 字段）分歧。
func TestUnquoteDoubleWrapped(t *testing.T) {
	cases := map[string]string{
		`"'debian'"`: "debian",
		`"debian"`:   "debian",
		`'debian'`:   "debian",
		`debian`:     "debian",
	}
	for in, want := range cases {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}
