// Package version 复刻 files/security-update-notify 里 is_newer_version 的 python 语义化版本
// 比较器：数字段逐段比较（缺省段补 0），pre-release 后缀按 semver 规则排序，任何解析失败一律
// fail-closed（视为“非更新”），使其可无守卫地替换 Bash 侧的自升级门。
//
// Package version reproduces the python semantic-version comparator embedded in
// files/security-update-notify (is_newer_version): numeric segments compared pairwise (missing = 0),
// pre-release suffixes ranked per semver, any parse failure fails closed (treated as "not newer") so
// it can replace the Bash self-upgrade gate without guards.
package version

import (
	"errors"
	"strconv"
	"strings"
)

// parsedVersion 拆成 release 数字段与 pre-release 后缀。
// parsedVersion splits a version into numeric release segments and a pre-release suffix.
type parsedVersion struct {
	rel []int
	pre string
}

var errBadVersion = errors.New("unparseable version")

// parseVersion 复刻 python 比较器的解析规则：去掉前导 v、丢弃 +构建元数据、按首个 '-' 切出
// pre-release；release 数字段仅接受纯 ASCII 数字（拒绝下划线、Unicode 数字等），任何畸形一律
// 报错，交由上层 fail-closed。
func parseVersion(v string) (parsedVersion, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // 构建元数据不参与优先级 / build metadata ignored
		v = v[:i]
	}
	rel, pre := v, ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		rel, pre = v[:i], v[i+1:]
	}
	if rel == "" {
		rel = "0"
	}
	parts := strings.Split(rel, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		if !isASCIIDigits(p) {
			return parsedVersion{}, errBadVersion
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return parsedVersion{}, errBadVersion
		}
		nums[i] = n
	}
	return parsedVersion{rel: nums, pre: pre}, nil
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cmpNumericStr 比较两个纯十进制数字串的数值（等价 python int() 比较），不经 strconv 故不会溢出：
// 先去前导零，位数多者更大，位数相同则按字典序。返回 -1/0/1。
func cmpNumericStr(x, y string) int {
	x = strings.TrimLeft(x, "0")
	y = strings.TrimLeft(y, "0")
	if len(x) != len(y) {
		if len(x) < len(y) {
			return -1
		}
		return 1
	}
	if x < y {
		return -1
	}
	if x > y {
		return 1
	}
	return 0
}

// cmpRelease 逐段比较，缺省段按 0 补齐（故 1.7.0.1 > 1.7.0）。
func cmpRelease(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// cmpPre 按 semver 规则比较 pre-release 后缀：无后缀 > 有后缀；数字标识符按值、且优先级低于
// 字母标识符；前缀相同则字段多者更大。
func cmpPre(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" { // 无预发布后缀 > 有预发布后缀 / a release outranks its pre-releases
		return 1
	}
	if b == "" {
		return -1
	}
	ai := strings.Split(a, ".")
	bi := strings.Split(b, ".")
	n := len(ai)
	if len(bi) < n {
		n = len(bi)
	}
	for i := 0; i < n; i++ {
		x, y := ai[i], bi[i]
		if x == y {
			continue
		}
		xn, yn := isASCIIDigits(x), isASCIIDigits(y)
		if xn && yn {
			// 复刻 python 参考实现 `return (int(x)>int(y))-(int(x)<int(y))`：数字标识符按值比较并
			// 立即返回（值相等即返回 0，结束整个 pre-release 比较）。用 cmpNumericStr 做任意长度的
			// 十进制比较，避免 strconv.Atoi 对 >int64 标识符溢出（会把不同大数误判为相等）。
			return cmpNumericStr(x, y)
		}
		if xn != yn { // 数字标识符优先级低于字母标识符 / numeric < alphanumeric
			if xn {
				return -1
			}
			return 1
		}
		if x < y {
			return -1
		}
		return 1
	}
	switch {
	case len(ai) < len(bi):
		return -1
	case len(ai) > len(bi):
		return 1
	default:
		return 0
	}
}

// Compare 返回 <0 (v1<v2) / 0 (相等) / >0 (v1>v2)；任一侧解析失败返回 error。
// Compare returns <0/0/>0 for v1 vs v2; an error if either side is unparseable.
func Compare(v1, v2 string) (int, error) {
	p1, err := parseVersion(v1)
	if err != nil {
		return 0, err
	}
	p2, err := parseVersion(v2)
	if err != nil {
		return 0, err
	}
	if c := cmpRelease(p1.rel, p2.rel); c != 0 {
		return c, nil
	}
	return cmpPre(p1.pre, p2.pre), nil
}

// IsNewer 复刻 is_newer_version：latest 严格高于 current 才为 true。空串或解析失败一律 false
// （fail-closed）。
// IsNewer reproduces is_newer_version: true iff latest is strictly newer than current. Empty strings
// or a parse failure yield false (fail-closed).
func IsNewer(current, latest string) bool {
	if current == "" || latest == "" {
		return false
	}
	c, err := Compare(latest, current)
	if err != nil {
		return false
	}
	return c > 0
}
