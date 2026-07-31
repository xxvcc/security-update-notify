// Package version 保留 SUN 2.x 的扩展语义版本比较：数字段逐段比较（缺省段补 0），pre-release
// 后缀按 SemVer 规则排序，任何解析失败一律 fail-closed（视为“非更新”）。
//
// Package version retains SUN's stable semantic-version ordering: numeric segments are compared pairwise
// (missing = 0), pre-release suffixes are ranked per semver, and parse failures fail closed.
package version

import (
	"errors"
	"strings"
)

// parsedVersion 拆成 release 数字段与 pre-release 后缀。
// parsedVersion splits a version into numeric release segments and a pre-release suffix.
type parsedVersion struct {
	rel []string
	pre string
}

var errBadVersion = errors.New("unparseable version")

// parseVersion 保留 python 比较器的排序规则，但在比较前严格校验版本结构：去掉前导 v、丢弃
// +构建元数据、按首个 '-' 切出 pre-release；release 数字段仅接受纯 ASCII 数字，pre-release
// 与构建元数据使用非空的 ASCII SemVer 标识符。任何畸形一律报错，交由上层 fail-closed。
func parseVersion(v string) (parsedVersion, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // 构建元数据不参与优先级 / build metadata ignored
		if !validSemverIdentifiers(v[i+1:], false) {
			return parsedVersion{}, errBadVersion
		}
		v = v[:i]
	}
	rel, pre := v, ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		rel, pre = v[:i], v[i+1:]
		if !validSemverIdentifiers(pre, true) {
			return parsedVersion{}, errBadVersion
		}
	}
	if rel == "" {
		return parsedVersion{}, errBadVersion
	}
	parts := strings.Split(rel, ".")
	nums := make([]string, len(parts))
	for i, p := range parts {
		if !isASCIIDigits(p) {
			return parsedVersion{}, errBadVersion
		}
		nums[i] = p
	}
	return parsedVersion{rel: nums, pre: pre}, nil
}

func validSemverIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		for i := 0; i < len(identifier); i++ {
			c := identifier[i]
			if !isASCIIAlphaNumeric(c) && c != '-' {
				return false
			}
		}
		if rejectNumericLeadingZero && len(identifier) > 1 && identifier[0] == '0' && isASCIIDigits(identifier) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
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
func cmpRelease(a, b []string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpNumericStr(x, y); c != 0 {
			return c
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
			if c := cmpNumericStr(x, y); c != 0 {
				return c
			}
			continue
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
