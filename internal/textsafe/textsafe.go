// Package textsafe removes terminal and bidirectional controls from displayed text.
package textsafe

import (
	"strings"
	"unicode"
)

// SingleLine replaces characters that can create a new line or alter terminal
// rendering. Printable Unicode text is preserved.
func SingleLine(value string) string {
	return sanitize(value, false)
}

// Multiline preserves intentional LF and tab formatting while replacing other
// control, format, and Unicode line-separator characters.
func Multiline(value string) string {
	return sanitize(value, true)
}

func sanitize(value string, multiline bool) string {
	return strings.Map(func(r rune) rune {
		if multiline && (r == '\n' || r == '\t') {
			return r
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return ' '
		}
		return r
	}, value)
}
