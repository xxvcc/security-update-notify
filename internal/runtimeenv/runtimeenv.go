// Package runtimeenv limits test-only runtime overrides at the privileged process boundary.
package runtimeenv

import (
	"flag"
	"os"
)

// Override returns an environment override for non-root callers and Go test
// binaries. A privileged production process always ignores it.
func Override(key string) string {
	value, ok := LookupOverride(key)
	if !ok {
		return ""
	}
	return value
}

// LookupOverride is the LookupEnv form of Override. It preserves an explicitly
// empty value for tests while treating a rejected privileged override as unset.
func LookupOverride(key string) (string, bool) {
	value, ok := os.LookupEnv(key)
	if !ok || !overrideAllowed(os.Geteuid(), flag.Lookup("test.v") != nil) {
		return "", false
	}
	return value, true
}

func overrideAllowed(euid int, testBinary bool) bool {
	return euid != 0 || testBinary
}
