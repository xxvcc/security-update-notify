package runtimeenv

import "testing"

func TestOverrideAllowed(t *testing.T) {
	tests := []struct {
		name       string
		euid       int
		testBinary bool
		want       bool
	}{
		{name: "non-root", euid: 1000, want: true},
		{name: "root production", euid: 0, want: false},
		{name: "root Go test", euid: 0, testBinary: true, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := overrideAllowed(test.euid, test.testBinary); got != test.want {
				t.Fatalf("overrideAllowed() = %t, want %t", got, test.want)
			}
		})
	}
}
