package cli

import "testing"

func TestParseWaitLockSeconds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		want  int
		ok    bool
	}{
		{value: "0", want: 0, ok: true},
		{value: "60", want: 60, ok: true},
		{value: "3600", want: 3600, ok: true},
		{value: "0001", want: 1, ok: true},
		{value: "", ok: false},
		{value: "00001", ok: false},
		{value: "+1", ok: false},
		{value: "-1", ok: false},
		{value: "3601", ok: false},
		{value: "9999", ok: false},
		{value: "1s", ok: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			got, ok := parseWaitLockSeconds(tt.value)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parseWaitLockSeconds(%q) = (%d, %v), want (%d, %v)", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}
