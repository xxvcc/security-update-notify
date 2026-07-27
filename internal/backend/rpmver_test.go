package backend

import "testing"

func TestRPMVersionCompareCanonicalVectors(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1", 1},
		{"5.5p1", "5.5p10", -1},
		{"xyz.4", "8", -1},
		{"6.0.rc1", "6.0", 1},
		{"10.0001", "10.1", 0},
		{"2_0", "2.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0.1", -1},
		{"1.0^20160101^git1", "1.0^20160102", -1},
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0^git1~pre", "1.0^git1", -1},
		{"1", "1.", 0},
		{"1", "1_", 0},
		{"1+", "1_", 0},
		{"1a", "1.a", 0},
		{"1a", "1.0", -1},
		{"1.0a", "1.0.0", -1},
		{"1.0^^git", "1.0^git", -1},
		{"1.0~~rc", "1.0~rc", -1},
		{"001", "1", 0},
		{"0", "00", 0},
		{"1.0~", "1.0", -1},
		{"1.0^", "1.0", 1},
	}
	for _, test := range tests {
		if got := rpmVersionCompare(test.left, test.right); got != test.want {
			t.Errorf("rpmVersionCompare(%q, %q)=%d want %d", test.left, test.right, got, test.want)
		}
		if got := rpmVersionCompare(test.right, test.left); got != -test.want {
			t.Errorf("rpmVersionCompare(%q, %q)=%d want %d", test.right, test.left, got, -test.want)
		}
	}
}

func TestRPMEVRCompareEpochVersionRelease(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"1.0-1", "0:1.0-1", 0},
		{"0001:1.0-1", "1:1.0-1", 0},
		{"1:1.0-1", "0:9999-9999", 1},
		{"0:2.0-1", "0:1.0-999", 1},
		{"2.0-2", "2.0-1", 1},
		{"2.0~rc1-1", "2.0-1", -1},
		{"2.0^git1-1", "2.0-1", 1},
	}
	for _, test := range tests {
		got, err := rpmEVRCompare(test.left, test.right)
		if err != nil {
			t.Fatalf("rpmEVRCompare(%q, %q): %v", test.left, test.right, err)
		}
		if got != test.want {
			t.Errorf("rpmEVRCompare(%q, %q)=%d want %d", test.left, test.right, got, test.want)
		}
	}
}

func TestRPMEVRCompareRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "1", "1-", "-1", ":1-1", "x:1-1", "1::1-1", "1.0-beta-1", "1.0-1 beta", "1.0--"} {
		if _, err := rpmEVRCompare(value, "1-1"); err == nil {
			t.Errorf("rpmEVRCompare accepted malformed EVR %q", value)
		}
	}
}
