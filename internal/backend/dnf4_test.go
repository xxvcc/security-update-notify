package backend

import (
	"strings"
	"testing"
)

func TestDNF4BlockedUpdatesUseVersionlockAwareCandidates(t *testing.T) {
	advisories := "RHSA-2026:1 Important/Sec. openssl-1:3.0.7-50.el9.x86_64\n"
	unrestricted := "openssl.x86_64 1:3.0.7-60.el9 baseos\n"
	for _, test := range []struct {
		name, restricted string
		blocked          bool
	}{
		{"installed version locked", "", true},
		{"older security version locked", "openssl.x86_64 1:3.0.7-40.el9 baseos\n", true},
		{"newer ordinary build covers advisory", "openssl.x86_64 1:3.0.7-55.el9 baseos\n", false},
		{"older epoch cannot cover advisory", "openssl.x86_64 3.0.7-99.el9 baseos\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			blocked, err := BlockedDNF4(advisories, test.restricted, unrestricted)
			if err != nil || (len(blocked) != 0) != test.blocked {
				t.Fatalf("blocked=%v err=%v", blocked, err)
			}
		})
	}
	if blocked, err := BlockedDNF4(advisories, "", ""); err != nil || len(blocked) != 0 {
		t.Fatalf("advisory for already installed/running kernel is not evidence of a blocked upgrade: %v %v", blocked, err)
	}
	if _, err := BlockedDNF4("", "", unrestricted); err == nil {
		t.Fatal("security candidates without corresponding advisories became a healthy result")
	}
}

func TestDNF4CandidateOutputVariants(t *testing.T) {
	output := "openssl.x86_64 1:3.0.7-50.el9 baseos\n" +
		"a-very-long-package-name.noarch\n 2.0-1.el9 updates\n" +
		"Obsoleting Packages\nreplacement.noarch 2-1.el9 updates\n    old-name.noarch 1-1.el9 @System\n" +
		"    old-from-baseos.noarch 1-1.el9 @baseos\n" +
		"    old-long-package-name-from-history.noarch\n        1-1.el9 @anaconda\n"
	candidates, err := ParseDNF4CheckUpgrades(output)
	if err != nil || len(candidates) != 3 {
		t.Fatalf("candidates=%v err=%v", candidates, err)
	}
	for _, output := range []string{"warning: unknown output", "openssl.x86_64", "openssl.x86_64 invalid updates", "Obsoleting Packages\n", "openssl.x86_64 2-1.el9 @System", "openssl.x86_64 2-1.el9 @baseos", "Obsoleting Packages\nold-name.noarch\n    1-1.el9 @baseos"} {
		if _, err := ParseDNF4CheckUpgrades(output); err == nil {
			t.Errorf("accepted malformed output %q", output)
		}
	}
	if _, err := BlockedDNF4("RHSA-2026:1 Important/Sec. openssl.x86_64", "", ""); err == nil {
		t.Fatal("accepted advisory without an EVR")
	}
	if _, err := BlockedDNF4(strings.Replace("RHSA-2026:1 Important/Sec. openssl-2-1.el9.x86_64", "Important/Sec.", "drift", 1), "", ""); err == nil {
		t.Fatal("accepted unknown advisory output")
	}
}
