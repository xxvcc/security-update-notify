package watchdog

import "testing"

func TestAPTPeriodicMasterSwitch(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"", true}, {`APT::Periodic::Enable "1";`, true},
		{`APT::Periodic::Enable "0";`, false}, {`APT::Periodic::Enable "true";`, false},
		{`APT::Periodic::Enable "\x31";`, false},
		{`APT::Periodic::Enable "";`, false}, {`APT::Periodic::Enable "1"`, false},
	} {
		if got := APTPeriodicEnabled(test.value); got != test.want {
			t.Errorf("APTPeriodicEnabled(%q)=%t want %t", test.value, got, test.want)
		}
		issues := CheckAPTPolicy(test.value, true)
		if got := hasIssueCode(issues, "apt-periodic-disabled"); got == test.want {
			t.Errorf("master switch %q issues=%v", test.value, issues)
		}
	}
}

func TestAPTIntervalRejectsBooleanAndMalformedValues(t *testing.T) {
	for _, value := range []string{"0", "true", "yes", "on", "ALWAYS", "-1", "1h junk", "08", "8H", "9223372036854775807d", `\x31`, `\061`, `\u0031`} {
		dump := `APT::Periodic::Update-Package-Lists "` + value + `";` + "\n" +
			`APT::Periodic::Unattended-Upgrade "` + value + `";`
		issues := CheckAPTPolicy(dump, true)
		for _, code := range []string{"apt-periodic-update-disabled", "apt-unattended-disabled"} {
			if !hasIssueCode(issues, code) {
				t.Errorf("interval %q did not report %s: %v", value, code, issues)
			}
		}
	}
}

func TestAPTLiteralSecurityCodenameMustExistInRepositoryMetadata(t *testing.T) {
	for _, test := range []struct {
		name, policy string
		mismatch     bool
	}{
		{"old release", `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bullseye-security,label=Debian-Security";`, true},
		{"current release", `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,n=bookworm-security,label=Debian-Security";`, false},
		{"variable", `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";`, false},
		{"wildcard", `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=*-security,label=Debian-Security";`, false},
		{"broad matching rule", `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=bullseye-security,label=Debian-Security";` + "\n" + `Unattended-Upgrade::Origins-Pattern:: "origin=Debian";`, false},
		{"legacy allowed origin", `Unattended-Upgrade::Allowed-Origins:: "Debian:oldstable-security";`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			issues := CheckAPTSecurityOriginCodenames(test.policy, []string{"bookworm-security"})
			if (len(issues) != 0) != test.mismatch {
				t.Fatalf("issues=%v", issues)
			}
			if issues := CheckAPTSecurityOriginCodenames(test.policy, nil); len(issues) != 0 {
				t.Fatalf("missing repository evidence caused an origin claim: %v", issues)
			}
		})
	}
}
