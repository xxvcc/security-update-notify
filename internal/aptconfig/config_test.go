package aptconfig

import (
	"strings"
	"testing"
)

func TestManagedPeriodicCompatibility(t *testing.T) {
	if !strings.HasPrefix(Periodic, "APT::Periodic::Enable \"1\";\n") {
		t.Fatal("managed APT policy does not enable its master switch")
	}
	for _, content := range []string{Periodic, LegacyPeriodic} {
		if !IsManagedPeriodic([]byte(content)) {
			t.Fatal("known SUN policy not recognized")
		}
		if IsManagedPeriodic([]byte(content + "// administrator change\n")) {
			t.Fatal("administrator policy treated as an exact SUN template")
		}
	}
}
