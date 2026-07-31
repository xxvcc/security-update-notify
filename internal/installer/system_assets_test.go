package installer

import (
	"strings"
	"testing"
)

func TestRenderedTimerDescribesAllRuntimeAlerts(t *testing.T) {
	timer := renderTimer("08:45")
	for _, want := range []string{
		"安全补丁维护风险", "重启需求", "SUN 新版本",
		"security patch maintenance risks", "restart needs", "new SUN releases",
		"OnCalendar=*-*-* 08:45:00", "RandomizedDelaySec=10m", "Persistent=true",
	} {
		if !strings.Contains(timer, want) {
			t.Errorf("rendered timer is missing %q", want)
		}
	}
}
