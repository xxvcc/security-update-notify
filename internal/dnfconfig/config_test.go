package dnfconfig

import (
	"strings"
	"testing"
)

func TestParseStrict(t *testing.T) {
	valid := []byte("# comment\r\n[COMMANDS]\r\nUpgrade_Type = SECURITY\r\nApply_Updates = YES\r\nReboot = NEVER\r\nList_Value = [one,two]\r\n")
	values, err := ParseStrict(valid)
	if err != nil {
		t.Fatal(err)
	}
	if values["commands.upgrade_type"] != "security" || values["commands.apply_updates"] != "yes" || values["commands.reboot"] != "never" {
		t.Fatalf("values=%v", values)
	}
	if values["commands.list_value"] != "[one,two]" {
		t.Fatalf("bracket-valued setting was not preserved: values=%v", values)
	}

	for _, test := range []struct {
		name, input, want string
	}{
		{name: "NUL", input: "[commands]\nvalue=yes\x00\n", want: "NUL"},
		{name: "bad section", input: "[commands\nvalue=yes\n", want: "invalid DNF INI section"},
		{name: "empty section", input: "[ ]\n", want: "empty DNF INI section"},
		{name: "before section", input: "value=yes\n", want: "before a section"},
		{name: "bad setting", input: "[commands]\nvalue yes\n", want: "invalid DNF INI setting"},
		{name: "duplicate section", input: "[commands]\nvalue=yes\n[COMMANDS]\nother=no\n", want: "duplicate DNF INI section"},
		{name: "duplicate key", input: "[commands]\nvalue=yes\nVALUE=no\n", want: "duplicate DNF INI setting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseStrict([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want %q", err, test.want)
			}
		})
	}
}
