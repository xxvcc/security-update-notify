package delivery

import (
	"reflect"
	"testing"
)

func TestParseChannels(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{"legacy-default", "", []string{"telegram"}, false},
		{"telegram", "telegram", []string{"telegram"}, false},
		{"feishu", "feishu", []string{"feishu"}, false},
		{"both", "telegram,feishu", []string{"telegram", "feishu"}, false},
		{"trim-case-dedupe", " Feishu, telegram,FEISHU ", []string{"feishu", "telegram"}, false},
		{"empty-entry", "telegram,", nil, true},
		{"unknown", "webhook", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseChannels(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("channels=%v want %v", got, tc.want)
			}
		})
	}
}
