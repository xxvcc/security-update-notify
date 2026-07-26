package run

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

func TestDPKGStatusIsInstalled(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "installed", output: "Package: test\nStatus: install ok installed\n", want: true},
		{name: "config files remain", output: "Package: test\nStatus: deinstall ok config-files\n"},
		{name: "unpacked", output: "Package: test\nStatus: install ok unpacked\n"},
		{name: "status-like description", output: "Description: Status: install ok installed\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := dpkgStatusIsInstalled(test.output); got != test.want {
				t.Fatalf("dpkgStatusIsInstalled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDoctorAPTDependenciesRejectsConfigFilesState(t *testing.T) {
	var output bytes.Buffer
	var packages []string
	ready := doctorAPTDependencies(&output, i18n.EN, func(string) bool { return true }, func(name string, args ...string) sysexec.Result {
		if name != "dpkg" || len(args) != 2 || args[0] != "-s" {
			return sysexec.Result{Code: -1, Err: errors.New("unexpected command")}
		}
		packages = append(packages, args[1])
		status := "install ok installed"
		if args[1] == "unattended-upgrades" {
			status = "deinstall ok config-files"
		}
		return sysexec.Result{Stdout: "Status: " + status + "\n"}
	})
	if ready {
		t.Fatal("config-files package state was reported ready")
	}
	if got := strings.Join(packages, ","); got != "unattended-upgrades,needrestart,apt-listchanges,ca-certificates" {
		t.Fatalf("checked packages = %q", got)
	}
	if text := output.String(); !strings.Contains(text, "FAIL package unattended-upgrades not fully installed") || strings.Contains(text, "OK package unattended-upgrades") {
		t.Fatalf("unexpected doctor output:\n%s", text)
	}
}
