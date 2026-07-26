package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/releasepkg"
)

func TestPackageSubcommandUsesRootVersionByDefault(t *testing.T) {
	clearReleaseEnv(t)
	var got releasepkg.Options
	build := func(_ context.Context, opts releasepkg.Options) (releasepkg.Result, error) {
		got = opts
		return releasepkg.Result{
			Tarball:  "/tmp/security-update-notify-3.0.0.tar.gz",
			Checksum: "/tmp/security-update-notify-3.0.0.tar.gz.sha256",
			SHA256:   strings.Repeat("a", 64),
		}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"package", "--root", "/repo"}, &stdout, &stderr, build); code != 0 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if got.Root != "/repo" || got.Version != "" {
		t.Fatalf("package options root=%q version=%q", got.Root, got.Version)
	}
	if !strings.Contains(stdout.String(), "security-update-notify-3.0.0.tar.gz") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestPackageVersionFlagIsCompatibilityAssertion(t *testing.T) {
	clearReleaseEnv(t)
	var got releasepkg.Options
	build := func(_ context.Context, opts releasepkg.Options) (releasepkg.Result, error) {
		got = opts
		return releasepkg.Result{}, nil
	}
	if code := run([]string{"package", "--version", "3.0.0"}, &bytes.Buffer{}, &bytes.Buffer{}, build); code != 0 {
		t.Fatalf("run code=%d", code)
	}
	if got.Version != "3.0.0" {
		t.Fatalf("version assertion=%q", got.Version)
	}
}

func TestPackageBuildFailureReturnsOne(t *testing.T) {
	clearReleaseEnv(t)
	build := func(context.Context, releasepkg.Options) (releasepkg.Result, error) {
		return releasepkg.Result{}, errors.New("version assertion mismatch")
	}
	var stderr bytes.Buffer
	if code := run([]string{"package"}, &bytes.Buffer{}, &stderr, build); code != 1 {
		t.Fatalf("run code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "sun-release: version assertion mismatch") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestPackageSignedOutputIncludesBootstrapSignature(t *testing.T) {
	clearReleaseEnv(t)
	build := func(context.Context, releasepkg.Options) (releasepkg.Result, error) {
		return releasepkg.Result{
			Tarball:            "/tmp/security-update-notify-3.0.0.tar.gz",
			Checksum:           "/tmp/security-update-notify-3.0.0.tar.gz.sha256",
			Signature:          "/tmp/security-update-notify-3.0.0.tar.gz.asc",
			BootstrapSignature: "/tmp/sun.sh.asc",
			SHA256:             strings.Repeat("a", 64),
			Signed:             true,
		}, nil
	}
	var stdout bytes.Buffer
	if code := run([]string{"package"}, &stdout, &bytes.Buffer{}, build); code != 0 {
		t.Fatalf("run code=%d", code)
	}
	for _, path := range []string{
		"/tmp/security-update-notify-3.0.0.tar.gz.asc",
		"/tmp/sun.sh.asc",
	} {
		if !strings.Contains(stdout.String(), path) {
			t.Fatalf("stdout=%q, want %q", stdout.String(), path)
		}
	}
}

func TestCommandAndUsage(t *testing.T) {
	clearReleaseEnv(t)
	neverBuild := func(context.Context, releasepkg.Options) (releasepkg.Result, error) {
		t.Fatal("build must not run")
		return releasepkg.Result{}, nil
	}
	for _, test := range []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput string
	}{
		{name: "missing", wantCode: 2, wantOutput: "missing command"},
		{name: "unknown", args: []string{"publish"}, wantCode: 2, wantOutput: `unknown command "publish"`},
		{name: "help", args: []string{"help"}, wantCode: 0, wantOutput: "sun-release package [options]"},
		{name: "dash help", args: []string{"--help"}, wantCode: 0, wantOutput: "sun-release package [options]"},
		{name: "package help", args: []string{"package", "--help"}, wantCode: 0, wantOutput: "version is read strictly from ROOT/VERSION"},
		{name: "help package", args: []string{"help", "package"}, wantCode: 0, wantOutput: "version is read strictly from ROOT/VERSION"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(test.args, &stdout, &stderr, neverBuild)
			if code != test.wantCode {
				t.Fatalf("run code=%d, want %d; stdout=%q stderr=%q", code, test.wantCode, stdout.String(), stderr.String())
			}
			if output := stdout.String() + stderr.String(); !strings.Contains(output, test.wantOutput) {
				t.Fatalf("output=%q, want substring %q", output, test.wantOutput)
			}
		})
	}
}

func TestEnvBool(t *testing.T) {
	for input, want := range map[string]bool{"": false, "0": false, "false": false, "no": false, "1": true, "true": true, "yes": true} {
		t.Run(input, func(t *testing.T) {
			t.Setenv("SUN_TEST_BOOL", input)
			got, err := envBool("SUN_TEST_BOOL")
			if err != nil || got != want {
				t.Fatalf("envBool(%q)=(%v,%v), want %v", input, got, err, want)
			}
		})
	}
	t.Setenv("SUN_TEST_BOOL", "maybe")
	if _, err := envBool("SUN_TEST_BOOL"); err == nil {
		t.Fatal("invalid boolean unexpectedly succeeded")
	}
}

func TestFilepathBase(t *testing.T) {
	for input, want := range map[string]string{"a/b.tar.gz": "b.tar.gz", `a\\b.tar.gz`: "b.tar.gz", "x": "x"} {
		if got := filepathBase(input); got != want {
			t.Errorf("filepathBase(%q)=%q, want %q", input, got, want)
		}
	}
}

func clearReleaseEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ALLOW_DIRTY_PACKAGE", "RELEASE", "VERSION", "SOURCE_DATE_EPOCH", "SIGN_RELEASE",
		"GPG_KEY_ID", "GNUPGHOME", "SUN_RELEASE_ROOT", "SUN_RELEASE_DIST",
	} {
		t.Setenv(key, "")
	}
}
