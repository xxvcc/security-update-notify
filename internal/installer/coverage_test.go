package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/osrel"
)

func TestExecRunnerClassifiesCommandOutcomesAndBoundsOutput(t *testing.T) {
	runner := ExecRunner{}
	if !runner.LookPath("sh") || runner.LookPath("security-update-notify-command-that-does-not-exist") {
		t.Fatal("LookPath did not distinguish an existing command from a missing one")
	}

	result := runner.Run(context.Background(), Command{
		Name:  "/bin/sh",
		Args:  []string{"-c", "IFS= read -r line; printf '%s' \"$SUN_TEST_VALUE:$line\"; printf '%s' warning >&2; exit 7"},
		Env:   map[string]string{"SUN_TEST_VALUE": "override"},
		Stdin: []byte("input\n"),
	})
	if result.Code != 7 || result.Err != nil || string(result.Stdout) != "override:input" || string(result.Stderr) != "warning" {
		t.Fatalf("non-zero command result = %+v", result)
	}

	extra, err := os.CreateTemp(t.TempDir(), "extra-file-")
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if _, err := extra.WriteString("descriptor-bound-data"); err != nil {
		t.Fatal(err)
	}
	if _, err := extra.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	fromDescriptor := runner.Run(context.Background(), Command{
		Name: "cat", Args: []string{"/proc/self/fd/3"}, ExtraFiles: []*os.File{extra},
	})
	if fromDescriptor.Err != nil || fromDescriptor.Code != 0 || string(fromDescriptor.Stdout) != "descriptor-bound-data" {
		t.Fatalf("extra-file command result = %+v", fromDescriptor)
	}

	executablePath := filepath.Join(t.TempDir(), "descriptor-command")
	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nprintf descriptor-executed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	executedDescriptor := runner.Run(context.Background(), Command{
		Name: "env", Args: []string{"/proc/self/fd/3"}, ExtraFiles: []*os.File{executable},
	})
	if executedDescriptor.Err != nil || executedDescriptor.Code != 0 || string(executedDescriptor.Stdout) != "descriptor-executed" {
		t.Fatalf("descriptor executable result = %+v", executedDescriptor)
	}

	missing := runner.Run(context.Background(), Command{Name: "/definitely/missing/security-update-notify"})
	if missing.Code != -1 || missing.Err == nil {
		t.Fatalf("missing command result = %+v", missing)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := runner.Run(ctx, Command{Name: "/bin/sh", Args: []string{"-c", "exit 0"}})
	if canceled.Code != -1 || !errors.Is(canceled.Err, context.Canceled) {
		t.Fatalf("canceled command result = %+v", canceled)
	}

	buffer := &cappedBuffer{max: 5}
	if n, err := buffer.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("first bounded write = (%d, %v)", n, err)
	}
	if n, err := buffer.Write([]byte("defgh")); n != 5 || err != nil || buffer.b.String() != "abcde" {
		t.Fatalf("truncated bounded write n=%d err=%v data=%q", n, err, buffer.b.String())
	}
	if !buffer.truncated {
		t.Fatal("bounded buffer did not record truncation")
	}
	if n, err := buffer.Write([]byte("ignored")); n != 7 || err != nil || buffer.b.String() != "abcde" || !buffer.truncated {
		t.Fatalf("full bounded write n=%d err=%v data=%q", n, err, buffer.b.String())
	}
}

func TestExecRunnerIgnoresCallerPATH(t *testing.T) {
	directory := t.TempDir()
	sentinel := filepath.Join(directory, "called")
	stub := filepath.Join(directory, "sh")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ntouch '"+sentinel+"'\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	result := (ExecRunner{}).Run(context.Background(), Command{
		Name: "sh",
		Args: []string{"-c", `test "$PATH" = '/usr/sbin:/usr/bin:/sbin:/bin' && test "$LC_ALL" = C`},
		Env:  map[string]string{"PATH": directory, "LC_ALL": "hostile"},
	})
	if result.Err != nil || result.Code != 0 {
		t.Fatalf("trusted sh result = %+v", result)
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("caller PATH stub executed: %v", err)
	}
}

func TestInstallerExitErrorsAndCommandDiagnostics(t *testing.T) {
	base := errors.New("base failure")
	plain := &ExitError{Code: 2, Err: base}
	if plain.Error() != "base failure" || !errors.Is(plain, base) {
		t.Fatalf("plain ExitError = %q, unwrap=%v", plain.Error(), errors.Is(plain, base))
	}
	wrapped := &ExitError{Code: 75, Op: "wait", Err: base}
	if wrapped.Error() != "wait: base failure" || ExitCode(wrapped) != 75 {
		t.Fatalf("wrapped ExitError = %q code=%d", wrapped.Error(), ExitCode(wrapped))
	}
	if ExitCode(nil) != 0 || ExitCode(base) != 1 || ExitCode(invalid("bad %s", "input")) != 2 {
		t.Fatal("installer exit-code mapping changed")
	}
	if got := failure("operation", nil).Error(); got != "operation: operation failed" {
		t.Fatalf("nil failure = %q", got)
	}
	if ExitCode(temporary("lock", ErrLockBusy)) != 75 {
		t.Fatal("temporary failure did not preserve EX_TEMPFAIL")
	}

	for _, test := range []struct {
		name   string
		result CommandResult
		want   string
	}{
		{name: "underlying error", result: CommandResult{Err: base}, want: "base failure"},
		{name: "stderr", result: CommandResult{Code: 4, Stderr: []byte(" stderr detail \n")}, want: "stderr detail"},
		{name: "stdout fallback", result: CommandResult{Code: 5, Stdout: []byte(" stdout detail \n")}, want: "stdout detail"},
		{name: "status fallback", result: CommandResult{Code: 6}, want: "command exited with status 6"},
		{name: "truncated stdout", result: CommandResult{StdoutTruncated: true}, want: "command output exceeded the capture limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := commandResultError(test.result).Error(); got != test.want {
				t.Fatalf("commandResultError()=%q want %q", got, test.want)
			}
		})
	}
	long := commandResultError(CommandResult{Code: 1, Stderr: []byte(strings.Repeat("x", 5000))}).Error()
	if len(long) != 4096 {
		t.Fatalf("bounded command diagnostic length=%d", len(long))
	}
}

func TestNormalizeAndValidateConfigRejectsUnsafeAndInconsistentValues(t *testing.T) {
	valid := func() map[string]string {
		values := cloneConfig(configDefaults)
		values["NOTIFY_CHANNELS"] = "telegram"
		values["TELEGRAM_BOT_TOKEN"] = "123456:valid_token"
		values["TELEGRAM_CHAT_ID"] = "-100123"
		return values
	}
	tests := []struct {
		name      string
		mutate    func(map[string]string)
		allowOpen bool
	}{
		{name: "oversized value", mutate: func(v map[string]string) { v["HOST_LABEL"] = strings.Repeat("x", 65537) }},
		{name: "line break", mutate: func(v map[string]string) { v["HOST_LABEL"] = "a\nb" }},
		{name: "nul byte", mutate: func(v map[string]string) { v["HOST_LABEL"] = "a\x00b" }},
		{name: "mixed quotes", mutate: func(v map[string]string) { v["HOST_LABEL"] = `a'b"c` }},
		{name: "unknown channel", mutate: func(v map[string]string) { v["NOTIFY_CHANNELS"] = "email" }},
		{name: "invalid Telegram token", mutate: func(v map[string]string) { v["TELEGRAM_BOT_TOKEN"] = "bad" }},
		{name: "missing Telegram chat", mutate: func(v map[string]string) { v["TELEGRAM_CHAT_ID"] = "" }},
		{name: "missing Feishu app", mutate: func(v map[string]string) {
			v["NOTIFY_CHANNELS"], v["FEISHU_RECEIVE_ID"] = "feishu", "ou_receiver"
		}},
		{name: "missing Feishu recipient", mutate: func(v map[string]string) {
			v["NOTIFY_CHANNELS"], v["FEISHU_APP_ID"], v["FEISHU_RECEIVE_ID"] = "feishu", "cli_app", ""
		}},
		{name: "invalid Feishu recipient", mutate: func(v map[string]string) {
			v["NOTIFY_CHANNELS"], v["FEISHU_APP_ID"], v["FEISHU_RECEIVE_ID"] = "feishu", "cli_app", "user"
		}},
		{name: "invalid boolean", mutate: func(v map[string]string) { v["CHECK_EOL"] = "sometimes" }},
		{name: "invalid language", mutate: func(v map[string]string) { v["NOTIFY_LANG"] = "fr" }},
		{name: "invalid interval", mutate: func(v map[string]string) {
			v["DEDUP_MODE"], v["DEDUP_INTERVAL_DAYS"] = "interval", "0"
		}},
		{name: "invalid dedup mode", mutate: func(v map[string]string) { v["DEDUP_MODE"] = "hourly" }},
		{name: "negative stale days", mutate: func(v map[string]string) { v["STALE_UPDATE_DAYS"] = "-1" }},
		{name: "overflow stale days", mutate: func(v map[string]string) { v["STALE_UPDATE_DAYS"] = "2147483648" }},
		{name: "overflow dedup interval", mutate: func(v map[string]string) {
			v["DEDUP_MODE"], v["DEDUP_INTERVAL_DAYS"] = "interval", "2147483648"
		}},
		{name: "zero self-update interval", mutate: func(v map[string]string) { v["SELF_UPDATE_CHECK_DAYS"] = "0" }},
		{name: "overflow self-update interval", mutate: func(v map[string]string) { v["SELF_UPDATE_CHECK_DAYS"] = "2147483648" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := valid()
			test.mutate(values)
			if err := normalizeAndValidateConfig(values, test.allowOpen); ExitCode(err) != 2 {
				t.Fatalf("unsafe config accepted or misclassified: %v", err)
			}
		})
	}

	values := valid()
	values["NOTIFY_CHANNELS"] = " FEISHU, telegram,feishu "
	values["FEISHU_APP_ID"] = "cli_app"
	values["FEISHU_RECEIVE_ID"] = ""
	values["DEDUP_MODE"] = "always"
	values["NOTIFY_OK"] = "YES"
	if got, err := normalizeChannels(""); err == nil || !strings.Contains(err.Error(), "receiving platforms cannot be empty") {
		t.Fatalf("normalizeChannels(%q) = %q, err=%v; want the empty-value diagnostic", "", got, err)
	}
	if got, err := normalizeChannels(" \t "); err == nil || !strings.Contains(err.Error(), "receiving platforms cannot be empty") {
		t.Fatalf("normalizeChannels(%q) = %q, err=%v; want the empty-value diagnostic", " \t ", got, err)
	}
	if got, err := normalizeChannels("feishu"); err != nil || got != "feishu" {
		t.Fatalf("normalizeChannels(%q) = %q, err=%v", "feishu", got, err)
	}
	if err := normalizeAndValidateConfig(values, true); err != nil {
		t.Fatal(err)
	}
	if values["NOTIFY_CHANNELS"] != "telegram,feishu" || values["DEDUP_MODE"] != "once" || values["NOTIFY_OK"] != "1" {
		t.Fatalf("normalized values = %+v", values)
	}
}

func TestApplyPreparedConfigRejectsBrokenPreflightState(t *testing.T) {
	newPlan := func() installPlan {
		values := cloneConfig(configDefaults)
		values["BACKEND"] = "apt"
		values["TELEGRAM_BOT_TOKEN"] = "123456:valid_token"
		values["TELEGRAM_CHAT_ID"] = "-100123"
		return installPlan{values: values, backend: "apt"}
	}
	tests := []struct {
		name    string
		prepare func(*installPlan) *Prepared
	}{
		{name: "nil prepared", prepare: func(*installPlan) *Prepared { return nil }},
		{name: "nil config", prepare: func(*installPlan) *Prepared { return &Prepared{} }},
		{name: "removed required key", prepare: func(plan *installPlan) *Prepared {
			cfg := cloneConfig(plan.values)
			delete(cfg, "HOST_LABEL")
			return &Prepared{Config: cfg}
		}},
		{name: "added unsupported key", prepare: func(plan *installPlan) *Prepared {
			cfg := cloneConfig(plan.values)
			cfg["UNSUPPORTED"] = "x"
			return &Prepared{Config: cfg}
		}},
		{name: "changed backend", prepare: func(plan *installPlan) *Prepared {
			cfg := cloneConfig(plan.values)
			cfg["BACKEND"] = "dnf"
			return &Prepared{Config: cfg}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := newPlan()
			if err := applyPreparedConfig(&plan, test.prepare(&plan)); ExitCode(err) != 2 {
				t.Fatalf("broken preflight config accepted or misclassified: %v", err)
			}
		})
	}

	plan := newPlan()
	cfg := cloneConfig(plan.values)
	cfg["HOST_LABEL"] = "selected-host"
	if err := applyPreparedConfig(&plan, &Prepared{Config: cfg}); err != nil {
		t.Fatal(err)
	}
	if plan.values["HOST_LABEL"] != "selected-host" || plan.values["CONFIG_VERSION"] != "4" {
		t.Fatalf("prepared config not committed: %+v", plan.values)
	}
}

func TestPrepareRejectsUnsupportedHostsAndUnsafeInputs(t *testing.T) {
	tests := []struct {
		name    string
		release string
		mutate  func(*Options)
		want    string
	}{
		{name: "missing runtime", release: "ID=debian\nVERSION_ID=13\n", mutate: func(o *Options) { o.Payload.Runtime = nil }, want: "runtime payload is required"},
		{name: "unknown config key", release: "ID=debian\nVERSION_ID=13\n", mutate: func(o *Options) { o.Config["UNKNOWN"] = "x" }, want: "unsupported config key"},
		{name: "invalid check time", release: "ID=debian\nVERSION_ID=13\n", mutate: func(o *Options) { o.CheckTime = "24:00" }, want: "invalid check time"},
		{name: "unsupported distribution", release: "ID=plan9\nVERSION_ID=1\n", mutate: func(*Options) {}, want: "unsupported distribution"},
		{name: "best effort requires opt-in", release: "ID=debian\nVERSION_ID=11\nPRETTY_NAME=Debian 11\n", mutate: func(*Options) {}, want: "best-effort"},
		{name: "invalid backend override", release: "ID=debian\nVERSION_ID=13\n", mutate: func(o *Options) { o.Backend = "rpm" }, want: "invalid or unsupported backend"},
		{name: "invalid Feishu secret", release: "ID=debian\nVERSION_ID=13\n", mutate: func(o *Options) { o.FeishuSecret = []byte("bad\nsecret") }, want: "Feishu App Secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installer, _, _, _ := setupInstaller(t, test.release)
			options := telegramOptions()
			test.mutate(&options)
			_, err := installer.prepare(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare error=%v want substring %q", err, test.want)
			}
		})
	}

	installer, _, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=11\nPRETTY_NAME=Debian 11\n")
	options := telegramOptions()
	options.AllowBestEffort = true
	plan, err := installer.prepare(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if plan.supportTier != "best-effort" || displayOS(plan.osRelease) != "Debian 11" {
		t.Fatalf("best-effort plan = %+v", plan)
	}
	if displayOS(plan.osRelease) != "Debian 11" || displayOS(plan.osRelease) == "" {
		t.Fatal("displayOS did not prefer PRETTY_NAME")
	}
}

func TestPrepareAllowsInferredDerivativeOnlyWithBestEffortOptIn(t *testing.T) {
	release := "ID=custom-el\nVERSION_ID=10\nID_LIKE='rhel fedora'\nPRETTY_NAME='Custom EL 10'\n"
	installer, _, runner, _ := setupInstaller(t, release)
	options := telegramOptions()
	if _, err := installer.prepare(context.Background(), options); err == nil || !strings.Contains(err.Error(), "unsupported distribution") {
		t.Fatalf("inferred derivative without opt-in error=%v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("inferred derivative probed without opt-in: %v", runner.commands)
	}
	options.AllowBestEffort = true
	plan, err := installer.prepare(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if plan.backend != "dnf" || plan.profile.Engine != osrel.EngineDNF4 || plan.supportTier != osrel.BestEffort {
		t.Fatalf("inferred plan=%+v profile=%+v", plan, plan.profile)
	}
	if !containsAllCommands(runner.commands, "dnf --version", "yum --version") {
		t.Fatalf("DNF generation probes = %v", runner.commands)
	}
	probeCount := len(runner.commands)
	options.SkipPostInstallCheck = true
	if _, err := installer.prepare(context.Background(), options); err == nil || !strings.Contains(err.Error(), "require the post-install verification gate") {
		t.Fatalf("inferred derivative skipped post-install gate: %v", err)
	}
	if len(runner.commands) != probeCount {
		t.Fatalf("skip-post-install rejection ran another probe: %v", runner.commands[probeCount:])
	}
	options.SkipPostInstallCheck = false

	known, _, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=42\n")
	if _, err := known.prepare(context.Background(), options); err == nil || !strings.Contains(err.Error(), "unsupported distribution") {
		t.Fatalf("known unverified release was accepted: %v", err)
	}
}

func TestPrepareProbesUnknownDNFDerivativeBeforeSelectingProfile(t *testing.T) {
	t.Run("DNF5 after ambiguous dnf", func(t *testing.T) {
		installer, _, runner, _ := setupInstaller(t, "ID=custom-fedora\nVERSION_ID=43\nID_LIKE=fedora\n")
		runner.missingCommands["dnf5"] = false
		runner.missingCommands["yum"] = true
		runner.failedCommands["dnf --version"] = CommandResult{Stdout: []byte("unrecognized version output\n")}
		options := telegramOptions()
		options.AllowBestEffort = true
		plan, err := installer.prepare(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		if plan.profile.Engine != osrel.EngineDNF5 || !containsInstallerString(plan.profile.Packages, "dnf5-plugin-automatic") {
			t.Fatalf("DNF5 inferred profile = %+v", plan.profile)
		}
		if !reflect.DeepEqual(runner.commands, []string{"dnf --version", "dnf5 --version"}) {
			t.Fatalf("probe commands = %v", runner.commands)
		}
	})

	t.Run("nonzero dnf then successful dnf5", func(t *testing.T) {
		installer, _, runner, _ := setupInstaller(t, "ID=custom-fedora\nVERSION_ID=43\nID_LIKE=fedora\n")
		runner.missingCommands["dnf5"] = false
		runner.missingCommands["yum"] = true
		runner.failedCommands["dnf --version"] = CommandResult{Code: 1, Stderr: []byte("broken\n")}
		options := telegramOptions()
		options.AllowBestEffort = true
		plan, err := installer.prepare(context.Background(), options)
		if err != nil || plan.profile.Engine != osrel.EngineDNF5 {
			t.Fatalf("plan=%+v err=%v", plan, err)
		}
	})

	for _, test := range []struct {
		name  string
		setup func(*fakeRunner)
		want  string
	}{
		{
			name: "ambiguous output",
			setup: func(runner *fakeRunner) {
				runner.missingCommands["yum"] = true
				runner.failedCommands["dnf --version"] = CommandResult{Stdout: []byte("unknown\n")}
			},
			want: "unambiguous successful version",
		},
		{
			name: "nonzero output",
			setup: func(runner *fakeRunner) {
				runner.missingCommands["yum"] = true
				runner.failedCommands["dnf --version"] = CommandResult{Code: 1, Stderr: []byte("failed\n")}
			},
			want: "unambiguous successful version",
		},
		{
			name: "truncated output",
			setup: func(runner *fakeRunner) {
				runner.missingCommands["dnf5"] = true
				runner.missingCommands["yum"] = true
				runner.failedCommands["dnf --version"] = CommandResult{Stdout: []byte("dnf5 version 5\n"), StdoutTruncated: true}
			},
			want: "unambiguous successful version",
		},
		{
			name: "only microdnf",
			setup: func(runner *fakeRunner) {
				runner.missingCommands["dnf"] = true
				runner.missingCommands["yum"] = true
				runner.missingCommands["microdnf"] = false
			},
			want: "no dnf, dnf5, or yum command",
		},
		{
			name: "conflicting generations",
			setup: func(runner *fakeRunner) {
				runner.missingCommands["dnf5"] = false
				runner.missingCommands["yum"] = true
			},
			want: "conflicting generations",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, _, runner, _ := setupInstaller(t, "ID=custom-el\nVERSION_ID=10\nID_LIKE='rhel fedora'\n")
			test.setup(runner)
			options := telegramOptions()
			options.AllowBestEffort = true
			if _, err := installer.prepare(context.Background(), options); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare error=%v want %q", err, test.want)
			}
		})
	}

	t.Run("known profile is not probed", func(t *testing.T) {
		installer, _, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
		if _, err := installer.prepare(context.Background(), telegramOptions()); err != nil {
			t.Fatal(err)
		}
		for _, command := range runner.commands {
			if strings.HasSuffix(command, " --version") {
				t.Fatalf("known Fedora profile was probed: %v", runner.commands)
			}
		}
	})
}

func TestUnknownDNFProbeFailurePrecedesInstallerWrites(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=custom-el\nVERSION_ID=10\nID_LIKE='rhel fedora'\n")
	runner.missingCommands["dnf"] = true
	runner.missingCommands["yum"] = true
	options := telegramOptions()
	options.AllowBestEffort = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "no dnf, dnf5, or yum command") {
		t.Fatalf("Install error=%v", err)
	}
	for _, path := range []string{BackupRoot, BinaryPath, ConfigPath, "/etc/dnf/automatic.conf"} {
		if existsNoErr(root, path) {
			t.Fatalf("probe failure created %s", path)
		}
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "rpm ") || strings.Contains(command, " install ") {
			t.Fatalf("probe failure reached package transaction: %v", runner.commands)
		}
	}
}

func TestDependencyPackageProbeTruncationIsTreatedAsMissing(t *testing.T) {
	for _, test := range []struct {
		name    string
		release string
		result  CommandResult
	}{
		{
			name:    "dpkg stdout",
			release: "ID=debian\nVERSION_ID=13\n",
			result:  CommandResult{Stdout: []byte("Package: partial\nStatus: install ok installed\n"), StdoutTruncated: true},
		},
		{
			name:    "rpm stderr",
			release: "ID=rocky\nVERSION_ID=9.6\n",
			result:  CommandResult{Stderr: []byte("partial diagnostic\n"), StderrTruncated: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, _, runner, _ := setupInstaller(t, test.release)
			plan, err := installer.prepare(context.Background(), telegramOptions())
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.profile.Packages) == 0 {
				t.Fatal("test profile has no dependency packages")
			}
			pkg := plan.profile.Packages[0]
			args := append(append([]string(nil), plan.profile.PackageProbe.Args...), pkg)
			commandLine := plan.profile.PackageProbe.Name + " " + strings.Join(args, " ")
			runner.failedCommands[commandLine] = test.result

			var request DependencyRequest
			attempted, err := installer.installDependencies(context.Background(), plan, func(_ context.Context, got DependencyRequest) (bool, error) {
				request = got
				return false, nil
			})
			if attempted || err == nil || !strings.Contains(err.Error(), "declined") {
				t.Fatalf("attempted=%v error=%v, want pre-install decline", attempted, err)
			}
			if request.Backend != plan.backend || !reflect.DeepEqual(request.Packages, []string{pkg}) {
				t.Fatalf("dependency request=%+v, want truncated probe package %q", request, pkg)
			}
		})
	}
}

func containsAllCommands(commands []string, wanted ...string) bool {
	for _, want := range wanted {
		found := false
		for _, command := range commands {
			if command == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func containsInstallerString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestLoadFeishuSecretCredentialStateMachine(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	if _, err := installer.loadFeishuSecret(context.Background()); ExitCode(err) != 2 {
		t.Fatalf("missing credential error=%v", err)
	}

	write(t, root, FeishuPlainCredentialPath, "plain-secret", 0o600)
	secret, err := installer.loadFeishuSecret(context.Background())
	if err != nil || string(secret) != "plain-secret" {
		t.Fatalf("plain credential=%q err=%v", secret, err)
	}
	write(t, root, FeishuPlainCredentialPath, "bad\nsecret", 0o600)
	if _, err := installer.loadFeishuSecret(context.Background()); ExitCode(err) != 2 {
		t.Fatalf("invalid plaintext credential error=%v", err)
	}
	if err := root.Remove(FeishuPlainCredentialPath); err != nil {
		t.Fatal(err)
	}

	write(t, root, FeishuEncryptedCredPath, "encrypted", 0o600)
	if _, err := installer.loadFeishuSecret(context.Background()); err == nil || !strings.Contains(err.Error(), "systemd-creds is required") {
		t.Fatalf("encrypted credential without decryptor error=%v", err)
	}
	runner.systemdCreds = true
	secret, err = installer.loadFeishuSecret(context.Background())
	if err != nil || string(secret) != "existing-secret" {
		t.Fatalf("decrypted credential=%q err=%v", secret, err)
	}
}

func TestFileLockerHonorsAlreadyCanceledContextBeforeFilesystemAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unlock, err := (FileLocker{}).Acquire(ctx, InstallLockPath, time.Second)
	if unlock != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lock acquisition unlock=%v err=%v", unlock, err)
	}
}

func TestRootFSRemoveAllRecursesWithoutFollowingSymlinks(t *testing.T) {
	rootDir := t.TempDir()
	root, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.MkdirAll("/tree/branch/deep", 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/tree/branch/deep/payload", "remove me", 0o600)

	outside := t.TempDir()
	marker := filepath.Join(outside, "keep")
	if err := os.WriteFile(marker, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink(outside, "/tree/branch/outside-link"); err != nil {
		t.Fatal(err)
	}

	if err := root.RemoveAll("/tree"); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("/tree"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recursive tree remained: %v", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserved" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, err)
	}

	if err := root.RemoveAll("/missing"); err != nil {
		t.Fatalf("missing path removal failed: %v", err)
	}
	write(t, root, "/leaf", "remove me too", 0o600)
	if err := root.RemoveAll("/leaf"); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("/leaf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("regular file remained: %v", err)
	}
}

func TestExistingConfigAndTimerRejectUnsafeFiles(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	truncate := func(name string, size int64) {
		t.Helper()
		write(t, root, name, "seed", 0o600)
		file, err := root.OpenFileNoFollow(name, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(size); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}

	truncate(ConfigPath, (4<<20)+1)
	if _, _, err := installer.readExistingConfig(); err == nil || !strings.Contains(err.Error(), "exceeds 4 MiB") {
		t.Fatalf("oversized config error=%v", err)
	}
	if err := root.Remove(ConfigPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink(target, ConfigPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installer.readExistingConfig(); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked config error=%v", err)
	}
	if err := root.Remove(ConfigPath); err != nil {
		t.Fatal(err)
	}
	write(t, root, ConfigPath, "CONFIG_VERSION='4'\n", 0o640)
	if _, _, err := installer.readExistingConfig(); err == nil || !strings.Contains(err.Error(), "protected root-owned") {
		t.Fatalf("group-readable config error=%v", err)
	}
	if err := root.Remove(ConfigPath); err != nil {
		t.Fatal(err)
	}
	write(t, root, ConfigPath, "CONFIG_VERSION='4'\n", 0o600)
	configHostPath := filepath.Join(root.Root, strings.TrimPrefix(ConfigPath, "/"))
	if err := os.Link(configHostPath, configHostPath+".alias"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := installer.readExistingConfig(); err == nil || !strings.Contains(err.Error(), "one hard link") {
		t.Fatalf("hard-linked config error=%v", err)
	}
	if err := root.Remove(ConfigPath); err != nil {
		t.Fatal(err)
	}

	truncate(TimerPath, (1<<20)+1)
	if _, err := installer.readExistingCheckTime(); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized timer error=%v", err)
	}
	if err := root.Remove(TimerPath); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink(target, TimerPath); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.readExistingCheckTime(); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked timer error=%v", err)
	}
	if err := root.Remove(TimerPath); err != nil {
		t.Fatal(err)
	}
	write(t, root, TimerPath, "[Timer]\nOnCalendar=*-*-* 09:00:00\n", 0o664)
	if _, err := installer.readExistingCheckTime(); err == nil || !strings.Contains(err.Error(), "protected root-owned") {
		t.Fatalf("group-writable timer error=%v", err)
	}
}

func TestBaselineAndProvenanceReadsRejectUnsafeMetadata(t *testing.T) {
	readers := []struct {
		name     string
		path     string
		contents string
		read     func(*Installer) (bool, error)
	}{
		{
			name: "stable-baseline", path: aptStableBackupPath, contents: "vendor baseline\n",
			read: func(installer *Installer) (bool, error) {
				return installer.validBaselineFile(aptStableBackupPath)
			},
		},
		{
			name: "absence-marker", path: aptAbsentMarkerPath, contents: aptAbsentMarkerContents,
			read: func(installer *Installer) (bool, error) {
				return installer.validAPTAbsentMarkerAt(aptAbsentMarkerPath)
			},
		},
		{
			name: "dependency-proof", path: aptDependencyProofPath,
			contents: string(aptDependencyProofContents([]byte("vendor default\n"))),
			read: func(installer *Installer) (bool, error) {
				return installer.validAPTDependencyProof([]byte("vendor default\n"))
			},
		},
	}
	mutations := []struct {
		name   string
		mutate func(*testing.T, *Installer, *RootFS, string)
	}{
		{
			name: "group-writable",
			mutate: func(t *testing.T, _ *Installer, root *RootFS, name string) {
				t.Helper()
				if err := root.Chmod(name, 0o620); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-owner",
			mutate: func(_ *testing.T, installer *Installer, _ *RootFS, _ string) {
				installer.rootOwnerUID = uint32(os.Geteuid() + 1)
			},
		},
		{
			name: "hard-linked",
			mutate: func(t *testing.T, _ *Installer, root *RootFS, name string) {
				t.Helper()
				hostPath := filepath.Join(root.Root, strings.TrimPrefix(name, "/"))
				if err := os.Link(hostPath, hostPath+".alias"); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, reader := range readers {
		reader := reader
		t.Run(reader.name+"/protected", func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, reader.path, reader.contents, 0o600)
			exists, err := reader.read(installer)
			if err != nil || !exists {
				t.Fatalf("protected file rejected: exists=%t err=%v", exists, err)
			}
		})
		for _, mutation := range mutations {
			mutation := mutation
			t.Run(reader.name+"/"+mutation.name, func(t *testing.T) {
				installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
				write(t, root, reader.path, reader.contents, 0o600)
				mutation.mutate(t, installer, root, reader.path)
				if exists, err := reader.read(installer); err == nil || exists || !strings.Contains(err.Error(), "protected root-owned") {
					t.Fatalf("unsafe file accepted: exists=%t err=%v", exists, err)
				}
			})
		}
	}
}

func TestEnsureLogFileValidatesOpenedInodeBeforeChangingMode(t *testing.T) {
	t.Run("create-and-normalize", func(t *testing.T) {
		installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
		if err := installer.ensureLogFile(); err != nil {
			t.Fatal(err)
		}
		info, err := root.Lstat(LogPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("created log mode=%04o want 0640", info.Mode().Perm())
		}
		if err := root.Chmod(LogPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := installer.ensureLogFile(); err != nil {
			t.Fatal(err)
		}
		info, err = root.Lstat(LogPath)
		if err != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("normalized log info=%v err=%v", info, err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Installer, *RootFS, string)
	}{
		{
			name: "group-writable",
			mutate: func(t *testing.T, _ *Installer, root *RootFS, _ string) {
				t.Helper()
				if err := root.Chmod(LogPath, 0o620); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-owner",
			mutate: func(_ *testing.T, installer *Installer, _ *RootFS, _ string) {
				installer.rootOwnerUID = uint32(os.Geteuid() + 1)
			},
		},
		{
			name: "hard-linked",
			mutate: func(t *testing.T, _ *Installer, _ *RootFS, hostPath string) {
				t.Helper()
				if err := os.Link(hostPath, hostPath+".alias"); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, LogPath, "existing log\n", 0o600)
			hostPath := filepath.Join(root.Root, strings.TrimPrefix(LogPath, "/"))
			test.mutate(t, installer, root, hostPath)
			before, err := os.Lstat(hostPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := installer.ensureLogFile(); err == nil || !strings.Contains(err.Error(), "protected root-owned") {
				t.Fatalf("unsafe log accepted: %v", err)
			}
			after, err := os.Lstat(hostPath)
			if err != nil {
				t.Fatal(err)
			}
			if after.Mode().Perm() != before.Mode().Perm() {
				t.Fatalf("unsafe log mode changed from %04o to %04o", before.Mode().Perm(), after.Mode().Perm())
			}
		})
	}
}

func TestOSReleaseRequiresTrustedFinalFile(t *testing.T) {
	t.Run("standard-relative-symlink", func(t *testing.T) {
		installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
		if err := root.Remove("/etc/os-release"); err != nil {
			t.Fatal(err)
		}
		write(t, root, "/usr/lib/os-release", "ID=ubuntu\nVERSION_ID=24.04\n", 0o644)
		if err := root.Symlink("../usr/lib/os-release", "/etc/os-release"); err != nil {
			t.Fatal(err)
		}
		release, err := installer.readOSRelease()
		if err != nil || release.ID != "ubuntu" || release.VersionID != "24.04" {
			t.Fatalf("standard os-release symlink: release=%+v err=%v", release, err)
		}
	})
	t.Run("protected-hard-link", func(t *testing.T) {
		installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
		hostPath := filepath.Join(root.Root, "etc/os-release")
		if err := os.Link(hostPath, hostPath+".alias"); err != nil {
			t.Fatal(err)
		}
		release, err := installer.readOSRelease()
		if err != nil || release.ID != "debian" || release.VersionID != "13" {
			t.Fatalf("protected hard-linked os-release: release=%+v err=%v", release, err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Installer, *RootFS)
	}{
		{
			name: "group-writable",
			mutate: func(t *testing.T, _ *Installer, root *RootFS) {
				t.Helper()
				if err := root.Chmod("/etc/os-release", 0o666); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-owner",
			mutate: func(_ *testing.T, installer *Installer, _ *RootFS) {
				installer.rootOwnerUID = uint32(os.Geteuid() + 1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			test.mutate(t, installer, root)
			if _, err := installer.readOSRelease(); err == nil || !strings.Contains(err.Error(), "protected root-owned") {
				t.Fatalf("unsafe os-release accepted: %v", err)
			}
		})
	}
}

func TestCommandEnvironmentOverridesAreUniqueAndDeterministic(t *testing.T) {
	t.Setenv("SUN_ENV_B", "old-b")
	t.Setenv("SUN_ENV_A", "old-a")
	t.Setenv("APT_CONFIG", "/tmp/attacker-apt.conf")
	t.Setenv("BASH_ENV", "/tmp/attacker.sh")
	t.Setenv("LD_PRELOAD", "/tmp/attacker.so")
	env := commandEnv(map[string]string{"SUN_ENV_B": "new-b", "SUN_ENV_A": "new-a"})
	joined := strings.Join(env, "\n")
	if strings.Count(joined, "SUN_ENV_A=") != 1 || strings.Count(joined, "SUN_ENV_B=") != 1 ||
		!strings.Contains(joined, "SUN_ENV_A=new-a\nSUN_ENV_B=new-b") {
		t.Fatalf("command environment is not unique and sorted:\n%s", joined)
	}
	if strings.Count(joined, "LC_ALL=") != 1 || !strings.Contains(joined, "LC_ALL=C") {
		t.Fatalf("command environment did not force C locale:\n%s", joined)
	}
	if strings.Count(joined, "PATH=") != 1 || !strings.Contains(joined, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
		t.Fatalf("command environment did not force the trusted PATH:\n%s", joined)
	}
	for _, forbidden := range []string{"APT_CONFIG=", "BASH_ENV=", "LD_PRELOAD="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("unsafe inherited environment %q survived:\n%s", forbidden, joined)
		}
	}
	if value := os.Getenv("SUN_ENV_A"); value != "old-a" {
		t.Fatalf("test environment was mutated: %q", value)
	}
}
