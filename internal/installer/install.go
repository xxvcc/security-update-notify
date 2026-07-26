package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// New constructs an installer. Zero dependencies select the real host
// implementations; tests normally provide all four boundaries explicitly.
func New(dependencies Dependencies) (*Installer, error) {
	customFilesystem := dependencies.FS != nil
	if dependencies.FS == nil {
		root, err := NewRootFS("/")
		if err != nil {
			return nil, err
		}
		dependencies.FS = root
	}
	if dependencies.Runner == nil {
		if customFilesystem {
			return nil, errors.New("a custom filesystem requires an explicit command runner")
		}
		dependencies.Runner = ExecRunner{}
	}
	if dependencies.Locker == nil {
		dependencies.Locker = FileLocker{FS: dependencies.FS}
	}
	if dependencies.EffectiveUID == nil {
		dependencies.EffectiveUID = os.Geteuid
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return &Installer{
		fs: dependencies.FS, runner: dependencies.Runner, locker: dependencies.Locker,
		uid: dependencies.EffectiveUID, now: dependencies.Now,
	}, nil
}

// Install installs or upgrades the runtime as one rollback-protected
// transaction. It is intentionally non-interactive; the CLI owns prompts and
// passes only explicit overrides in Options.Config.
func (i *Installer) Install(ctx context.Context, options Options) (result Result, returnErr error) {
	if i.uid() != 0 {
		return Result{}, failure("require root", errors.New("please run as root"))
	}
	if options.LockWait < 0 {
		return Result{}, invalid("lock wait must not be negative")
	}
	if options.LockWait == 0 && !options.LockWaitSet {
		options.LockWait = 60 * time.Second
	}
	if options.LockWait > time.Hour {
		return Result{}, invalid("lock wait exceeds 3600 seconds")
	}
	if err := i.ensureDir("/run", 0o755); err != nil {
		return Result{}, failure("prepare installer lock", err)
	}
	unlockInstall, err := i.locker.Acquire(ctx, InstallLockPath, 0)
	if err != nil {
		if errors.Is(err, ErrLockBusy) {
			return Result{}, temporary("acquire installer lock", errors.New("another install or upgrade transaction is running"))
		}
		return Result{}, failure("acquire installer lock", err)
	}
	defer func() {
		if err := unlockInstall(); err != nil && returnErr == nil {
			returnErr = failure("release installer lock", err)
		}
	}()

	plan, err := i.prepare(options)
	if err != nil {
		return Result{}, err
	}
	if err := i.requireSystemd(); err != nil {
		return Result{}, err
	}
	private, err := i.snapshotPrivateCredentials()
	if err != nil {
		return Result{}, err
	}
	defer func() {
		for _, snapshot := range private {
			zeroBytes(snapshot.data)
		}
	}()
	timer := i.snapshotTimer()
	previousVersion := i.currentInstalledVersion(ctx)
	b, err := i.createBackup()
	if err != nil {
		return Result{}, err
	}
	transactionActive := true
	defer func() {
		if returnErr == nil || !transactionActive {
			return
		}
		if rollbackErr := i.restoreBackup(b, private, timer, options.LockWait); rollbackErr != nil {
			returnErr = &ExitError{
				Code: 1,
				Op:   "installation failed and rollback was incomplete",
				Err:  fmt.Errorf("original error: %v; rollback error: %w", returnErr, rollbackErr),
			}
		}
	}()

	if err := i.quiesceExisting(ctx, plan.upgrade, options.LockWait); err != nil {
		return Result{}, err
	}
	if !options.SkipDependencies {
		if err := i.installDependencies(ctx, plan, options.ConfirmDependencies); err != nil {
			return Result{}, err
		}
	}
	if err := i.captureDependencyDefaults(b); err != nil {
		return Result{}, err
	}
	credentialSecret := bytes.Clone(options.FeishuSecret)
	defer func() { zeroBytes(credentialSecret) }()

	if options.Preflight != nil {
		var preflightSecret []byte
		if channelSelected(plan.values["NOTIFY_CHANNELS"], "feishu") {
			if len(options.FeishuSecret) > 0 {
				preflightSecret = bytes.Clone(options.FeishuSecret)
			} else {
				preflightSecret, err = i.loadFeishuSecret(ctx)
				if err != nil {
					return Result{}, err
				}
			}
		}
		prepared := Prepared{
			Config: cloneConfig(plan.values), CheckTime: plan.checkTime, Backend: plan.backend,
			Upgrade: plan.upgrade, FeishuSecret: preflightSecret, ExistingSetup: plan.existingConfig,
		}
		preflightErr := func() error {
			baselineSecret := bytes.Clone(preflightSecret)
			defer zeroBytes(baselineSecret)
			defer zeroBytes(preflightSecret)
			defer func() { zeroBytes(prepared.FeishuSecret) }()
			if err := options.Preflight(ctx, &prepared); err != nil {
				return err
			}
			if err := applyPreparedConfig(&plan, &prepared); err != nil {
				return err
			}
			if !bytes.Equal(prepared.FeishuSecret, baselineSecret) {
				if err := validateSecret(prepared.FeishuSecret); err != nil {
					return err
				}
				zeroBytes(credentialSecret)
				credentialSecret = bytes.Clone(prepared.FeishuSecret)
			}
			return nil
		}()
		if preflightErr != nil {
			return Result{}, preflightErr
		}
	}

	storage, err := i.installFiles(ctx, plan, options, credentialSecret)
	if err != nil {
		return Result{}, err
	}
	postInstallDoctor, err := i.activateAndVerify(ctx, plan, options, previousVersion)
	if err != nil {
		return Result{}, err
	}
	transactionActive = false
	return Result{
		Upgrade: plan.upgrade, Backend: plan.backend, SupportTier: plan.supportTier,
		PreviousVersion: previousVersion, BackupDir: b.dir, CredentialStorage: storage,
		PostInstallDoctor: postInstallDoctor,
	}, nil
}

func (i *Installer) activateAndVerify(ctx context.Context, plan installPlan, options Options, previousVersion string) (*CommandResult, error) {
	if err := i.requiredCommandContext(ctx, "reload systemd", Command{Name: "systemctl", Args: []string{"daemon-reload"}, Timeout: 30 * time.Second}); err != nil {
		return nil, err
	}
	if plan.backend == "apt" {
		_ = i.runner.Run(ctx, Command{Name: "systemctl", Args: []string{"enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"}, Timeout: 30 * time.Second})
		_ = i.runner.Run(ctx, Command{Name: "systemctl", Args: []string{"enable", "--now", "unattended-upgrades.service"}, Timeout: 30 * time.Second})
	} else {
		_ = i.runner.Run(ctx, Command{Name: "systemctl", Args: []string{"enable", "--now", "dnf-automatic.timer"}, Timeout: 30 * time.Second})
	}
	if !options.SkipPostInstallCheck {
		if err := i.requiredCommandContext(ctx, "verify installed runtime", Command{Name: BinaryPath, Args: []string{"--version"}, Timeout: 30 * time.Second}); err != nil {
			return nil, err
		}
		if !i.runner.LookPath("systemd-analyze") {
			return nil, failure("verify systemd units", errors.New("systemd-analyze is required"))
		}
		if err := i.requiredCommandContext(ctx, "verify systemd units", Command{
			Name: "systemd-analyze", Args: []string{"verify", ServicePath, TimerPath}, Timeout: 30 * time.Second,
		}); err != nil {
			return nil, err
		}
	}
	if options.SendTest {
		if err := i.requiredCommandContext(ctx, "send post-install test", Command{
			Name: BinaryPath, Args: []string{"--test-ok", "--no-dedupe", "--wait-lock", lockSeconds(options.LockWait)}, Timeout: options.LockWait + 30*time.Second,
		}); err != nil {
			return nil, err
		}
	}
	if err := i.fs.Remove(RuntimeTimerLink); err != nil {
		return nil, failure("remove stale runtime timer link", err)
	}
	if err := i.requiredCommandContext(ctx, "enable project timer", Command{Name: "systemctl", Args: []string{"enable", "--now", "security-update-notify.timer"}, Timeout: 30 * time.Second}); err != nil {
		return nil, err
	}
	var postInstallDoctor *CommandResult
	if !options.SkipPostInstallCheck {
		result := i.runner.Run(ctx, Command{
			Name: BinaryPath, Args: []string{"--doctor", "--skip-notify", "--lang", plan.values["NOTIFY_LANG"]}, Timeout: 2 * time.Minute,
		})
		postInstallDoctor = &result
	}
	if err := i.requiredCommandContext(ctx, "list project timer", Command{
		Name: "systemctl", Args: []string{"list-timers", "security-update-notify.timer", "--no-pager"}, Timeout: 30 * time.Second,
	}); err != nil {
		return nil, err
	}
	if plan.upgrade && plan.values["NOTIFY_UPGRADE"] == "1" {
		newVersion := i.currentInstalledVersion(ctx)
		_ = i.runner.Run(ctx, Command{
			Name:    BinaryPath,
			Args:    []string{"--notify-upgrade-event", "--upgrade-from", previousVersion, "--upgrade-to", newVersion},
			Timeout: 2 * time.Minute,
		})
	}
	return postInstallDoctor, nil
}

func (i *Installer) currentInstalledVersion(ctx context.Context) string {
	info, err := i.fs.Lstat(BinaryPath)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "none"
	}
	result := i.runner.Run(ctx, Command{Name: BinaryPath, Args: []string{"--version"}, Timeout: 15 * time.Second})
	if result.Err != nil || result.Code != 0 {
		return "unknown"
	}
	fields := strings.Fields(string(result.Stdout))
	if len(fields) < 2 || len(fields[1]) > 128 {
		return "unknown"
	}
	return fields[1]
}

func lockSeconds(wait time.Duration) string {
	seconds := int(wait.Round(time.Second) / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 3600 {
		seconds = 3600
	}
	return fmt.Sprintf("%d", seconds)
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
