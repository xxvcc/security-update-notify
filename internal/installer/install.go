package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
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
		dependencies.Locker = FileLocker{FS: dependencies.FS, OwnerUID: dependencies.RootOwnerUID}
	}
	if dependencies.EffectiveUID == nil {
		dependencies.EffectiveUID = os.Geteuid
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	return &Installer{
		fs: dependencies.FS, runner: dependencies.Runner, locker: dependencies.Locker,
		uid: dependencies.EffectiveUID, rootOwnerUID: dependencies.RootOwnerUID, now: dependencies.Now,
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
	installLock, err := i.locker.Acquire(ctx, InstallLockPath, 0)
	if err != nil {
		if errors.Is(err, ErrLockBusy) {
			return Result{}, temporary("acquire installer lock", errors.New("another install or upgrade transaction is running"))
		}
		return Result{}, failure("acquire installer lock", err)
	}
	defer func() {
		if err := installLock.Unlock(); err != nil {
			returnErr = errors.Join(returnErr, failure("release installer lock", err))
		}
	}()
	// An earlier process may have stopped after changing the host but before its
	// in-memory defers ran. Finish that transaction under the install lock before
	// parsing a new request or making any new installation change.
	if err := i.recoverInterruptedTransaction(ctx, options.LockWait); err != nil {
		return Result{}, err
	}
	if err := installContextError(ctx); err != nil {
		return Result{}, err
	}

	plan, err := i.prepare(ctx, options)
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
	timer, err := i.snapshotTimer(ctx)
	if err != nil {
		return Result{}, err
	}
	var automaticUnits []unitSnapshot
	runtimeLock, err := i.acquireRuntimeLock(ctx, options.LockWait)
	if err != nil {
		return Result{}, err
	}
	// Register this before the rollback defer below so failures are restored
	// while the transaction still excludes every normal runtime invocation.
	defer func() {
		if err := runtimeLock.Unlock(); err != nil {
			returnErr = errors.Join(returnErr, failure("release runtime lock", err))
		}
	}()
	previousVersion := i.currentInstalledVersion(ctx, runtimeLock)
	b, err := i.createBackup()
	if err != nil {
		return Result{}, err
	}
	aptConfigOriginallyAbsent := plan.backend == "apt" && !b.snapshots[aptPeriodicPath].exists
	dnfConfigOriginallyAbsent := plan.backend == "dnf" && !b.snapshots[dnfAutomaticPath].exists
	tx, err := i.beginTransaction(b, private, timer)
	if err != nil {
		return Result{}, err
	}
	transactionActive := true
	defer func() {
		if returnErr == nil || !transactionActive {
			return
		}
		if !tx.journal.RecoverySafe {
			returnErr = &ExitError{
				Code: 1,
				Op:   "installation failed during an unsafe dependency phase; automatic rollback was skipped",
				Err: errors.Join(returnErr, errors.New(
					"the package-manager state requires manual inspection; the transaction journal and private recovery material were retained")),
			}
			return
		}
		rollbackErr := i.restoreBackup(b, private, timer, automaticUnits)
		if rollbackErr == nil {
			_, rollbackErr = tx.finish(transactionStateRevert)
		}
		if rollbackErr != nil {
			returnErr = &ExitError{
				Code: 1,
				Op:   "installation failed and rollback was incomplete",
				Err: errors.Join(
					fmt.Errorf("original error: %w", returnErr),
					fmt.Errorf("rollback error: %w", rollbackErr),
				),
			}
		}
	}()

	if err := installContextError(ctx); err != nil {
		return Result{}, err
	}
	if err := i.quiesceExisting(ctx, plan.upgrade); err != nil {
		return Result{}, err
	}
	if err := installContextError(ctx); err != nil {
		return Result{}, err
	}
	if plan.backend == "apt" {
		if err := i.migrateAPTMetadata(b); err != nil {
			return Result{}, err
		}
	}
	if aptConfigOriginallyAbsent {
		if err := i.recordAPTAbsentBaseline(); err != nil {
			return Result{}, err
		}
	}
	if dnfConfigOriginallyAbsent {
		if err := i.recordDNFAbsentBaseline(plan); err != nil {
			return Result{}, err
		}
	}
	packageInstallAttempted := false
	var dependencyErr error
	if !options.SkipDependencies {
		packageInstallAttempted, dependencyErr = i.installDependencies(ctx, plan, options.ConfirmDependencies, func() error {
			return tx.markDependencyMutation(b, plan)
		})
	}
	var dependencyProofErr error
	if packageInstallAttempted {
		switch {
		case aptConfigOriginallyAbsent:
			dependencyProofErr = i.recordAPTDependencyProof()
		case dnfConfigOriginallyAbsent:
			dependencyProofErr = i.recordDNF4DependencyProof(plan)
		}
	}
	// Package installation is not rolled back. Capture its defaults together
	// with baseline metadata so a late failure and retry retain the original
	// host baseline. Recording the marker before package-manager writes also
	// preserves that baseline across an abrupt process or host failure.
	if packageInstallAttempted {
		if err := i.captureDependencyDefaults(b); err != nil {
			if dependencyErr != nil {
				if dependencyProofErr != nil {
					return Result{}, failure("capture partial dependency installation", fmt.Errorf(
						"dependency installation error: %v; proof error: %v; capture error: %w",
						dependencyErr, dependencyProofErr, err,
					))
				}
				return Result{}, failure("capture partial dependency installation", fmt.Errorf(
					"dependency installation error: %v; capture error: %w", dependencyErr, err,
				))
			}
			return Result{}, err
		}
	}
	if dependencyErr != nil {
		if dependencyProofErr != nil {
			return Result{}, failure("preserve partial dependency installation", fmt.Errorf(
				"dependency installation error: %v; proof error: %w", dependencyErr, dependencyProofErr,
			))
		}
		return Result{}, dependencyErr
	}
	if dependencyProofErr != nil {
		// A successful retained package transaction is sufficient in-process
		// provenance to promote its validated default. Do that before reporting
		// the proof failure so purge cannot leave an enabled distribution timer
		// without its vendor configuration.
		var baselineErr error
		if plan.backend == "apt" {
			baselineErr = i.persistAPTDependencyBaseline(b, aptConfigOriginallyAbsent, packageInstallAttempted)
		} else {
			baselineErr = i.persistDNF4DependencyBaseline(plan, b, dnfConfigOriginallyAbsent)
		}
		if baselineErr != nil {
			return Result{}, failure("preserve dependency installation", fmt.Errorf(
				"proof error: %v; baseline error: %w", dependencyProofErr, baselineErr,
			))
		}
		return Result{}, failure("preserve dependency installation", dependencyProofErr)
	}
	if plan.backend == "apt" {
		if err := i.persistAPTDependencyBaseline(b, aptConfigOriginallyAbsent, packageInstallAttempted); err != nil {
			return Result{}, err
		}
	}
	if err := i.persistDNF4DependencyBaseline(plan, b, dnfConfigOriginallyAbsent); err != nil {
		return Result{}, err
	}
	if err := i.verifyBackendCommands(ctx, plan); err != nil {
		return Result{}, err
	}
	automaticUnits, err = i.snapshotAutomaticUnits(ctx, plan)
	if err != nil {
		return Result{}, err
	}
	if err := tx.captureAutomaticUnits(automaticUnits); err != nil {
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
	if err := i.snapshotChangedDeliveryTargets(b, plan); err != nil {
		return Result{}, err
	}
	if err := i.markChangedDeliveryTargets(ctx, plan); err != nil {
		return Result{}, err
	}

	storage, err := i.installFiles(ctx, plan, options, credentialSecret, b)
	if err != nil {
		return Result{}, err
	}
	if err := i.verifyBackendPolicyFile(plan); err != nil {
		return Result{}, err
	}
	postInstallTest, postInstallDoctor, err := i.activateAndVerify(ctx, plan, options, previousVersion, automaticUnits, runtimeLock)
	if err != nil {
		return Result{}, err
	}
	if err := installContextError(ctx); err != nil {
		return Result{}, err
	}
	finalized, err := tx.finish(transactionStateCommit)
	if finalized {
		transactionActive = false
	}
	if err != nil {
		return Result{}, err
	}
	return Result{
		Upgrade: plan.upgrade, Backend: plan.backend, SupportTier: plan.supportTier,
		PreviousVersion: previousVersion, BackupDir: b.dir, CredentialStorage: storage,
		PostInstallTest: postInstallTest, PostInstallDoctor: postInstallDoctor,
	}, nil
}

func installContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return failure("installation canceled", err)
	}
	return nil
}

func deliveryStatePaths(channel string) []string {
	if channel == "telegram" {
		return []string{
			TelegramAlertHashPath, TelegramAlertTimePath,
			TelegramTargetPath, TelegramTargetPendingPath,
		}
	}
	return []string{
		FeishuAlertHashPath, FeishuAlertTimePath,
		FeishuTargetPath, FeishuTargetPendingPath,
	}
}

func targetPendingPath(channel string) string {
	if channel == "telegram" {
		return TelegramTargetPendingPath
	}
	return FeishuTargetPendingPath
}

func (i *Installer) snapshotChangedDeliveryTargets(b *backup, plan installPlan) error {
	for _, channel := range changedDeliveryTargetChannels(plan) {
		for _, statePath := range deliveryStatePaths(channel) {
			if err := i.snapshotAdditionalPath(b, statePath); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *Installer) markChangedDeliveryTargets(ctx context.Context, plan installPlan) error {
	channels := changedDeliveryTargetChannels(plan)
	if len(channels) == 0 {
		return nil
	}
	if err := i.ensureManagedDir(StateDirPath, 0o750); err != nil {
		return failure("prepare delivery target state", err)
	}
	for _, channel := range channels {
		if err := installContextError(ctx); err != nil {
			return err
		}
		if err := i.fs.WriteFileAtomic(targetPendingPath(channel), []byte("pending\n"), 0o600); err != nil {
			return failure("invalidate changed "+channel+" delivery target", err)
		}
	}
	return nil
}

func (i *Installer) activateAndVerify(ctx context.Context, plan installPlan, options Options, previousVersion string, automaticUnits []unitSnapshot, runtimeLock *HeldLock) (*CommandResult, *CommandResult, error) {
	if err := i.requiredCommandContext(ctx, "reload systemd", Command{Name: "systemctl", Args: []string{"daemon-reload"}, Timeout: 30 * time.Second}); err != nil {
		return nil, nil, err
	}
	automaticTimer := plan.profile.AutomaticTimer
	if automaticTimer == "" {
		return nil, nil, failure("enable automatic-update timer", errors.New("distribution profile does not define a timer"))
	}
	if err := i.disableAutomaticTimerVariants(ctx, plan, automaticUnits); err != nil {
		return nil, nil, err
	}
	if plan.backend == "apt" {
		if err := i.requiredCommandContext(ctx, "enable automatic-update timers", Command{Name: "systemctl", Args: []string{"enable", "--now", "apt-daily.timer", automaticTimer}, Timeout: 30 * time.Second}); err != nil {
			return nil, nil, err
		}
		_ = i.runner.Run(ctx, Command{Name: "systemctl", Args: []string{"enable", "--now", "unattended-upgrades.service"}, Timeout: 30 * time.Second})
	} else {
		if err := i.requiredCommandContext(ctx, "enable automatic-update timer", Command{Name: "systemctl", Args: []string{"enable", "--now", automaticTimer}, Timeout: 30 * time.Second}); err != nil {
			return nil, nil, err
		}
	}
	enablement := i.runner.Run(ctx, Command{Name: "systemctl", Args: []string{"is-enabled", automaticTimer}, Timeout: 30 * time.Second})
	if commandResultIncomplete(enablement) || enablement.Err != nil || enablement.Code != 0 {
		return nil, nil, failure("verify automatic-update timer", commandResultError(enablement))
	}
	state := strings.TrimSpace(string(enablement.Stdout))
	if state != "enabled" && state != "enabled-runtime" {
		return nil, nil, failure("verify automatic-update timer", fmt.Errorf(
			"%s has enablement state %q; want enabled or enabled-runtime", automaticTimer, state))
	}
	if !options.SkipPostInstallCheck {
		command, err := commandWithRuntimeLock(Command{Name: BinaryPath, Args: []string{"--version"}, Timeout: 30 * time.Second}, runtimeLock)
		if err != nil {
			return nil, nil, failure("verify installed runtime", err)
		}
		if err := i.requiredCommandContext(ctx, "verify installed runtime", command); err != nil {
			return nil, nil, err
		}
		if !i.runner.LookPath("systemd-analyze") {
			return nil, nil, failure("verify systemd units", errors.New("systemd-analyze is required"))
		}
		if err := i.requiredCommandContext(ctx, "verify systemd units", Command{
			Name: "systemd-analyze", Args: []string{"verify", ServicePath, TimerPath}, Timeout: 30 * time.Second,
		}); err != nil {
			return nil, nil, err
		}
	}
	var postInstallTest *CommandResult
	if options.SendTest {
		command, lockErr := commandWithRuntimeLock(Command{
			Name: BinaryPath, Args: []string{"--test-ok", "--no-dedupe", "--wait-lock", lockSeconds(options.LockWait)}, Timeout: options.LockWait + 30*time.Second,
		}, runtimeLock)
		if lockErr != nil {
			return nil, nil, failure("prepare post-install notification test", lockErr)
		}
		result := i.runner.Run(ctx, command)
		postInstallTest = &result
	}
	if err := i.fs.Remove(RuntimeTimerLink); err != nil {
		return postInstallTest, nil, failure("remove stale runtime timer link", err)
	}
	if err := i.requiredCommandContext(ctx, "enable project timer", Command{Name: "systemctl", Args: []string{"enable", "--now", "security-update-notify.timer"}, Timeout: 30 * time.Second}); err != nil {
		return postInstallTest, nil, err
	}
	var postInstallDoctor *CommandResult
	if !options.SkipPostInstallCheck {
		command, lockErr := commandWithRuntimeLock(Command{
			Name: BinaryPath, Args: []string{"--doctor", "--skip-notify", "--lang", plan.values["NOTIFY_LANG"]}, Timeout: 2 * time.Minute,
		}, runtimeLock)
		if lockErr != nil {
			return postInstallTest, nil, failure("prepare post-install doctor", lockErr)
		}
		result := i.runner.Run(ctx, command)
		postInstallDoctor = &result
		if plan.profile.Inferred && (commandResultIncomplete(result) || result.Err != nil || result.Code != 0) {
			return postInstallTest, postInstallDoctor, failure("verify inferred derivative with doctor", commandResultError(result))
		}
	}
	if err := i.requiredCommandContext(ctx, "list project timer", Command{
		Name: "systemctl", Args: []string{"list-timers", "security-update-notify.timer", "--no-pager"}, Timeout: 30 * time.Second,
	}); err != nil {
		return postInstallTest, postInstallDoctor, err
	}
	if plan.upgrade && plan.values["NOTIFY_UPGRADE"] == "1" {
		newVersion := i.currentInstalledVersion(ctx, runtimeLock)
		command, lockErr := commandWithRuntimeLock(Command{
			Name:    BinaryPath,
			Args:    []string{"--notify-upgrade-event", "--upgrade-from", previousVersion, "--upgrade-to", newVersion},
			Timeout: 2 * time.Minute,
		}, runtimeLock)
		if lockErr == nil {
			_ = i.runner.Run(ctx, command)
		}
	}
	return postInstallTest, postInstallDoctor, nil
}

func (i *Installer) currentInstalledVersion(ctx context.Context, runtimeLock *HeldLock) string {
	pathInfo, err := i.fs.Lstat(BinaryPath)
	if err != nil || pathInfo.Mode()&fs.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return "none"
	}
	if err := i.validateInstalledBinaryParent(); err != nil {
		return "unknown"
	}
	file, err := i.fs.OpenFileNoFollow(BinaryPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "unknown"
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o022, true) != nil ||
		info.Mode().Perm()&0o111 == 0 || info.Size() < 0 || info.Size() > 256<<20 {
		return "unknown"
	}
	command, err := commandWithRuntimeLock(Command{
		Name: "env", Args: []string{"/proc/self/fd/3", "--version"}, ExtraFiles: []*os.File{file}, Timeout: 15 * time.Second,
	}, runtimeLock)
	if err != nil {
		return "unknown"
	}
	result := i.runner.Run(ctx, command)
	if commandResultIncomplete(result) || result.Err != nil || result.Code != 0 {
		return "unknown"
	}
	fields := strings.Fields(string(result.Stdout))
	if len(fields) < 2 || len(fields[1]) > 128 {
		return "unknown"
	}
	return fields[1]
}

func commandWithRuntimeLock(command Command, runtimeLock *HeldLock) (Command, error) {
	if runtimeLock == nil || runtimeLock.File == nil {
		return Command{}, errors.New("runtime lock descriptor is unavailable")
	}
	command.Args = append([]string(nil), command.Args...)
	command.ExtraFiles = append(append([]*os.File(nil), command.ExtraFiles...), runtimeLock.File)
	command.Env = cloneConfig(command.Env)
	command.Env["SECURITY_UPDATE_NOTIFY_LOCK_FD"] = fmt.Sprintf("%d", 2+len(command.ExtraFiles))
	return command, nil
}

func (i *Installer) validateInstalledBinaryParent() error {
	for _, directory := range []string{"/usr/local", "/usr/local/sbin"} {
		info, err := i.fs.Lstat(directory)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			if directory == "/usr/local/sbin" {
				return i.validateLocalSbinAlias(info)
			}
			return errors.New("privileged binary parent must be a real directory")
		}
		if !info.IsDir() {
			return errors.New("privileged binary parent must be a real directory")
		}
		if err := i.validateTrustedDirectory(directory, info); err != nil {
			return err
		}
	}
	return nil
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
