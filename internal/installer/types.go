// Package installer owns the privileged, transactional installation of
// security-update-notify. All operating-system boundaries are injectable so
// the transaction can be exercised without touching the host running tests.
package installer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/xxvcc/security-update-notify/internal/assets"
)

const (
	BinaryPath                = "/usr/local/sbin/security-update-notify"
	ConfigPath                = "/etc/security-update-notify/telegram.env"
	ServicePath               = "/etc/systemd/system/security-update-notify.service"
	TimerPath                 = "/etc/systemd/system/security-update-notify.timer"
	PersistentTimerLink       = "/etc/systemd/system/timers.target.wants/security-update-notify.timer"
	RuntimeTimerLink          = "/run/systemd/system/timers.target.wants/security-update-notify.timer"
	LogPath                   = "/var/log/security-update-notify.log"
	LogrotatePath             = "/etc/logrotate.d/security-update-notify"
	StateDirPath              = "/var/lib/security-update-notify"
	TelegramAlertHashPath     = StateDirPath + "/last-alert.sha256"
	TelegramAlertTimePath     = StateDirPath + "/last-alert.sent_at"
	TelegramTargetPath        = StateDirPath + "/last-alert.telegram.target.sha256"
	TelegramTargetPendingPath = StateDirPath + "/last-alert.telegram.target.pending"
	FeishuAlertHashPath       = StateDirPath + "/last-alert.feishu.sha256"
	FeishuAlertTimePath       = StateDirPath + "/last-alert.feishu.sent_at"
	FeishuTargetPath          = StateDirPath + "/last-alert.feishu.target.sha256"
	FeishuTargetPendingPath   = StateDirPath + "/last-alert.feishu.target.pending"
	BackupRoot                = "/var/backups/security-update-notify"
	InstallLockPath           = "/run/security-update-notify.install.lock"
	RuntimeLockPath           = "/run/security-update-notify.lock"
	FeishuPlainCredentialPath = "/etc/security-update-notify/credentials/feishu-app-secret"
	FeishuEncryptedCredPath   = "/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred"
	FeishuCredentialDropIn    = "/etc/systemd/system/security-update-notify.service.d/credentials.conf"
)

// ExitError carries the command-line exit status used by the legacy installer.
// Validation failures use 2, temporary lock contention uses 75, and host or
// transaction failures use 1.
type ExitError struct {
	Code int
	Op   string
	Err  error
}

func (e *ExitError) Error() string {
	if e.Op == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode maps an installer error to a process exit status.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 1
}

func failure(op string, err error) error {
	if err == nil {
		err = errors.New("operation failed")
	}
	return &ExitError{Code: 1, Op: op, Err: err}
}

func invalid(format string, args ...any) error {
	return &ExitError{Code: 2, Err: fmt.Errorf(format, args...)}
}

func temporary(op string, err error) error {
	return &ExitError{Code: 75, Op: op, Err: err}
}

// FileSystem is the complete filesystem boundary used by Installer. Paths are
// logical absolute host paths. Implementations must keep every operation below
// their configured root even when path components are replaced concurrently.
type FileSystem interface {
	Lstat(path string) (fs.FileInfo, error)
	ReadFile(path string) ([]byte, error)
	ReadFileFollow(path string, maxBytes int64) ([]byte, fs.FileInfo, error)
	ReadRegularFile(path string, maxBytes int64) ([]byte, fs.FileInfo, error)
	OpenFileNoFollow(path string, flag int, perm fs.FileMode) (*os.File, error)
	WriteFileAtomic(path string, data []byte, perm fs.FileMode) error
	CopyRegularFileAtomic(source, destination string, maxBytes int64) error
	CopyTrustedRegularFileAtomic(source, destination string, maxBytes int64, ownerUID uint32) error
	ValidateTrustedRegularFile(source string, maxBytes int64, ownerUID uint32) error
	Mkdir(path string, perm fs.FileMode) error
	MkdirAll(path string, perm fs.FileMode) error
	SyncDir(path string) error
	ReadDir(path string) ([]fs.DirEntry, error)
	Readlink(path string) (string, error)
	Symlink(target, path string) error
	Chmod(path string, perm fs.FileMode) error
	Remove(path string) error
	RemoveAll(path string) error
}

// Command is one shell-free external command invocation.
type Command struct {
	Name       string
	Args       []string
	Env        map[string]string
	Stdin      []byte
	ExtraFiles []*os.File
	Timeout    time.Duration
}

// CommandResult treats a non-zero exit as data. Err is reserved for failures
// to start, cancellation, and timeout.
type CommandResult struct {
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
	Code            int
	Err             error
}

type Runner interface {
	LookPath(name string) bool
	Run(ctx context.Context, command Command) CommandResult
}

type UnlockFunc func() error

// HeldLock keeps the exact descriptor that owns the advisory lock available to
// trusted child checks. Unlock must be called exactly once.
type HeldLock struct {
	File   *os.File
	unlock UnlockFunc
}

func (l *HeldLock) Unlock() error {
	if l == nil || l.unlock == nil {
		return errors.New("lock is not held")
	}
	unlock := l.unlock
	l.unlock = nil
	return unlock()
}

// Locker provides advisory process locks for install serialization and the
// runtime quiescence barrier.
type Locker interface {
	Acquire(ctx context.Context, path string, wait time.Duration) (*HeldLock, error)
}

var ErrLockBusy = errors.New("lock is busy")

// Payload contains the binary and static files installed by the transaction.
// Runtime must be supplied by the caller, normally by reading os.Executable.
type Payload struct {
	Runtime     []byte
	Service     []byte
	Needrestart []byte
	Logrotate   []byte
}

func (p Payload) withEmbeddedDefaults() Payload {
	if len(p.Service) == 0 {
		p.Service = assets.SystemdServiceUnit()
	}
	if len(p.Needrestart) == 0 {
		p.Needrestart = assets.NeedrestartConf()
	}
	if len(p.Logrotate) == 0 {
		p.Logrotate = assets.LogrotateConf()
	}
	return p
}

// Prepared is passed to the optional network preflight after dependencies are
// available but before any new runtime/configuration is installed. Callers
// must not retain FeishuSecret.
type Prepared struct {
	Config        map[string]string
	CheckTime     string
	Backend       string
	Upgrade       bool
	FeishuSecret  []byte
	ExistingSetup bool
}

// PreflightFunc may update Prepared.Config (most commonly FEISHU_RECEIVE_ID
// after a directory scan) and replace Prepared.FeishuSecret after an
// interactive retry. Installer revalidates and copies changes into the
// transaction only after the hook succeeds.
type PreflightFunc func(context.Context, *Prepared) error

// DependencyRequest describes the complete missing package set before the
// installer performs apt/dnf writes. Packages is a caller-owned copy and may
// be displayed by an interactive CLI.
type DependencyRequest struct {
	Backend  string
	Packages []string
}

// ConfirmDependenciesFunc authorizes package-manager writes. It is called
// exactly once when required packages are missing and never when the host is
// already ready. Returning false declines the installation without running an
// update/install command.
type ConfirmDependenciesFunc func(context.Context, DependencyRequest) (bool, error)

// Options are non-interactive installer inputs. Config contains only explicit
// schema-4 overrides; absent keys are preserved from an existing install or
// receive safe defaults on a fresh install.
type Options struct {
	Config               map[string]string
	CheckTime            string
	Backend              string
	AllowBestEffort      bool
	Payload              Payload
	FeishuSecret         []byte
	Preflight            PreflightFunc
	ConfirmDependencies  ConfirmDependenciesFunc
	SkipDependencies     bool
	SkipPostInstallCheck bool
	SendTest             bool
	LockWait             time.Duration
	LockWaitSet          bool
}

type Result struct {
	Upgrade           bool
	Backend           string
	SupportTier       string
	PreviousVersion   string
	BackupDir         string
	CredentialStorage string
	PostInstallTest   *CommandResult
	PostInstallDoctor *CommandResult
}

// Dependencies replaces every host-specific boundary in tests.
type Dependencies struct {
	FS           FileSystem
	Runner       Runner
	Locker       Locker
	EffectiveUID func() int
	// RootOwnerUID is the host UID representing root inside a private test root.
	// Production callers leave it zero.
	RootOwnerUID uint32
	Now          func() time.Time
}

type Installer struct {
	fs           FileSystem
	runner       Runner
	locker       Locker
	uid          func() int
	rootOwnerUID uint32
	now          func() time.Time
}
