package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

func (i *Installer) ensureDir(directory string, mode fs.FileMode) error {
	return i.ensureDirWithForbiddenPerm(directory, mode, 0o022)
}

// syncDirectoryChain confirms every directory entry from the selected root to
// logicalPath before a transaction relies on that path for durable recovery.
// It intentionally includes existing directories so a retry repairs an earlier
// mkdir whose parent sync reported failure after the entry became visible.
func (i *Installer) syncDirectoryChain(logicalPath string) error {
	clean, err := cleanLogicalPath(logicalPath)
	if err != nil {
		return err
	}
	current := "/"
	if err := i.fs.SyncDir(current); err != nil {
		return fmt.Errorf("sync directory chain at %s: %w", current, err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if component == "" {
			continue
		}
		current = path.Join(current, component)
		if err := i.fs.SyncDir(current); err != nil {
			return fmt.Errorf("sync directory chain at %s: %w", current, err)
		}
	}
	return nil
}

func (i *Installer) ensureDirWithForbiddenPerm(directory string, mode, forbiddenPerm fs.FileMode) error {
	info, err := i.fs.Lstat(directory)
	if errors.Is(err, fs.ErrNotExist) {
		if err := i.fs.MkdirAll(directory, mode); err != nil {
			return err
		}
		if err := i.fs.Chmod(directory, mode); err != nil {
			return err
		}
		info, err = i.fs.Lstat(directory)
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		if directory == "/usr/local/sbin" {
			return i.validateLocalSbinAlias(info)
		}
		return fmt.Errorf("%s must be a directory, not a symlink", directory)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory, not a symlink", directory)
	}
	return i.validateTrustedDirectoryWithForbiddenPerm(directory, info, forbiddenPerm)
}

func (i *Installer) ensureSharedLogDir() error {
	return i.ensureDirWithForbiddenPerm("/var/log", 0o755, 0o002)
}

func (i *Installer) validateLocalSbinAlias(linkInfo fs.FileInfo) error {
	target, err := i.fs.Readlink("/usr/local/sbin")
	if err != nil || target != "bin" {
		return errors.New("/usr/local/sbin must be a real directory or the exact relative symlink 'bin'")
	}
	stat, ok := linkInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify owner of /usr/local/sbin")
	}
	if stat.Uid != i.rootOwnerUID {
		return errors.New("/usr/local/sbin must be owned by root")
	}
	for _, name := range []string{"/usr/local", "/usr/local/bin"} {
		info, err := i.fs.Lstat(name)
		if err != nil {
			return fmt.Errorf("inspect standard /usr/local/sbin target %s: %w", name, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("standard /usr/local/sbin target %s must be a real directory", name)
		}
		if err := i.validateTrustedDirectory(name, info); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) ensureManagedDir(directory string, mode fs.FileMode) error {
	info, err := i.fs.Lstat(directory)
	if err == nil {
		if err := i.validateManagedDir(directory, info, 0); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := i.ensureDir(directory, mode); err != nil {
		return err
	}
	info, err = i.fs.Lstat(directory)
	if err != nil {
		return err
	}
	if err := i.validateManagedDir(directory, info, 0); err != nil {
		return err
	}
	if err := i.fs.Chmod(directory, mode); err != nil {
		return err
	}
	info, err = i.fs.Lstat(directory)
	if err != nil {
		return err
	}
	return i.validateManagedDir(directory, info, mode)
}

func (i *Installer) validateManagedDir(directory string, info fs.FileInfo, expectedMode fs.FileMode) error {
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a real directory", directory)
	}
	if err := i.validateTrustedDirectory(directory, info); err != nil {
		return err
	}
	if expectedMode != 0 && info.Mode().Perm() != expectedMode.Perm() {
		return fmt.Errorf("managed directory %s has mode %04o, want %04o", directory, info.Mode().Perm(), expectedMode.Perm())
	}
	return nil
}

func (i *Installer) validateTrustedDirectory(directory string, info fs.FileInfo) error {
	return i.validateTrustedDirectoryWithForbiddenPerm(directory, info, 0o022)
}

func (i *Installer) validateTrustedDirectoryWithForbiddenPerm(directory string, info fs.FileInfo, forbiddenPerm fs.FileMode) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify owner of privileged directory %s", directory)
	}
	if stat.Uid != i.rootOwnerUID {
		return fmt.Errorf("privileged directory %s must be owned by root", directory)
	}
	if info.Mode().Perm()&forbiddenPerm != 0 {
		if forbiddenPerm.Perm() == 0o002 {
			return fmt.Errorf("privileged directory %s must not be writable by other users", directory)
		}
		return fmt.Errorf("privileged directory %s must not be writable by group or other users", directory)
	}
	return nil
}

func (i *Installer) installFiles(ctx context.Context, plan installPlan, options Options, secret []byte, b *backup) (string, error) {
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	payload := options.Payload.withEmbeddedDefaults()
	for directory, mode := range map[string]fs.FileMode{
		"/usr/local/sbin":     0o755,
		"/etc/systemd/system": 0o755,
	} {
		if err := installContextError(ctx); err != nil {
			return "", err
		}
		if err := i.ensureDir(directory, mode); err != nil {
			return "", failure("create install directory", err)
		}
	}
	if err := i.ensureSharedLogDir(); err != nil {
		return "", failure("create install directory", err)
	}
	for directory, mode := range map[string]fs.FileMode{
		"/etc/security-update-notify": 0o750,
		StateDirPath:                  0o750,
	} {
		if err := installContextError(ctx); err != nil {
			return "", err
		}
		if err := i.ensureManagedDir(directory, mode); err != nil {
			return "", failure("create managed install directory", err)
		}
	}
	if err := i.ensureLogFile(); err != nil {
		return "", err
	}
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	if logrotateDir, err := i.fs.Lstat("/etc/logrotate.d"); err == nil && logrotateDir.IsDir() && logrotateDir.Mode()&fs.ModeSymlink == 0 {
		if err := i.fs.WriteFileAtomic(LogrotatePath, payload.Logrotate, 0o644); err != nil {
			return "", failure("install logrotate policy", err)
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", failure("inspect logrotate directory", err)
	} else if err == nil {
		return "", failure("inspect logrotate directory", errors.New("/etc/logrotate.d must be a real directory"))
	}
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	if err := i.fs.WriteFileAtomic(BinaryPath, payload.Runtime, 0o755); err != nil {
		return "", failure("install runtime", err)
	}
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	if err := i.fs.WriteFileAtomic(ServicePath, payload.Service, 0o644); err != nil {
		return "", failure("install service unit", err)
	}
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	if err := i.installBackendPolicy(plan, payload, b); err != nil {
		return "", err
	}
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	storage, err := i.installFeishuCredential(ctx, plan.values["NOTIFY_CHANNELS"], secret)
	if err != nil {
		return "", err
	}
	configData, err := renderConfig(plan.values)
	if err != nil {
		return "", failure("render config", err)
	}
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	if err := i.fs.WriteFileAtomic(ConfigPath, configData, 0o600); err != nil {
		return "", failure("install config", err)
	}
	timerData := []byte(renderTimer(plan.checkTime))
	if err := installContextError(ctx); err != nil {
		return "", err
	}
	if err := i.fs.WriteFileAtomic(TimerPath, timerData, 0o644); err != nil {
		return "", failure("install timer unit", err)
	}
	return storage, nil
}

func (i *Installer) ensureLogFile() (returnErr error) {
	file, err := i.fs.OpenFileNoFollow(LogPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		if err := i.fs.WriteFileAtomic(LogPath, nil, 0o640); err != nil {
			return failure("create log file", err)
		}
		file, err = i.fs.OpenFileNoFollow(LogPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return failure("inspect log file", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, file.Close())
	}()
	info, err := file.Stat()
	if err != nil {
		return failure("inspect log file", err)
	}
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o022, true); err != nil {
		return failure("inspect log file", fmt.Errorf("log must be a protected root-owned regular file with one hard link: %w", err))
	}
	if err := file.Chmod(0o640); err != nil {
		return failure("set log permissions", err)
	}
	info, err = file.Stat()
	if err != nil {
		return failure("verify log file", err)
	}
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o022, true); err != nil || info.Mode().Perm() != 0o640 {
		if err == nil {
			err = fmt.Errorf("mode is %04o, want 0640", info.Mode().Perm())
		}
		return failure("verify log file", err)
	}
	return nil
}

func (i *Installer) installFeishuCredential(ctx context.Context, channels string, secret []byte) (string, error) {
	if !channelSelected(channels, "feishu") {
		for _, name := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath, FeishuCredentialDropIn} {
			if err := i.fs.Remove(name); err != nil {
				return "", failure("remove disabled Feishu credential", err)
			}
		}
		return "disabled", nil
	}
	if len(secret) == 0 {
		if exists, err := i.regularCredentialExists(FeishuEncryptedCredPath); err != nil {
			return "", err
		} else if exists {
			if err := i.writeCredentialDropIn(); err != nil {
				return "", err
			}
			return "encrypted", nil
		}
		if exists, err := i.regularCredentialExists(FeishuPlainCredentialPath); err != nil {
			return "", err
		} else if exists {
			if err := i.fs.Remove(FeishuCredentialDropIn); err != nil {
				return "", failure("remove stale credential drop-in", err)
			}
			return "plain", nil
		}
		return "", invalid("missing Feishu App Secret credential")
	}
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	if i.runner.LookPath("systemd-creds") {
		_ = i.runner.Run(ctx, Command{Name: "systemd-creds", Args: []string{"setup"}, Timeout: 30 * time.Second})
		result := i.runner.Run(ctx, Command{
			Name: "systemd-creds", Args: []string{"encrypt", "--name=feishu_app_secret", "--with-key=host", "-", "-"},
			Stdin: secret, Timeout: 30 * time.Second,
		})
		if commandResultIncomplete(result) || result.Err != nil || result.Code != 0 || len(result.Stdout) == 0 || len(result.Stdout) > 128<<10 {
			return "", failure("encrypt Feishu App Secret", commandResultError(result))
		}
		if err := i.ensureManagedDir(path.Dir(FeishuEncryptedCredPath), 0o700); err != nil {
			return "", failure("create encrypted credential directory", err)
		}
		if err := i.fs.WriteFileAtomic(FeishuEncryptedCredPath, result.Stdout, 0o600); err != nil {
			return "", failure("install encrypted credential", err)
		}
		if err := i.fs.Remove(FeishuPlainCredentialPath); err != nil {
			return "", failure("remove plaintext credential", err)
		}
		if err := i.writeCredentialDropIn(); err != nil {
			return "", err
		}
		return "encrypted", nil
	}
	if err := i.ensureManagedDir(path.Dir(FeishuPlainCredentialPath), 0o700); err != nil {
		return "", failure("create plaintext credential directory", err)
	}
	if err := i.fs.WriteFileAtomic(FeishuPlainCredentialPath, secret, 0o600); err != nil {
		return "", failure("install plaintext credential", err)
	}
	if err := i.fs.Remove(FeishuEncryptedCredPath); err != nil {
		return "", failure("remove encrypted credential", err)
	}
	if err := i.fs.Remove(FeishuCredentialDropIn); err != nil {
		return "", failure("remove encrypted credential drop-in", err)
	}
	return "plain", nil
}

func (i *Installer) writeCredentialDropIn() error {
	if err := i.ensureManagedDir(path.Dir(FeishuCredentialDropIn), 0o755); err != nil {
		return failure("create credential drop-in directory", err)
	}
	content := []byte("[Service]\nLoadCredentialEncrypted=feishu_app_secret:" + FeishuEncryptedCredPath + "\n")
	if err := i.fs.WriteFileAtomic(FeishuCredentialDropIn, content, 0o644); err != nil {
		return failure("install credential drop-in", err)
	}
	return nil
}

func (i *Installer) regularCredentialExists(name string) (bool, error) {
	limit := int64(64 << 10)
	if name == FeishuEncryptedCredPath {
		limit = 128 << 10
	}
	file, _, exists, err := i.openFeishuCredential(name, limit)
	if err != nil {
		return false, failure("inspect Feishu credential", err)
	}
	if !exists {
		return false, nil
	}
	if err := file.Close(); err != nil {
		return false, failure("inspect Feishu credential", err)
	}
	return true, nil
}

func (i *Installer) loadFeishuSecret(ctx context.Context) ([]byte, error) {
	encrypted, _, exists, err := i.openFeishuCredential(FeishuEncryptedCredPath, 128<<10)
	if err != nil {
		return nil, failure("inspect Feishu credential", err)
	}
	if exists {
		defer encrypted.Close()
		if !i.runner.LookPath("systemd-creds") {
			return nil, failure("decrypt Feishu credential", errors.New("systemd-creds is required"))
		}
		result := i.runner.Run(ctx, Command{
			Name:       "systemd-creds",
			Args:       []string{"decrypt", "--name=feishu_app_secret", "/proc/self/fd/3", "-"},
			ExtraFiles: []*os.File{encrypted},
			Timeout:    10 * time.Second,
		})
		if commandResultIncomplete(result) || result.Err != nil || result.Code != 0 {
			return nil, failure("decrypt Feishu credential", commandResultError(result))
		}
		if err := validateSecret(result.Stdout); err != nil {
			return nil, err
		}
		return bytes.Clone(result.Stdout), nil
	}
	plain, _, exists, err := i.openFeishuCredential(FeishuPlainCredentialPath, 64<<10)
	if err != nil {
		return nil, failure("inspect Feishu credential", err)
	}
	if exists {
		defer plain.Close()
		data, _, err := readOpenedRegularFile(plain, 64<<10)
		if err != nil {
			return nil, failure("read Feishu credential", err)
		}
		if err := validateSecret(data); err != nil {
			return nil, err
		}
		return bytes.Clone(data), nil
	}
	return nil, invalid("missing Feishu App Secret credential")
}
