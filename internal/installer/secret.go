package installer

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

func (i *Installer) openFeishuCredential(name string, maxBytes int64) (*os.File, fs.FileInfo, bool, error) {
	file, err := i.fs.OpenFileNoFollow(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, false, nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return nil, nil, false, errors.New("credential must be a regular file, not a symlink")
	}
	if err != nil {
		return nil, nil, false, err
	}
	fail := func(err error) (*os.File, fs.FileInfo, bool, error) {
		_ = file.Close()
		return nil, nil, false, err
	}
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o077, true); err != nil {
		return fail(fmt.Errorf("credential must be a protected root-owned regular file: %w", err))
	}
	if maxBytes < 0 || info.Size() < 0 || info.Size() > maxBytes {
		return fail(fmt.Errorf("credential exceeds %d bytes", maxBytes))
	}
	return file, info, true, nil
}

// ReadTelegramTokenFile safely reads a token source without following a
// symlink. The caller should place the returned value in Options.Config.
func (i *Installer) ReadTelegramTokenFile(name string) (string, error) {
	data, info, err := i.fs.ReadRegularFile(name, 4<<10)
	if err != nil {
		return "", invalid("Telegram token path must be a readable regular file (not a symlink): %v", err)
	}
	// A Bot Token is a bearer credential exactly like the Feishu App Secret, so
	// it gets the same source-file contract. Validate the opened inode before the
	// content checks so a protected-file failure is never masked by a formatting one.
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o077, true); err != nil {
		return "", invalid("Telegram token file must be protected, owned by root, and have one hard link: %v", err)
	}
	data = trimTerminalNewlines(data)
	if len(data) == 0 || bytes.ContainsAny(data, "\r\n\x00") {
		return "", invalid("Telegram token file contains invalid or multiple lines")
	}
	return string(data), nil
}

// ReadFeishuSecretFile enforces the root-only source-file contract before the
// secret enters Options.FeishuSecret. The returned bytes belong to the caller
// and should be zeroed after Install returns.
func (i *Installer) ReadFeishuSecretFile(name string) ([]byte, error) {
	data, info, err := i.fs.ReadRegularFile(name, 64<<10)
	if err != nil {
		return nil, invalid("Feishu App Secret path must be a readable regular file (not a symlink): %v", err)
	}
	if err := filetrust.ValidateRegular(info, int(i.rootOwnerUID), 0o077, true); err != nil {
		return nil, invalid("Feishu App Secret file must be protected, owned by root, and have one hard link: %v", err)
	}
	data = trimTerminalNewlines(data)
	if err := validateSecret(data); err != nil {
		return nil, err
	}
	return bytes.Clone(data), nil
}

func trimTerminalNewlines(data []byte) []byte {
	data = bytes.TrimRight(data, "\n")
	data = bytes.TrimSuffix(data, []byte{'\r'})
	return data
}
