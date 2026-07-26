package installer

import (
	"bytes"
	"syscall"
)

// ReadTelegramTokenFile safely reads a token source without following a
// symlink. The caller should place the returned value in Options.Config.
func (i *Installer) ReadTelegramTokenFile(name string) (string, error) {
	data, _, err := i.fs.ReadRegularFile(name, 4<<10)
	if err != nil {
		return "", invalid("Telegram token path must be a readable regular file (not a symlink): %v", err)
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
	if info.Mode().Perm()&0o077 != 0 {
		return nil, invalid("Feishu App Secret file must not be accessible by group or other users")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
		return nil, invalid("Feishu App Secret file must be owned by root")
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
