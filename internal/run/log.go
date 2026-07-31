package run

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
)

// logEvent 复刻运行时 log_event：向 /var/log/security-update-notify.log 追加一行
// `YYYY-mm-dd HH:MM:SS ±ZZZZ <line>`。日志不存在时请求 0640；进程 umask 可将其收紧（systemd
// 的 UMask=0077 下实际为 0600）。所有写入均 best-effort（失败静默，绝不影响通知流程）。
//
// logEvent reproduces the runtime's log_event: append `YYYY-mm-dd HH:MM:SS ±ZZZZ <line>` to the log,
// requesting mode 0640 when absent; the process umask may make it stricter (0600 under systemd's
// UMask=0077). All writes are best-effort and never affect the notification flow.
func logEvent(line string) {
	logEventForOwner(line, os.Geteuid())
}

func logEventForOwner(line string, euid int) {
	path := logFilePath()
	directory, err := filetrust.OpenOrCreateDirectory(filepath.Dir(path), euid)
	if err != nil {
		return
	}
	defer directory.Close()
	fd, err := syscall.Openat(
		int(directory.Fd()), filepath.Base(path),
		syscall.O_APPEND|syscall.O_WRONLY|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0o640,
	)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || filetrust.ValidateRegular(info, euid, 0o022, true) != nil {
		return
	}
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05 -0700"), singleLineLogText(line))
}

func singleLineLogText(value string) string {
	return textsafe.SingleLine(value)
}

func b01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
