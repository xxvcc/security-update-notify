//go:build linux

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

// readHiddenLine disables terminal echo while reading a secret. A non-terminal
// input (for example an automation pipe) is read normally from the shared
// buffered reader so bytes already buffered by earlier prompts are preserved.
func readHiddenLine(input *os.File, reader *bufio.Reader, out io.Writer, prompt string) (line string, returnErr error) {
	if _, err := fmt.Fprint(out, prompt); err != nil {
		return "", err
	}

	fd := input.Fd()
	var original syscall.Termios
	if err := terminalIOCTL(fd, syscall.TCGETS, &original); err != nil {
		if errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EINVAL) {
			return readBoundedLine(reader)
		}
		return "", fmt.Errorf("inspect terminal: %w", err)
	}

	hidden := original
	hidden.Lflag &^= syscall.ECHO
	guard := terminalEchoGuard{fd: fd, original: original, ioctl: terminalIOCTL}
	unregisterCleanup := sysexec.RegisterTerminationCleanup(func() { _ = guard.terminate() })
	if err := guard.disable(&hidden); err != nil {
		unregisterCleanup()
		return "", fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() {
		restoreErr := guard.restore()
		unregisterCleanup()
		_, newlineErr := fmt.Fprintln(out)
		if returnErr == nil && restoreErr != nil {
			returnErr = fmt.Errorf("restore terminal echo: %w", restoreErr)
		}
		if returnErr == nil && newlineErr != nil {
			returnErr = newlineErr
		}
	}()

	line, returnErr = readBoundedLine(reader)
	return line, returnErr
}

func isTerminalFile(file *os.File) bool {
	if file == nil {
		return false
	}
	var state syscall.Termios
	return terminalIOCTL(file.Fd(), syscall.TCGETS, &state) == nil
}

var errTerminalTermination = errors.New("termination signal received while configuring terminal")

type terminalEchoGuard struct {
	mu          sync.Mutex
	fd          uintptr
	original    syscall.Termios
	ioctl       func(uintptr, uintptr, *syscall.Termios) error
	hidden      bool
	terminating bool
}

func (g *terminalEchoGuard) disable(hidden *syscall.Termios) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.terminating {
		return errTerminalTermination
	}
	if err := g.ioctl(g.fd, syscall.TCSETS, hidden); err != nil {
		return err
	}
	g.hidden = true
	return nil
}

func (g *terminalEchoGuard) restore() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.restoreLocked()
}

func (g *terminalEchoGuard) terminate() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.terminating = true
	return g.restoreLocked()
}

func (g *terminalEchoGuard) restoreLocked() error {
	if !g.hidden {
		return nil
	}
	if err := g.ioctl(g.fd, syscall.TCSETS, &g.original); err != nil {
		return err
	}
	g.hidden = false
	return nil
}

func terminalIOCTL(fd, request uintptr, state *syscall.Termios) error {
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(state)), 0, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return errno
		}
		return nil
	}
}

func openRegularNoFollow(path string) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return nil, errors.New("path must name an absolute file")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open returned an invalid root file descriptor")
	}
	components := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
			0,
		)
		if openErr != nil {
			_ = current.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return nil, errors.New("open returned an invalid directory file descriptor")
		}
		_ = current.Close()
		current = next
	}
	leaf := components[len(components)-1]
	fileFD, err := syscall.Openat(
		int(current.Fd()), leaf,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	_ = current.Close()
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileFD), clean)
	if file == nil {
		_ = syscall.Close(fileFD)
		return nil, errors.New("open returned an invalid file descriptor")
	}
	return file, nil
}
