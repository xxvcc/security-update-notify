package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/xxvcc/security-update-notify/internal/installer"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

func TestContextLineReadCancelsWithoutConsumingLaterInput(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	reader := bufio.NewReader(input)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := readBoundedLineContext(ctx, input, reader)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled input read did not return")
	}
	if _, err := io.WriteString(writer, "next\nlast"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	for _, want := range []string{"next\n", "last"} {
		got, err := readBoundedLineContext(context.Background(), input, reader)
		if got != want || (err != nil && !errors.Is(err, io.EOF)) {
			t.Fatalf("next read = %q, %v; want %q", got, err, want)
		}
	}
}

type cancellationPromptWriter struct {
	marker string
	prompt string
	output strings.Builder
}

func (w *cancellationPromptWriter) Write(value []byte) (int, error) {
	w.output.Write(value)
	if strings.Contains(w.output.String(), w.prompt) {
		if err := os.WriteFile(w.marker, []byte("ready"), 0o600); err != nil {
			return 0, err
		}
	}
	return len(value), nil
}

type cancellationInstaller struct {
	*fakeInstallerAPI
	mode   string
	marker string
	called string
}

func (f *cancellationInstaller) Install(ctx context.Context, options installer.Options) (result installer.Result, err error) {
	if err := os.WriteFile(f.called, []byte("called"), 0o600); err != nil {
		return result, err
	}
	defer func() {
		if errors.Is(err, context.Canceled) {
			err = errors.Join(err, os.WriteFile(f.marker, []byte("cleanup complete"), 0o600))
		}
	}()
	if f.mode == "dependencies" {
		_, err = options.ConfirmDependencies(ctx, installer.DependencyRequest{Backend: "apt", Packages: []string{"needrestart"}})
		return result, err
	}
	return f.fakeInstallerAPI.Install(ctx, options)
}

func TestInstallPromptTerminationHelper(t *testing.T) {
	mode := os.Getenv("SUN_PROMPT_CANCELLATION_MODE")
	if mode == "" {
		return
	}
	command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
	command.console.in = bufio.NewReader(os.Stdin)
	command.console.input = os.Stdin
	command.console.errOut = os.Stderr
	command.console.out = io.MultiWriter(os.Stdout, &cancellationPromptWriter{
		marker: os.Getenv("SUN_PROMPT_CANCELLATION_READY"), prompt: os.Getenv("SUN_PROMPT_CANCELLATION_PROMPT"),
	})
	command.console.readSecret = func(prompt string) (string, error) {
		return readHiddenLineContext(command.console.context, os.Stdin, command.console.in, command.console.out, prompt)
	}
	command.newInstaller = func() (installerAPI, error) {
		return &cancellationInstaller{
			fakeInstallerAPI: fake, mode: mode, marker: os.Getenv("SUN_PROMPT_CANCELLATION_CLEANUP"),
			called: os.Getenv("SUN_PROMPT_CANCELLATION_CALLED"),
		}, nil
	}
	command.telegram = &fakeTelegramPreflight{getMeErrors: []error{temporaryTestError{"fixture network unavailable"}}}
	if mode == "secret" {
		command.telegram = &fakeTelegramPreflight{getMeErrors: []error{errors.New("fixture invalid credentials")}}
	}
	sysexec.InstallSignalForwarding()
	args := []string{
		"--lang", "en", "--notify-channels", "telegram",
		"--telegram-chat-id", "-100", "--time", "09:00", "--dedup-mode", "daily", "--skip-post-install-check",
	}
	if mode != "initial-secret" {
		args = append(args, "--telegram-token", "123:fixture")
	}
	command.run(args, false)
	// The signal handler re-raises only after Install's cleanup and the command's
	// completion handshake. Keep the helper alive to observe that exact signal.
	select {}
}

func TestInstallPromptsExitOnFirstTerminationSignal(t *testing.T) {
	for _, mode := range []struct{ name, prompt, input string }{
		{"dependencies", "Install these packages now?", "n\n"},
		{"preflight", "Skip this preflight", "n\n"},
		{"secret", "Telegram Bot Token (input hidden):", "n\ny\n"},
		{"initial-secret", "Telegram Bot Token (input hidden):", ""},
	} {
		for _, signal := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM} {
			t.Run(mode.name+"/"+signal.String(), func(t *testing.T) {
				directory := t.TempDir()
				ready, cleanup := filepath.Join(directory, "ready"), filepath.Join(directory, "cleanup")
				called := filepath.Join(directory, "installer-called")
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInstallPromptTerminationHelper$")
				child.Env = append(os.Environ(), "SUN_PROMPT_CANCELLATION_MODE="+mode.name,
					"SUN_PROMPT_CANCELLATION_PROMPT="+mode.prompt, "SUN_PROMPT_CANCELLATION_READY="+ready,
					"SUN_PROMPT_CANCELLATION_CLEANUP="+cleanup, "SUN_PROMPT_CANCELLATION_CALLED="+called)
				var output bytes.Buffer
				child.Stdout, child.Stderr = &output, &output
				var stdin io.WriteCloser
				var terminal *os.File
				var original syscall.Termios
				var err error
				if strings.Contains(mode.name, "secret") {
					stdin, terminal = openCancellationPTY(t)
					defer terminal.Close()
					child.Stdin = terminal
					if err := terminalIOCTL(terminal.Fd(), syscall.TCGETS, &original); err != nil {
						t.Fatal(err)
					}
				} else {
					stdin, err = child.StdinPipe()
				}
				if err != nil {
					t.Fatal(err)
				}
				defer stdin.Close()
				if err := child.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- child.Wait() }()
				if _, err := io.WriteString(stdin, mode.input); err != nil {
					t.Fatal(err)
				}
				for {
					if _, err := os.Stat(ready); err == nil {
						break
					}
					select {
					case err := <-done:
						t.Fatalf("child exited before prompt: %v\n%s", err, output.String())
					case <-time.After(10 * time.Millisecond):
					}
				}
				if terminal != nil {
					for {
						var state syscall.Termios
						if err := terminalIOCTL(terminal.Fd(), syscall.TCGETS, &state); err != nil {
							t.Fatal(err)
						}
						if state.Lflag&syscall.ECHO == 0 {
							break
						}
						select {
						case err := <-done:
							t.Fatalf("child exited before disabling echo: %v\n%s", err, output.String())
						case <-time.After(10 * time.Millisecond):
						}
					}
				}
				if err := child.Process.Signal(signal); err != nil {
					t.Fatal(err)
				}
				err = <-done
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("helper exit = %v\n%s", err, output.String())
				}
				status, ok := exitErr.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != signal {
					t.Fatalf("helper status = %v, want %s\n%s", exitErr.Sys(), signal, output.String())
				}
				if mode.name == "initial-secret" {
					if _, err := os.Stat(called); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("initial prompt reached installer: %v", err)
					}
				} else if data, err := os.ReadFile(cleanup); err != nil || string(data) != "cleanup complete" {
					t.Fatalf("cleanup did not complete before signal exit: %q, %v\n%s", data, err, output.String())
				}
				if terminal != nil {
					var restored syscall.Termios
					if err := terminalIOCTL(terminal.Fd(), syscall.TCGETS, &restored); err != nil || restored != original {
						t.Fatalf("signal exit did not restore terminal state: %v", err)
					}
				}
			})
		}
	}
}

func openCancellationPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var unlock, number uint32
	for _, request := range []struct {
		op    uintptr
		value *uint32
	}{{syscall.TIOCSPTLCK, &unlock}, {syscall.TIOCGPTN, &number}} {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), request.op, uintptr(unsafe.Pointer(request.value))); errno != 0 {
			master.Close()
			t.Fatal(errno)
		}
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	return master, slave
}
