package releasepkg

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
)

const (
	maxCombinedCommandOutput = 8 << 20
	maxCommandErrorBytes     = 4 << 10
)

type cappedCombinedOutput struct {
	buf       bytes.Buffer
	truncated bool
}

func (c *cappedCombinedOutput) Write(p []byte) (int, error) {
	remaining := maxCombinedCommandOutput - c.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = c.buf.Write(p[:remaining])
			c.truncated = true
		} else {
			_, _ = c.buf.Write(p)
		}
	} else if len(p) != 0 {
		c.truncated = true
	}
	return len(p), nil
}

func findExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required command %s is unavailable", name)
	}
	return path, nil
}

func runCombined(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	return runCombinedFiles(ctx, dir, env, nil, name, args...)
}

func runCombinedFiles(ctx context.Context, dir string, env []string, files []*os.File, name string, args ...string) ([]byte, error) {
	cmd := sysexec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	cmd.ExtraFiles = append([]*os.File(nil), files...)
	var output cappedCombinedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	captured := output.buf.Bytes()
	if output.truncated {
		return captured, fmt.Errorf("%s: combined output exceeds %d bytes", filepath.Base(name), maxCombinedCommandOutput)
	}
	if err != nil {
		message := commandErrorSummary(output.buf.Bytes())
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return captured, fmt.Errorf("command timed out: %s", filepath.Base(name))
		}
		if message != "" {
			return captured, fmt.Errorf("%s: %w: %s", filepath.Base(name), err, message)
		}
		return captured, fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return captured, nil
}

func commandErrorSummary(output []byte) string {
	message := strings.TrimSpace(textsafe.SingleLine(string(output)))
	if len(message) <= maxCommandErrorBytes {
		return message
	}
	limit := maxCommandErrorBytes
	for limit > 0 && !utf8.ValidString(message[:limit]) {
		limit--
	}
	return strings.TrimSpace(message[:limit])
}

func buildAllBinaries(ctx context.Context, root, pkgDir, version string, stdout, stderr interface{ Write([]byte) (int, error) }) error {
	goTool, err := findExecutable("go")
	if err != nil {
		return err
	}
	if err := validateRegularSource(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("required go.mod: %w", err)
	}
	if err := requirePinnedGoToolchain(ctx, root, goTool); err != nil {
		return err
	}

	var nativeBinary string
	for _, arch := range officialArches {
		output := filepath.Join(pkgDir, "files", productName+"-linux-"+arch)
		args := []string{
			"build", "-C", root, "-trimpath", "-buildvcs=false",
			"-ldflags", "-s -w -buildid= -X main.Version=" + version,
			"-o", output, "./cmd/security-update-notify",
		}
		out, err := runCombined(ctx, root, goBuildEnvironment("linux", arch), goTool, args...)
		if len(out) != 0 {
			_, _ = stderr.Write(out)
		}
		if err != nil {
			return fmt.Errorf("build linux/%s: %w", arch, err)
		}
		if err := os.Chmod(output, 0o755); err != nil {
			return fmt.Errorf("normalize linux/%s binary mode: %w", arch, err)
		}
		if err := validateLinuxBinary(output, arch); err != nil {
			return fmt.Errorf("validate linux/%s binary: %w", arch, err)
		}
		if runtime.GOOS == "linux" && runtime.GOARCH == arch {
			nativeBinary = output
		}
		fmt.Fprintf(stdout, "built linux/%s\n", arch)
	}

	removeProbe := func() {}
	if !nativeArchitectureSupported() {
		probeDir, err := os.MkdirTemp(filepath.Dir(pkgDir), ".version-probe-")
		if err != nil {
			return fmt.Errorf("create version probe directory: %w", err)
		}
		removeProbe = func() { _ = os.RemoveAll(probeDir) }
		nativeBinary = filepath.Join(probeDir, productName)
		args := []string{
			"build", "-C", root, "-trimpath", "-buildvcs=false",
			"-ldflags", "-s -w -buildid= -X main.Version=" + version,
			"-o", nativeBinary, "./cmd/security-update-notify",
		}
		if _, err := runCombined(ctx, root, goBuildEnvironment(runtime.GOOS, runtime.GOARCH), goTool, args...); err != nil {
			removeProbe()
			return fmt.Errorf("build native version probe: %w", err)
		}
	}
	defer removeProbe()
	out, err := runCombined(ctx, root, nil, nativeBinary, "--version")
	if err != nil {
		return fmt.Errorf("run binary version probe: %w", err)
	}
	if string(out) != productName+" "+version+"\n" {
		return fmt.Errorf("binary version probe mismatch: got %q, want %q", string(out), productName+" "+version+"\n")
	}
	return nil
}

func requirePinnedGoToolchain(ctx context.Context, root, goTool string) error {
	env := goBuildEnvironment(runtime.GOOS, runtime.GOARCH)
	metadata, err := runCombined(ctx, root, env, goTool, "mod", "edit", "-json")
	if err != nil {
		return fmt.Errorf("read pinned Go toolchain: %w", err)
	}
	actual, err := runCombined(ctx, root, env, goTool, "env", "GOVERSION")
	if err != nil {
		return fmt.Errorf("read active Go toolchain: %w", err)
	}
	return validatePinnedGoToolchain(metadata, actual)
}

func validatePinnedGoToolchain(metadata, actualOutput []byte) error {
	var module struct {
		Toolchain string `json:"Toolchain"`
	}
	if err := json.Unmarshal(metadata, &module); err != nil {
		return fmt.Errorf("parse go.mod metadata: %w", err)
	}
	if module.Toolchain == "" {
		return errors.New("go.mod must pin an exact toolchain for release builds")
	}
	actual := strings.TrimSpace(string(actualOutput))
	if actual != module.Toolchain {
		return fmt.Errorf("active Go toolchain %q does not match pinned %q", actual, module.Toolchain)
	}
	return nil
}

func validateLinuxBinary(path, arch string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("empty or non-regular output")
	}
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("not an ELF executable: %w", err)
	}
	defer f.Close()
	type expectation struct {
		machine elf.Machine
		class   elf.Class
		data    elf.Data
	}
	want, ok := map[string]expectation{
		"amd64":   {elf.EM_X86_64, elf.ELFCLASS64, elf.ELFDATA2LSB},
		"arm64":   {elf.EM_AARCH64, elf.ELFCLASS64, elf.ELFDATA2LSB},
		"386":     {elf.EM_386, elf.ELFCLASS32, elf.ELFDATA2LSB},
		"ppc64le": {elf.EM_PPC64, elf.ELFCLASS64, elf.ELFDATA2LSB},
		"s390x":   {elf.EM_S390, elf.ELFCLASS64, elf.ELFDATA2MSB},
	}[arch]
	if !ok {
		return fmt.Errorf("unsupported architecture %q", arch)
	}
	if f.Machine != want.machine || f.Class != want.class || f.Data != want.data {
		return fmt.Errorf("ELF identity is machine=%s class=%s data=%s", f.Machine, f.Class, f.Data)
	}
	return nil
}

func goBuildEnvironment(goos, goarch string) []string {
	remove := map[string]bool{
		"CGO_ENABLED": true, "GOOS": true, "GOARCH": true, "GOTOOLCHAIN": true,
		"GOFLAGS": true, "GOWORK": true, "GOENV": true, "GO111MODULE": true,
		"GOEXPERIMENT": true, "GOFIPS140": true, "GOAMD64": true, "GO386": true,
		"GOARM": true, "GOARM64": true, "GOPPC64": true, "GORISCV64": true,
	}
	env := make([]string, 0, len(os.Environ())+16)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if !remove[key] {
			env = append(env, item)
		}
	}
	env = append(env,
		"CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch,
		"GOTOOLCHAIN=local", "GOFLAGS=", "GOWORK=off", "GOENV=off",
		"GO111MODULE=on", "GOEXPERIMENT=", "GOFIPS140=off",
		"GOAMD64=v1", "GO386=sse2", "GOARM=7", "GOARM64=v8.0",
		"GOPPC64=power8", "GORISCV64=rva20u64",
	)
	return env
}
