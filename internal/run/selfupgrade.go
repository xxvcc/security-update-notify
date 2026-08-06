package run

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/assets"
	"github.com/xxvcc/security-update-notify/internal/commandpath"
	"github.com/xxvcc/security-update-notify/internal/dist"
	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/version"
)

var latestVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$`)

const (
	maxUpgradeVersionOutputBytes = 4 << 10
	privilegedUpgradePath        = commandpath.TrustedPATH
	privilegedUpgradeTempBase    = "/var/tmp"
	upgradeInstallerTimeout      = time.Hour
	// http.Client.Timeout bounds the whole exchange including reading the body, so the metadata
	// ceiling below would force the multi-megabyte release archive to arrive within a minute and
	// make --upgrade impossible on a slow link. The archive gets its own generous deadline.
	releaseMetadataTimeout = 60 * time.Second
	releaseDownloadTimeout = 15 * time.Minute
)

type releaseELFIdentity struct {
	machine elf.Machine
	class   elf.Class
	data    elf.Data
}

var releaseELFIdentities = map[string]releaseELFIdentity{
	"amd64":   {machine: elf.EM_X86_64, class: elf.ELFCLASS64, data: elf.ELFDATA2LSB},
	"arm64":   {machine: elf.EM_AARCH64, class: elf.ELFCLASS64, data: elf.ELFDATA2LSB},
	"386":     {machine: elf.EM_386, class: elf.ELFCLASS32, data: elf.ELFDATA2LSB},
	"ppc64le": {machine: elf.EM_PPC64, class: elf.ELFCLASS64, data: elf.ELFDATA2LSB},
	"s390x":   {machine: elf.EM_S390, class: elf.ELFCLASS64, data: elf.ELFDATA2MSB},
}

// SelfUpgrade 复刻 run_self_upgrade（--upgrade）：非 root 时经 sudo 重新执行自身；否则下载发布包，
// 校验 sha256，用内置 pin 指纹强制校验 GPG 签名（解包前，fail-closed），安全解包并做版本/架构绑定，
// 最后运行已验证包内当前架构的 Go 二进制完成安装。二进制替换发生在安装器子进程的备份/回滚事务里，
// 本进程作为“存活父进程”等待并透传其退出码——不做 rename-then-exec 自替换，也不依赖 Bash runtime。
func SelfUpgrade(ver string, disp i18n.Lang, langExplicit bool) int {
	// Reject a malformed build identity before privilege escalation or any
	// release-network access. A valid release version is part of the upgrade
	// trust binding, not merely display text.
	if !validUpgradeLocalVersion(ver) {
		say(os.Stderr, disp, "本地版本数据无效，拒绝升级", "Invalid local version data; refusing to upgrade")
		return 1
	}
	if os.Geteuid() != 0 {
		sudo, err := commandpath.Resolve("sudo")
		if err != nil {
			say(os.Stderr, disp, "升级需要 root 权限", "Root privileges are required to upgrade")
			return 1
		}
		self, err := os.Executable()
		if err != nil {
			say(os.Stderr, disp, "无法定位自身可执行文件", "Cannot locate own executable")
			return 1
		}
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		argv := selfUpgradeSudoArgs(sudo, self, disp, langExplicit)
		if err := syscall.Exec(sudo, argv, trustedPATHEnvironment(os.Environ())); err != nil {
			say(os.Stderr, disp, "sudo 重新执行失败", "Failed to re-exec via sudo")
			return 1
		}
		return 1 // exec 成功则不会到达
	}

	client := httpx.New(releaseMetadataTimeout)
	latest, err := dist.LatestRelease(client, Repo)
	if err != nil {
		say(os.Stderr, disp, "无法获取最新版本", "Failed to fetch latest version")
		return 1
	}
	comparison, err := version.Compare(latest, ver)
	if err != nil {
		say(os.Stderr, disp, "版本数据无效，拒绝升级", "Invalid version data; refusing to upgrade")
		return 1
	}
	if comparison == 0 {
		say(os.Stdout, disp, "已经是最新版本 "+ver, "Already up to date: "+ver)
		return 0
	}
	if comparison < 0 {
		say(os.Stdout, disp, "本地版本 "+ver+" 高于或等于最新发布 "+latest+"，不自动升级。",
			"Local version "+ver+" is at or above latest release "+latest+"; not upgrading.")
		return 0
	}

	tmp, err := createUpgradeTempDir(privilegedUpgradeTempBase)
	if err != nil {
		say(os.Stderr, disp, "创建临时目录失败", "Failed to create temp dir")
		return 1
	}
	defer os.RemoveAll(tmp)

	pkg := "security-update-notify-" + latest + ".tar.gz"
	pkgdir := "security-update-notify-" + latest

	say(os.Stdout, disp, "正在下载并校验发布包: "+ver+" -> "+latest, "Downloading and verifying release: "+ver+" -> "+latest)
	tarPath := filepath.Join(tmp, pkg)
	shaPath := tarPath + ".sha256"
	if err := requireUpgradeGPG(dist.GPGAvailable()); err != nil {
		say(os.Stderr, disp, "缺少 gpg；为安全起见拒绝升级。",
			"Missing gpg; refusing to upgrade for safety.")
		return 1
	}
	selectedBase, err := dist.DownloadReleaseSet(httpx.New(releaseDownloadTimeout), dist.ReleaseBases(Repo, latest), pkg, tmp, true)
	if err != nil {
		say(os.Stderr, disp, "镜像和 GitHub 均无法提供完整发布包", "Neither the mirror nor GitHub provided a complete release set")
		return 1
	}
	if strings.HasPrefix(selectedBase, dist.DefaultReleaseMirrorBase) {
		say(os.Stdout, disp, "已通过发布镜像下载", "Downloaded through the release mirror")
	} else {
		say(os.Stdout, disp, "发布镜像不可用，已回退 GitHub", "Release mirror unavailable; fell back to GitHub")
	}

	// 签名和固定指纹校验在解包前恒为必需；缺 .asc 或缺 gpg 都会 fail closed。
	ascPath := tarPath + ".asc"
	if err := dist.VerifyReleaseKey(tarPath, shaPath, ascPath, assets.ReleaseSigningPublicKey(), assets.ReleaseSigningFingerprint); err != nil {
		say(os.Stderr, disp, "签名或校验失败；拒绝升级："+err.Error(), "Verification failed; refusing to upgrade: "+err.Error())
		return 1
	}
	say(os.Stdout, disp, "签名校验通过 ("+assets.ReleaseSigningFingerprint+")", "Signature verified ("+assets.ReleaseSigningFingerprint+")")

	// 安全解包（拒绝穿越/特殊条目/顶层目录外条目），并做版本绑定核对。
	if err := validateUpgradeArchive(tarPath, pkgdir); err != nil {
		say(os.Stderr, disp, "压缩包安全检查失败："+err.Error(), "Archive safety check failed: "+err.Error())
		return 1
	}
	if err := dist.Extract(tarPath, tmp); err != nil {
		say(os.Stderr, disp, "解包失败："+err.Error(), "Extraction failed: "+err.Error())
		return 1
	}
	extractDir := filepath.Join(tmp, pkgdir)
	installBinary, err := selectUpgradeBinary(extractDir, latest, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		say(os.Stderr, disp, "发布包校验失败；拒绝升级："+err.Error(),
			"Release payload validation failed; refusing to upgrade: "+err.Error())
		return 1
	}
	if err := validateUpgradeBinaryVersion(installBinary, extractDir, latest); err != nil {
		say(os.Stderr, disp, "发布包二进制版本校验失败；拒绝升级："+err.Error(),
			"Release binary version validation failed; refusing to upgrade: "+err.Error())
		return 1
	}

	say(os.Stdout, disp, "正在以已校验的发布包升级...", "Upgrading from the verified release...")
	installCtx, cancelInstall := context.WithTimeout(context.Background(), upgradeInstallerTimeout)
	cmd := upgradeInstallCommand(installCtx, installBinary, extractDir, disp)
	if err := cmd.Run(); err != nil {
		installCtxErr := installCtx.Err()
		cancelInstall()
		if errors.Is(installCtxErr, context.DeadlineExceeded) {
			say(os.Stderr, disp, "Go 安装器运行超过 1 小时，升级已中止。", "The Go installer exceeded the 1-hour limit; upgrade aborted.")
			return 1
		}
		if code, ok := upgradeInstallerExitCode(err); ok {
			return code
		}
		say(os.Stderr, disp, "运行 Go 安装器失败："+err.Error(), "Failed to run the Go installer: "+err.Error())
		return 1
	}
	cancelInstall()
	return 0
}

func validUpgradeLocalVersion(ver string) bool {
	// version.Compare deliberately trims surrounding whitespace for general
	// comparisons. A compiled-in build identity is a stricter trust input: do
	// not let terminal controls or an unbounded value survive into privileged
	// upgrade output and release selection.
	if ver == "" || len(ver) > 128 || ver != strings.TrimSpace(ver) {
		return false
	}
	_, err := version.Compare(ver, ver)
	return err == nil
}

func selfUpgradeSudoArgs(sudo, self string, disp i18n.Lang, langExplicit bool) []string {
	argv := []string{sudo, self, "--upgrade"}
	if langExplicit {
		argv = append(argv, "--lang", string(disp))
	}
	return argv
}

func trustedPATHEnvironment(env []string) []string {
	return commandpath.SanitizedEnvironmentFrom(env, commandpath.TrustedPATH, nil)
}

func requireUpgradeGPG(available bool) error {
	if !available {
		return errors.New("gpg is required for release signature verification")
	}
	return nil
}

// createUpgradeTempDir deliberately takes an explicit base and never consults TMPDIR. Shared system
// temporary directories are accepted only when the sticky bit prevents unprivileged users from
// replacing the root-owned upgrade tree after its release signature has been verified.
func createUpgradeTempDir(base string) (string, error) {
	return createUpgradeTempDirForOwner(base, 0)
}

func createUpgradeTempDirForOwner(base string, ownerUID int) (string, error) {
	return filetrust.MkdirTemp(base, "sun-upgrade-", ownerUID)
}

func validateUpgradeArchive(tarPath, pkgdir string) error {
	return dist.CheckArchive(tarPath, pkgdir)
}

func selectUpgradeBinary(extractDir, expectedVersion, goos, goarch string) (string, error) {
	packageVersion, err := readPackageVersion(filepath.Join(extractDir, "VERSION"))
	if err != nil {
		return "", err
	}
	if packageVersion != expectedVersion {
		return "", fmt.Errorf("package version %q does not match requested version %q", packageVersion, expectedVersion)
	}
	identity, ok := releaseELFIdentities[goarch]
	if goos != "linux" || !ok {
		return "", fmt.Errorf("release does not support %s/%s", goos, goarch)
	}

	path := filepath.Join(extractDir, "files", "security-update-notify-linux-"+goarch)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("release is missing the linux/%s binary", goarch)
		}
		return "", fmt.Errorf("inspect linux/%s binary: %w", goarch, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", fmt.Errorf("linux/%s binary is empty or not a regular file", goarch)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("linux/%s binary is not executable", goarch)
	}
	if err := validateUpgradeELF(path, identity); err != nil {
		return "", fmt.Errorf("invalid linux/%s binary: %w", goarch, err)
	}
	return path, nil
}

func validateUpgradeELF(path string, want releaseELFIdentity) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("not an ELF executable: %w", err)
	}
	defer f.Close()
	if f.Machine != want.machine || f.Class != want.class || f.Data != want.data {
		return fmt.Errorf("ELF identity is machine=%s class=%s data=%s", f.Machine, f.Class, f.Data)
	}
	return nil
}

type boundedUpgradeOutput struct {
	buf      bytes.Buffer
	overflow bool
}

func (w *boundedUpgradeOutput) Write(p []byte) (int, error) {
	if remaining := maxUpgradeVersionOutputBytes + 1 - w.buf.Len(); remaining > 0 {
		if len(p) < remaining {
			remaining = len(p)
		}
		_, _ = w.buf.Write(p[:remaining])
	}
	if w.buf.Len() > maxUpgradeVersionOutputBytes {
		w.overflow = true
	}
	return len(p), nil
}

func validateUpgradeBinaryVersion(binary, extractDir, expectedVersion string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return validateUpgradeBinaryVersionContext(ctx, binary, extractDir, expectedVersion)
}

func validateUpgradeBinaryVersionContext(ctx context.Context, binary, extractDir, expectedVersion string) error {
	cmd := sysexec.CommandContext(ctx, binary, "--version")
	cmd.Dir = extractDir
	cmd.Env = upgradeChildEnvironment(os.Environ(), false)
	stdout, stderr := &boundedUpgradeOutput{}, &boundedUpgradeOutput{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("version probe timed out")
	}
	if err != nil {
		return fmt.Errorf("version probe failed: %w", err)
	}
	if stdout.overflow || stderr.overflow {
		return fmt.Errorf("version probe output exceeds %d bytes", maxUpgradeVersionOutputBytes)
	}
	want := "security-update-notify " + expectedVersion + "\n"
	if stdout.buf.String() != want || stderr.buf.Len() != 0 {
		return fmt.Errorf("binary reported unexpected version output %q", stdout.buf.String())
	}
	return nil
}

func readPackageVersion(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("release is missing root VERSION")
		}
		return "", fmt.Errorf("open root VERSION: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect root VERSION: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256 {
		return "", errors.New("root VERSION is empty, oversized, or not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return "", fmt.Errorf("read root VERSION: %w", err)
	}
	const prefix = `VERSION="`
	const suffix = "\"\n"
	if len(b) <= len(prefix)+len(suffix) || len(b) > 256 ||
		!strings.HasPrefix(string(b), prefix) || !strings.HasSuffix(string(b), suffix) {
		return "", errors.New(`root VERSION must have the exact form VERSION="<version>"`)
	}
	value := string(b[len(prefix) : len(b)-len(suffix)])
	if !latestVersionRe.MatchString(value) || string(b) != prefix+value+suffix {
		return "", errors.New("root VERSION contains an invalid version")
	}
	if _, err := version.Compare(value, value); err != nil {
		return "", errors.New("root VERSION contains an invalid version")
	}
	return value, nil
}

func upgradeInstallCommand(ctx context.Context, binary, extractDir string, disp i18n.Lang) *sysexec.Cmd {
	cmd := sysexec.CommandContext(ctx, binary, "install", "--non-interactive", "-y", "--lang", string(disp))
	cmd.Dir = extractDir
	cmd.Env = upgradeChildEnvironment(os.Environ(), true)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func upgradeInstallerExitCode(err error) (int, bool) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return code, true
		}
	}
	return 0, false
}

func upgradeChildEnvironment(env []string, markUpgrade bool) []string {
	keep := map[string]bool{
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
		"http_proxy": true, "https_proxy": true, "no_proxy": true,
		"TERM": true, "TZ": true, "SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS": true,
	}
	out := make([]string, 0, len(keep)+6)
	for _, item := range env {
		key, _, ok := strings.Cut(item, "=")
		if ok && keep[key] {
			out = append(out, item)
		}
	}
	out = append(out,
		"HOME=/root",
		"USER=root",
		"LOGNAME=root",
		"PATH="+privilegedUpgradePath,
		"LC_ALL=C",
	)
	if markUpgrade {
		out = append(out, "SECURITY_UPDATE_NOTIFY_UPGRADE=1")
	}
	return out
}

func envWithOverride(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}
