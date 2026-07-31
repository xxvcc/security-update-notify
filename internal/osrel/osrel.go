// Package osrel 解析 /etc/os-release 并做后端探测与支持分级。AutoBackend 保留稳定的 BACKEND=auto
// 语义（BACKEND 是去重 hash 字段，必须一致）；SupportTier 提供 supported/best-effort/unsupported 分级。
//
// Package osrel parses /etc/os-release and performs backend detection plus support tiering. AutoBackend
// retains the stable BACKEND=auto semantics (BACKEND is a dedup-hash field, so it must match); SupportTier
// provides the supported/best-effort/unsupported classification.
package osrel

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

const (
	maxOSReleaseBytes        = 4 << 20
	trustedOSReleaseOwnerUID = 0
)

// OSRelease 保存运行时/安装器关心的 os-release 字段。
type OSRelease struct {
	ID         string
	VersionID  string
	PrettyName string
	IDLike     string
	SupportEnd string
}

// Read 解析 os-release 文件（缺失或不安全时返回零值）。发行版通常允许 /etc/os-release
// 指向 /usr/lib/os-release，因此这里跟随最终 symlink，但最终对象必须是 root 所有、不可被
// group/other 写入的有界普通文件；非阻塞打开避免损坏的 FIFO 或设备文件挂住 timer。硬链接不会
// 绕过 inode 的所有权或写权限检查，因此不要求唯一链接，以兼容不可变/去重系统镜像。
// 只取运行时需要的字段且不做变量展开。
func Read(path string) OSRelease {
	return readTrusted(path, trustedOSReleaseOwnerUID)
}

func readTrusted(path string, ownerUID int) OSRelease {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return OSRelease{}
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return OSRelease{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || filetrust.ValidateRegular(info, ownerUID, 0o022, false) != nil ||
		info.Size() < 0 || info.Size() > maxOSReleaseBytes {
		return OSRelease{}
	}
	contents, err := io.ReadAll(io.LimitReader(f, maxOSReleaseBytes+1))
	if err != nil || len(contents) > maxOSReleaseBytes {
		return OSRelease{}
	}
	o, err := Parse(bytes.NewReader(contents))
	if err != nil {
		return OSRelease{}
	}
	return o
}

// ReadFirst reads the canonical os-release path and falls back only when that
// path does not exist. Permission, I/O, and parse failures are not hidden by a
// second file with different contents.
func ReadFirst(primary, fallback string) OSRelease {
	return readFirstTrusted(primary, fallback, trustedOSReleaseOwnerUID)
}

func readFirstTrusted(primary, fallback string, ownerUID int) OSRelease {
	if _, err := os.Lstat(primary); errors.Is(err, fs.ErrNotExist) {
		return readTrusted(fallback, ownerUID)
	} else if err != nil {
		return OSRelease{}
	}
	return readTrusted(primary, ownerUID)
}

// Parse parses os-release data from r and reports scanner errors. Callers that already control file IO can
// use Parse without duplicating the parser.
func Parse(r io.Reader) (OSRelease, error) {
	var o OSRelease
	sc := bufio.NewScanner(r)
	// 放宽默认 64KB 行上限，避免超长行导致后续行被静默跳过（与 Bash `read -r` 的无界读法一致）。
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = unquote(val)
		switch key {
		case "ID":
			o.ID = val
		case "VERSION_ID":
			o.VersionID = val
		case "PRETTY_NAME":
			o.PrettyName = val
		case "ID_LIKE":
			o.IDLike = val
		case "SUPPORT_END":
			o.SupportEnd = val
		}
	}
	return o, sc.Err()
}

// SupportEndDate 返回 os-release 中格式严格且真实存在的 YYYY-MM-DD 日期；无值或非法值返回空串。
// 它不在解析阶段丢弃原字段，便于诊断损坏的发行版元数据，同时避免调用方误用宽松日期。
func SupportEndDate(o OSRelease) string {
	if o.SupportEnd == "" {
		return ""
	}
	parsed, err := time.Parse(time.DateOnly, o.SupportEnd)
	if err != nil || parsed.Format(time.DateOnly) != o.SupportEnd {
		return ""
	}
	return o.SupportEnd
}

// unquote 顺序剥离（先双引号再单引号），保留 2.x 配置与 os-release 解析语义：值
// "'debian'" 会被剥成 debian；早返回只剥一层，会改变既有 BACKEND 自动判定结果。
func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		v = v[1 : len(v)-1]
	}
	return v
}

// AutoBackend 保留 BACKEND=auto 的既有判定：Debian 系→apt；Fedora/EL 系→dnf；否则用
// ID_LIKE 兜底，仍无则 unknown。Backend 名称保持 apt/dnf，DNF 代际由 Profile.Engine 区分。
func AutoBackend(o OSRelease) string {
	switch o.ID {
	case "debian", "ubuntu":
		return "apt"
	case "rhel", "rocky", "almalinux", "fedora", "centos", "amzn", "ol", "cloudlinux":
		return "dnf"
	}
	if o.IDLike != "" {
		aptLike := hasIDLike(o.IDLike, "debian", "ubuntu")
		dnfLike := hasIDLike(o.IDLike, "rhel", "fedora", "centos")
		if aptLike && dnfLike {
			return "unknown"
		}
		if aptLike {
			return "apt"
		}
		if dnfLike {
			return "dnf"
		}
	}
	return "unknown"
}

// Support 分级。
const (
	Supported   = "supported"
	BestEffort  = "best-effort"
	Unsupported = "unsupported"
)

// Engine 区分共享同一稳定 BACKEND 值的具体实现。
const (
	EngineUnknown = "unknown"
	EngineAPT     = "apt"
	EngineDNF4    = "dnf4"
	EngineDNF5    = "dnf5"
)

// CommandProbe 描述不经 shell 执行的命令探测。Args 是固定前缀；例如 PackageProbe 会在其后追加包名。
type CommandProbe struct {
	Name string
	Args []string
}

// Profile 汇总发行版相关且会随包管理器代际变化的元数据。Backend 是稳定的用户配置值；Engine
// 是内部实现。返回值的 slice 均由本次调用独占，调用方可以安全修改。
type Profile struct {
	Backend  string
	Engine   string
	Tier     string
	Inferred bool // true only when backend/engine came from an unknown distribution's ID_LIKE
	Packages []string

	PackageProbe     CommandProbe
	PackageManagers  []string
	RequiredCommands []string

	AutomaticConfig        string
	AutomaticTimer         string
	AutomaticTimerVariants []string
	AutomaticService       string
	AutomaticProbe         CommandProbe

	RestartHintProbe     CommandProbe
	RestartServicesProbe CommandProbe
}

// ProfileFor 返回安装和运行探测共用的发行版 profile。未知发行版仍可从 ID_LIKE 得到稳定 backend，
// 但不会因此获得支持等级；只有足以可靠判断实现代际时才填充 engine 元数据。
func ProfileFor(o OSRelease) Profile {
	return profileForEngine(o, engineFor(o))
}

// ProfileForDetectedEngine completes an inferred DNF profile after a caller
// has positively identified the installed command generation. It cannot
// override a listed distribution or an already-known engine.
func ProfileForDetectedEngine(o OSRelease, engine string) (Profile, bool) {
	p := ProfileFor(o)
	if !p.Inferred || p.Backend != "dnf" || p.Engine != EngineUnknown ||
		(engine != EngineDNF4 && engine != EngineDNF5) {
		return p, false
	}
	return profileForEngine(o, engine), true
}

func profileForEngine(o OSRelease, engine string) Profile {
	p := Profile{
		Backend: AutoBackend(o),
		Engine:  engine,
		Tier:    supportTierFor(o),
	}
	p.Inferred = !knownDistributionID(o.ID) && p.Backend != "unknown"

	switch p.Engine {
	case EngineAPT:
		p.Packages = []string{"unattended-upgrades", "needrestart", "apt-listchanges", "ca-certificates"}
		p.PackageProbe = CommandProbe{Name: "dpkg", Args: []string{"-s"}}
		p.PackageManagers = []string{"apt-get"}
		p.RequiredCommands = []string{"apt-get", "dpkg", "needrestart"}
		p.AutomaticConfig = "/etc/apt/apt.conf.d/20auto-upgrades"
		p.AutomaticTimer = "apt-daily-upgrade.timer"
		p.AutomaticService = "apt-daily-upgrade.service"
		p.AutomaticProbe = CommandProbe{Name: "unattended-upgrade", Args: []string{"--help"}}
		p.RestartServicesProbe = CommandProbe{Name: "needrestart", Args: []string{"-b"}}
	case EngineDNF4:
		p.Packages = []string{"dnf-automatic", "ca-certificates"}
		if o.ID == "fedora" || o.ID == "amzn" || p.Inferred && !hasIDLike(o.IDLike, "rhel", "centos") {
			p.Packages = append(p.Packages, "dnf-utils")
		} else {
			p.Packages = append(p.Packages, "yum-utils")
		}
		if major, ok := versionMajor(o.VersionID); ok && major == "10" && (isELFamilyID(o.ID) || p.Inferred) {
			// EL10 minimal images provide microdnf but not the dnf command used at runtime.
			p.Packages = append([]string{"dnf"}, p.Packages...)
		}
		p.PackageProbe = CommandProbe{Name: "rpm", Args: []string{"-q"}}
		p.PackageManagers = []string{"dnf", "microdnf", "yum"}
		p.RequiredCommands = []string{"dnf", "rpm", "needs-restarting"}
		p.AutomaticConfig = "/etc/dnf/automatic.conf"
		p.AutomaticTimer = "dnf-automatic.timer"
		p.AutomaticTimerVariants = []string{
			"dnf-automatic-notifyonly.timer",
			"dnf-automatic-download.timer",
			"dnf-automatic-install.timer",
		}
		p.AutomaticService = "dnf-automatic.service"
		p.AutomaticProbe = CommandProbe{Name: "dnf-automatic", Args: []string{"--help"}}
		p.RestartHintProbe = CommandProbe{Name: "needs-restarting", Args: []string{"-r"}}
		p.RestartServicesProbe = CommandProbe{Name: "needs-restarting", Args: []string{"-s"}}
	case EngineDNF5:
		p.Packages = []string{"dnf5-plugin-automatic", "ca-certificates", "dnf5-plugins"}
		p.PackageProbe = CommandProbe{Name: "rpm", Args: []string{"-q"}}
		p.PackageManagers = []string{"dnf", "dnf5", "microdnf"}
		p.RequiredCommands = []string{"dnf", "rpm"}
		p.AutomaticConfig = "/etc/dnf/automatic.conf"
		p.AutomaticTimer = "dnf5-automatic.timer"
		p.AutomaticTimerVariants = []string{"dnf-automatic.timer"}
		p.AutomaticService = "dnf5-automatic.service"
		p.AutomaticProbe = CommandProbe{Name: "dnf", Args: []string{"automatic", "--help"}}
		p.RestartHintProbe = CommandProbe{Name: "dnf", Args: []string{"needs-restarting"}}
		p.RestartServicesProbe = CommandProbe{Name: "dnf", Args: []string{"needs-restarting", "-s"}}
	}
	return p
}

// SupportTier 返回安装器视角的稳定 backend 与支持级别。保留既有 API，具体元数据由 ProfileFor 提供。
func SupportTier(o OSRelease) (backend, tier string) {
	p := ProfileFor(o)
	return p.Backend, p.Tier
}

func supportTierFor(o OSRelease) string {
	tier := Unsupported
	major, validMajor := versionMajor(o.VersionID)
	switch o.ID {
	case "debian":
		switch o.VersionID {
		case "12", "13":
			tier = Supported
		case "11":
			tier = BestEffort
		}
	case "ubuntu":
		switch o.VersionID {
		case "22.04", "24.04", "26.04":
			tier = Supported
		case "20.04":
			tier = BestEffort
		}
	case "rhel", "rocky", "almalinux":
		if validMajor {
			switch major {
			case "8", "9", "10":
				tier = Supported
			}
		}
	case "fedora":
		switch o.VersionID {
		case "43", "44":
			tier = Supported
		}
	case "centos":
		if validMajor {
			switch major {
			case "9", "10":
				tier = BestEffort
			}
		}
	case "ol", "cloudlinux":
		if validMajor {
			switch major {
			case "8", "9", "10":
				tier = BestEffort
			}
		}
	case "amzn":
		if o.VersionID == "2023" {
			tier = BestEffort
		}
	}
	return tier
}

func engineFor(o OSRelease) string {
	switch o.ID {
	case "debian", "ubuntu":
		return EngineAPT
	case "fedora":
		major, ok := numericMajor(o.VersionID)
		if !ok {
			return EngineUnknown
		}
		if major >= 41 {
			return EngineDNF5
		}
		return EngineDNF4
	case "rhel", "rocky", "almalinux", "centos", "amzn", "ol", "cloudlinux":
		return EngineDNF4
	}

	aptLike := hasIDLike(o.IDLike, "debian", "ubuntu")
	elLike := hasIDLike(o.IDLike, "rhel", "centos")
	fedoraLike := hasIDLike(o.IDLike, "fedora")
	if aptLike && (elLike || fedoraLike) {
		return EngineUnknown
	}
	if aptLike {
		return EngineAPT
	}
	return EngineUnknown
}

func isELFamilyID(id string) bool {
	switch id {
	case "rhel", "rocky", "almalinux", "centos", "ol", "cloudlinux":
		return true
	default:
		return false
	}
}

func knownDistributionID(id string) bool {
	switch id {
	case "debian", "ubuntu", "rhel", "rocky", "almalinux", "fedora", "centos", "amzn", "ol", "cloudlinux":
		return true
	default:
		return false
	}
}

func hasIDLike(idLike string, ids ...string) bool {
	if idLike == "" {
		return false
	}
	padded := " " + idLike + " "
	for _, id := range ids {
		if strings.Contains(padded, " "+id+" ") {
			return true
		}
	}
	return false
}

func versionMajor(version string) (string, bool) {
	parts := strings.Split(version, ".")
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	for _, part := range parts {
		if part == "" {
			return "", false
		}
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return "", false
			}
		}
	}
	return parts[0], true
}

func numericMajor(version string) (int, bool) {
	major, ok := versionMajor(version)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, false
	}
	return n, true
}
