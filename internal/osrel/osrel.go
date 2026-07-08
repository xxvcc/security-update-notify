// Package osrel 解析 /etc/os-release 并做后端探测与支持分级，取代 files/lib.sh 与运行时内联的
// os-release 解析。AutoBackend 复刻“运行时”的 BACKEND=auto 语义（BACKEND 是去重 hash 字段，必须一致）；
// SupportTier 复刻安装器 lib.sh 的 supported/best-effort/unsupported 分级。
//
// Package osrel parses /etc/os-release and does backend detection + support tiering, replacing files/lib.sh
// and the runtime's inline os-release parsing. AutoBackend reproduces the RUNTIME's BACKEND=auto semantics
// (BACKEND is a dedup-hash field, so it must match); SupportTier reproduces the installer's lib.sh
// supported/best-effort/unsupported tiering.
package osrel

import (
	"bufio"
	"os"
	"strings"
)

// OSRelease 保存运行时/安装器关心的 os-release 字段。
type OSRelease struct {
	ID         string
	VersionID  string
	PrettyName string
	IDLike     string
}

// Read 解析 os-release 文件（缺失返回零值）。只取 ID/VERSION_ID/PRETTY_NAME/ID_LIKE，剥离一层引号，
// 复刻运行时与 lib.sh 的解析（不做变量展开）。
func Read(path string) OSRelease {
	var o OSRelease
	f, err := os.Open(path)
	if err != nil {
		return o
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
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
		}
	}
	return o
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	return v
}

// AutoBackend 复刻运行时 BACKEND=auto 的判定：debian/ubuntu→apt；rhel/rocky/almalinux/fedora/centos/
// amzn→dnf；否则用 ID_LIKE 兜底（*debian*/*ubuntu*→apt，*rhel*/*fedora*/*centos*→dnf），仍无则 unknown。
func AutoBackend(o OSRelease) string {
	switch o.ID {
	case "debian", "ubuntu":
		return "apt"
	case "rhel", "rocky", "almalinux", "fedora", "centos", "amzn":
		return "dnf"
	}
	if o.IDLike != "" {
		padded := " " + o.IDLike + " "
		if strings.Contains(padded, " debian ") || strings.Contains(padded, " ubuntu ") {
			return "apt"
		}
		if strings.Contains(padded, " rhel ") || strings.Contains(padded, " fedora ") || strings.Contains(padded, " centos ") {
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

// SupportTier 复刻 lib.sh lib_detect_backend：返回安装器视角的 backend 与支持级别。
func SupportTier(o OSRelease) (backend, tier string) {
	backend, tier = "unknown", Unsupported
	major := o.VersionID
	if i := strings.IndexByte(major, '.'); i >= 0 {
		major = major[:i]
	}
	switch o.ID {
	case "debian":
		backend = "apt"
		switch o.VersionID {
		case "12", "13":
			tier = Supported
		case "11":
			tier = BestEffort
		}
	case "ubuntu":
		backend = "apt"
		switch o.VersionID {
		case "22.04", "24.04":
			tier = Supported
		case "20.04":
			tier = BestEffort
		}
	case "rhel", "rocky", "almalinux":
		backend = "dnf"
		switch major {
		case "8", "9":
			tier = Supported
		}
	case "fedora":
		backend, tier = "dnf", Supported
	case "centos":
		backend = "dnf"
		switch major {
		case "8", "9":
			tier = BestEffort
		}
	case "amzn":
		backend = "dnf"
		if o.VersionID == "2023" {
			tier = BestEffort
		}
	}
	if backend == "unknown" && o.IDLike != "" {
		padded := " " + o.IDLike + " "
		switch {
		case strings.Contains(padded, " debian ") || strings.Contains(padded, " ubuntu "):
			backend = "apt"
		case strings.Contains(padded, " rhel ") || strings.Contains(padded, " fedora ") || strings.Contains(padded, " centos "):
			backend = "dnf"
		}
	}
	return backend, tier
}
