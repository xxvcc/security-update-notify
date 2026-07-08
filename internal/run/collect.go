package run

import (
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/osrel"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/systemd"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

const osReleasePath = "/etc/os-release"

// Flags 是影响采集/决策的运行时标志。
type Flags struct {
	TestReboot bool   // --test-reboot：用固定夹具，不读真实重启状态
	TestOK     bool   // --test-ok：无关注时也发 OK
	NoDedupe   bool   // --no-dedupe
	Lang       string // --lang（UI_LANG），空表示未指定
}

// --test-reboot 的固定摘要（与 check_apt/check_dnf 的测试分支一致）。
const (
	aptTestRebootSummary = "NEEDRESTART-VER: test\nNEEDRESTART-KCUR: test-current\nNEEDRESTART-KEXP: test-expected\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service"
	dnfTestRebootSummary = "needs-restarting -r:\nReboot is required to ensure that your system benefits from these updates.\n\nneeds-restarting -s:\ntest-service.service"
)

// Collect 从系统与配置采集 run 路径的全部输入。纯逻辑在 Assemble；此处集中所有 IO/exec。
func Collect(cfg *config.Config, f Flags) Input {
	o := osrel.Read(osReleasePath)

	be := cfg.Get("BACKEND")
	if be == "" || be == "auto" {
		be = osrel.AutoBackend(o)
	}
	notifyLang := i18n.NormalizeNotify(orDefault(cfg.Get("NOTIFY_LANG"), "zh"))

	includeIP, publicIP := resolvePublicIP(cfg)

	in := Input{
		Host:            hostLabel(cfg),
		Backend:         be,
		NotifyLang:      notifyLang,
		IncludePublicIP: includeIP,
		PublicIP:        publicIP,
		OS:              orDefault(o.PrettyName, "unknown"),
		Kernel:          kernelRelease(),
		Now:             time.Now().Format("2006-01-02 15:04:05 MST"),
		SendOK:          f.TestOK || cfg.Get("NOTIFY_OK") == "1",
		NoDedupe:        f.NoDedupe,
	}

	if f.TestReboot {
		in.Restart = testRebootState(be)
	} else if be == "apt" {
		in.Restart = collectAPT()
	} else if be == "dnf" {
		in.Restart = collectDNF()
	}

	in.Health, in.Pending, in.EOL = collectWatchdog(cfg, be, o)
	return in
}

// collectWatchdog 采集看门狗三项（健康/待装/EOL），受各自的配置开关门控。Collect 与 Doctor 共用。
func collectWatchdog(cfg *config.Config, be string, o osrel.OSRelease) (watchdog.Health, watchdog.Pending, watchdog.EOL) {
	var h watchdog.Health
	if truthyLooseDefault(cfg.Get("CHECK_UPDATE_HEALTH"), true) && systemd.Available() {
		h = collectHealth(be, staleDays(cfg))
	}
	p := watchdog.CollectPending(be, collectPendingOutput(be))
	var e watchdog.EOL
	if truthyLooseDefault(cfg.Get("CHECK_EOL"), true) {
		e = watchdog.CheckEOL(o.ID, o.VersionID, o.PrettyName, time.Now().Unix())
	}
	return h, p, e
}

// resolvePublicIP 复刻 INCLUDE_PUBLIC_IP + PUBLIC_IP + 运行时自动获取 的解析。
func resolvePublicIP(cfg *config.Config) (include bool, ip string) {
	if !truthyLooseDefault(cfg.Get("INCLUDE_PUBLIC_IP"), true) {
		return false, ""
	}
	if v := cfg.Get("PUBLIC_IP"); v != "" {
		return true, v
	}
	return true, fetchPublicIP()
}

func testRebootState(be string) backend.RestartState {
	if be == "dnf" {
		return backend.RestartState{RebootRequired: true, RebootPkgs: "kernel\nTEST-MODE-no-real-reboot", RestartAttention: true, RestartSummary: dnfTestRebootSummary}
	}
	return backend.RestartState{RebootRequired: true, RebootPkgs: "linux-image-amd64\nTEST-MODE-no-real-reboot", RestartAttention: true, RestartSummary: aptTestRebootSummary}
}

func collectAPT() backend.RestartState {
	pkgs := ""
	if b, err := os.ReadFile("/var/run/reboot-required.pkgs"); err == nil {
		pkgs = string(b)
	}
	hasNR := sysexec.Look("needrestart")
	nrb := ""
	if hasNR {
		nrb = sysexec.Run("needrestart", "-b").Stdout
	}
	return backend.ParseAPT(backend.APTInput{
		RebootRequiredExists: fileExists("/var/run/reboot-required"),
		RebootRequiredPkgs:   pkgs,
		HasNeedrestart:       hasNR,
		NeedrestartB:         nrb,
	})
}

func collectDNF() backend.RestartState {
	hasNR := sysexec.Look("needs-restarting")
	var nrR, nrS string
	var rcR int
	hasS := false
	if hasNR {
		r := sysexec.Run("needs-restarting", "-r") // Bash 用 2>&1
		nrR = r.Stdout + r.Stderr
		rcR = r.Code
		help := sysexec.Run("needs-restarting", "--help")
		hasS = strings.Contains(help.Stdout+help.Stderr, "-s")
		if hasS {
			nrS = sysexec.Run("needs-restarting", "-s").Stdout
		}
	}
	updateInfo := ""
	if sysexec.Look("dnf") {
		updateInfo = firstNLines(sysexec.Run("dnf", "-q", "updateinfo", "list", "security", "updates").Stdout, 40)
	}
	return backend.ParseDNF(backend.DNFInput{
		HasNeedsRestarting: hasNR,
		NeedsRestartingR:   nrR,
		NeedsRestartingRC:  rcR,
		HasS:               hasS,
		NeedsRestartingS:   nrS,
		UpdateInfo:         updateInfo,
	})
}

func collectHealth(be string, stale int) watchdog.Health {
	var timer, svc string
	switch be {
	case "apt":
		timer, svc = "apt-daily-upgrade.timer", "apt-daily-upgrade.service"
	case "dnf":
		timer, svc = "dnf-automatic.timer", "dnf-automatic.service"
	default:
		return watchdog.Health{}
	}
	lastTs := systemd.ShowValue(svc, "ExecMainExitTimestamp")
	timerTrig := systemd.ShowValue(timer, "LastTriggerUSec")
	return watchdog.CheckHealth(watchdog.HealthInput{
		Backend:           be,
		TimerEnabled:      systemd.IsEnabled(timer),
		SvcResult:         systemd.ShowValue(svc, "Result"),
		HaveSvcExit:       lastTs != "",
		SvcExitEpoch:      parseSystemdTime(lastTs),
		HaveTimerTrigger:  timerTrig != "" && timerTrig != "n/a",
		TimerTriggerEpoch: parseSystemdTime(timerTrig),
		Now:               time.Now().Unix(),
		StaleDays:         stale,
		Disks:             collectDisks(),
	})
}

func collectPendingOutput(be string) string {
	switch be {
	case "apt":
		if sysexec.Look("apt-get") {
			return sysexec.Run("apt-get", "-s", "upgrade").Stdout
		}
	case "dnf":
		if sysexec.Look("dnf") {
			return sysexec.Run("dnf", "-q", "updateinfo", "list", "security").Stdout
		}
	}
	return ""
}

func collectDisks() []watchdog.DiskAvail {
	var out []watchdog.DiskAvail
	for _, mp := range []string{"/", "/boot"} {
		fi, err := os.Stat(mp)
		if err != nil || !fi.IsDir() {
			continue
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(mp, &st); err != nil {
			continue
		}
		// Bavail 与 Bsize 的类型随架构而异（386/s390x 上 Bsize 是 int32/uint32），一律显式转 int64。
		availKB := int64(st.Bavail) * int64(st.Bsize) / 1024
		out = append(out, watchdog.DiskAvail{Mount: mp, AvailKB: availKB})
	}
	return out
}

// parseSystemdTime 复刻 `date -d "$ts" +%s`：保留一个极小的 date exec 以精确匹配 systemd 人类时间戳
// 到 epoch 的换算（该值进入 HEALTH_SIG，属去重 hash，故要求字节级一致）。空/解析失败返回 0。
func parseSystemdTime(ts string) int64 {
	if ts == "" {
		return 0
	}
	r := sysexec.Run("date", "-d", ts, "+%s")
	if r.Code != 0 {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(r.Stdout), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func hostLabel(cfg *config.Config) string {
	if v := cfg.Get("HOST_LABEL"); v != "" {
		return v
	}
	if r := sysexec.Run("hostname", "-f"); r.Code == 0 {
		if h := strings.TrimSpace(r.Stdout); h != "" {
			return h
		}
	}
	if r := sysexec.Run("hostname"); r.Code == 0 {
		if h := strings.TrimSpace(r.Stdout); h != "" {
			return h
		}
	}
	return "unknown"
}

func kernelRelease() string {
	if r := sysexec.Run("uname", "-r"); r.Code == 0 {
		if k := strings.TrimSpace(r.Stdout); k != "" {
			return k
		}
	}
	return "unknown"
}

// fetchPublicIP 复刻 get_public_ip：依次尝试 ipify / ifconfig.me，校验是合法 IP，失败返回 unknown。
func fetchPublicIP() string {
	client := httpx.New(5 * time.Second)
	for _, url := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		buf := make([]byte, 128)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		ip := strings.Fields(strings.TrimSpace(string(buf[:n])))
		if len(ip) == 0 {
			continue
		}
		if net.ParseIP(ip[0]) != nil {
			return ip[0]
		}
	}
	return "unknown"
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func firstNLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func truthyLooseDefault(v string, dflt bool) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	case "":
		return dflt
	default:
		return dflt // 无效值回退默认（运行时对这些键无效即按默认）
	}
}

func staleDays(cfg *config.Config) int {
	v := cfg.Get("STALE_UPDATE_DAYS")
	if v == "" {
		return 7
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 7
	}
	return n
}
