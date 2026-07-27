package run

import (
	"encoding/json"
	"io"
	"math"
	"math/bits"
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

const (
	osReleasePath              = "/etc/os-release"
	osReleaseFallbackPath      = "/usr/lib/os-release"
	maxRebootPkgsBytes         = 1 << 20
	restartProbeCommandTimeout = 30 * time.Second
	identityCommandTimeout     = 5 * time.Second
	ubuntu2004ESMSupportEnd    = "2030-04-30"
)

// Flags 是影响采集/决策的运行时标志。
type Flags struct {
	TestReboot    bool   // --test-reboot：用固定夹具，不读真实重启状态
	TestOK        bool   // --test-ok：无关注时也发 OK
	NoDedupe      bool   // --no-dedupe
	Lang          string // --lang（UI_LANG），空表示未指定
	Version       string // 编译期注入的 SUN 版本，仅用于通知展示
	NoStateWrites bool   // dry-run/diagnostic paths must not create patch-age state
}

// --test-reboot 的固定摘要（与 check_apt/check_dnf 的测试分支一致）。
const (
	aptTestRebootSummary = "NEEDRESTART-VER: test\nNEEDRESTART-KCUR: test-current\nNEEDRESTART-KEXP: test-expected\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service"
	dnfTestRebootSummary = "needs-restarting -r:\nReboot is required to ensure that your system benefits from these updates.\n\nneeds-restarting -s:\ntest-service.service"
)

// Collect 从系统与配置采集 run 路径的全部输入。纯逻辑在 Assemble；此处集中所有 IO/exec。
func Collect(cfg *config.Config, f Flags) Input {
	o := osrel.ReadFirst(osReleasePath, osReleaseFallbackPath)

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
		Version:         f.Version,
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

	persistPatchState := !f.NoStateWrites && !f.TestReboot && !f.TestOK
	skipSelfUpdate := f.NoStateWrites || f.TestReboot || f.TestOK
	in.Health, in.Pending, in.Patch, in.EOL = collectWatchdog(cfg, be, o, in.Restart, f.Version, persistPatchState, false, skipSelfUpdate)
	if be == "dnf" && len(in.Pending.Packages) > 0 {
		pkgs := in.Pending.Packages
		if len(pkgs) > 40 {
			pkgs = pkgs[:40]
		}
		in.Restart.RebootPkgs = strings.Join(pkgs, "\n")
	}
	return in
}

// collectWatchdog 采集看门狗三项（健康/待装/EOL），受各自的配置开关门控。Collect 与 Doctor 共用。
func collectWatchdog(cfg *config.Config, be string, o osrel.OSRelease, restart backend.RestartState, currentVersion string, persistPatchState, forceSelfUpdate, skipSelfUpdate bool) (watchdog.Health, watchdog.Pending, watchdog.Patch, watchdog.EOL) {
	var h watchdog.Health
	if truthyLooseDefault(cfg.Get("CHECK_UPDATE_HEALTH"), true) && systemd.Available() {
		h = collectHealth(be, staleDays(cfg))
	}
	patch, p := collectPatchWatchdog(cfg, be, restart, currentVersion, patchCollectOptions{PersistState: persistPatchState, ForceSelfUpdate: forceSelfUpdate, SkipSelfUpdate: skipSelfUpdate})
	var e watchdog.EOL
	if truthyLooseDefault(cfg.Get("CHECK_EOL"), true) {
		if supportEnd := effectiveSupportEnd(o); supportEnd != "" {
			e = watchdog.CheckEOLDate(supportEnd, time.Now().Unix())
		}
	}
	return h, p, patch, e
}

func effectiveSupportEnd(o osrel.OSRelease) string {
	if o.ID == "ubuntu" && o.VersionID == "20.04" {
		if ubuntuESMInfraEnabled(identityCommandTimeout) {
			return ubuntu2004ESMSupportEnd
		}
		// Ubuntu 20.04 is past standard maintenance. Do not let generic
		// os-release metadata extend it without local entitlement evidence.
		return watchdog.EolDateFor(o.ID, o.VersionID, o.PrettyName)
	}
	if supportEnd := osrel.SupportEndDate(o); supportEnd != "" {
		return supportEnd
	}
	return watchdog.EolDateFor(o.ID, o.VersionID, o.PrettyName)
}

func ubuntuESMInfraEnabled(timeout time.Duration) bool {
	command := ""
	for _, candidate := range []string{"pro", "ua"} {
		if sysexec.Look(candidate) {
			command = candidate
			break
		}
	}
	if command == "" {
		return false
	}
	result := sysexec.RunTimeout(timeout, command, "api", "u.pro.status.enabled_services.v1")
	return result.Err == nil && result.Code == 0 && parseUbuntuESMInfraStatus(result.Stdout)
}

func parseUbuntuESMInfraStatus(output string) bool {
	var response struct {
		SchemaVersion string             `json:"_schema_version"`
		Result        string             `json:"result"`
		Errors        *[]json.RawMessage `json:"errors"`
		Data          struct {
			Type       string `json:"type"`
			Attributes struct {
				EnabledServices *[]struct {
					Name string `json:"name"`
				} `json:"enabled_services"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &response); err != nil ||
		response.SchemaVersion != "v1" || response.Result != "success" ||
		response.Data.Type != "EnabledServices" || response.Errors == nil || len(*response.Errors) != 0 ||
		response.Data.Attributes.EnabledServices == nil {
		return false
	}
	for _, service := range *response.Data.Attributes.EnabledServices {
		if service.Name == "esm-infra" {
			return true
		}
	}
	return false
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
	return collectAPTWithTimeout(restartProbeCommandTimeout)
}

func collectAPTWithTimeout(timeout time.Duration) backend.RestartState {
	pkgs := readFilePrefix("/var/run/reboot-required.pkgs", maxRebootPkgsBytes)
	hasNR := sysexec.Look("needrestart")
	nrb := ""
	if hasNR {
		nrb = sysexec.RunTimeout(timeout, "needrestart", "-b").Stdout
	}
	return backend.ParseAPT(backend.APTInput{
		RebootRequiredExists: fileExists("/var/run/reboot-required"),
		RebootRequiredPkgs:   pkgs,
		HasNeedrestart:       hasNR,
		NeedrestartB:         nrb,
	})
}

func readFilePrefix(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return ""
	}
	return string(b)
}

func collectDNF() backend.RestartState {
	return collectDNFWithTimeout(restartProbeCommandTimeout)
}

func collectDNFWithTimeout(timeout time.Duration) backend.RestartState {
	runtime := detectDNFRuntime(timeout)
	if !runtime.GenerationKnown {
		return backend.RestartState{
			RestartSummary: "无法识别 DNF 代际；已跳过 needs-restarting 检查 / DNF generation probe failed; skipped needs-restarting checks",
			ProbeIssue:     "dnf-restart-probe-failed",
		}
	}
	if runtime.isDNF5() {
		return collectDNF5WithRuntime(timeout, runtime)
	}
	hasNR := sysexec.Look("needs-restarting")
	var nrR, nrS string
	var rcR int
	hasS := false
	probeIssue := ""
	rebootValid := false
	if hasNR {
		r := sysexec.RunTimeout(timeout, "needs-restarting", "-r")
		nrR = r.Stdout
		rcR = r.Code
		_, rebootValid = backend.DNFRebootDecision(nrR, rcR)
		rebootValid = rebootValid && r.Err == nil && strings.TrimSpace(r.Stderr) == ""
		if !rebootValid {
			probeIssue = "dnf-restart-probe-failed"
		}
		help := sysexec.RunTimeout(timeout, "needs-restarting", "--help")
		if help.Code != 0 {
			probeIssue = "dnf-restart-probe-failed"
		} else {
			hasS = strings.Contains(help.Stdout+help.Stderr, "-s")
		}
		if hasS {
			services := sysexec.RunTimeout(timeout, "needs-restarting", "-s")
			var valid bool
			nrS, valid = backend.NormalizeDNFServiceList(services.Stdout)
			if services.Err != nil || services.Code != 0 || strings.TrimSpace(services.Stderr) != "" || !valid {
				probeIssue = "dnf-restart-probe-failed"
				nrS = ""
			}
		}
	} else {
		probeIssue = "dnf-restart-probe-failed"
	}
	state := backend.ParseDNF(backend.DNFInput{
		Generation:         runtime.Generation,
		HasNeedsRestarting: hasNR,
		NeedsRestartingR:   nrR,
		NeedsRestartingRC:  rcR,
		HasS:               hasS,
		NeedsRestartingS:   nrS,
		UpdateInfo:         "",
	})
	if !rebootValid {
		state.RebootRequired = false
	}
	state.ProbeIssue = probeIssue
	return state
}

func collectDNF5WithRuntime(timeout time.Duration, runtime dnfRuntime) backend.RestartState {
	help := sysexec.RunTimeout(timeout, runtime.Command, "needs-restarting", "--help")
	hasNR := help.Code == 0
	var nrR, nrS string
	var rcR int
	hasS := false
	probeIssue := ""
	rebootValid := false
	if hasNR {
		r := sysexec.RunTimeout(timeout, runtime.Command, "-q", "needs-restarting")
		nrR = r.Stdout
		rcR = r.Code
		_, rebootValid = backend.DNFRebootDecision(nrR, rcR)
		rebootValid = rebootValid && r.Err == nil && strings.TrimSpace(r.Stderr) == ""
		if !rebootValid {
			probeIssue = "dnf-restart-probe-failed"
		}
		hasS = strings.Contains(help.Stdout+help.Stderr, "-s") || strings.Contains(help.Stdout+help.Stderr, "--services")
		if hasS {
			services := sysexec.RunTimeout(timeout, runtime.Command, "-q", "needs-restarting", "-s")
			var valid bool
			nrS, valid = backend.NormalizeDNFServiceList(services.Stdout)
			wantCode := 0
			if nrS != "" {
				wantCode = 1
			}
			if services.Err != nil || services.Code != wantCode || strings.TrimSpace(services.Stderr) != "" || !valid {
				probeIssue = "dnf-restart-probe-failed"
				nrS = ""
			}
		} else {
			probeIssue = "dnf-restart-probe-failed"
		}
	} else {
		probeIssue = "dnf-restart-probe-failed"
	}
	state := backend.ParseDNF(backend.DNFInput{
		Generation:         runtime.Generation,
		HasNeedsRestarting: hasNR,
		NeedsRestartingR:   nrR,
		NeedsRestartingRC:  rcR,
		HasS:               hasS,
		NeedsRestartingS:   nrS,
	})
	if !rebootValid {
		state.RebootRequired = false
	}
	state.ProbeIssue = probeIssue
	return state
}

func collectHealth(be string, stale int) watchdog.Health {
	var timer, svc string
	timerEnabled := false
	var dnfUnit dnfAutomaticUnit
	switch be {
	case "apt":
		timer, svc = "apt-daily-upgrade.timer", "apt-daily-upgrade.service"
		timerEnabled = systemd.IsEnabled(timer)
	case "dnf":
		runtime := detectDNFRuntime(restartProbeCommandTimeout)
		if !runtime.GenerationKnown {
			return watchdog.Health{}
		}
		dnfUnit = selectDNFAutomaticUnit(runtime.Generation, systemd.IsEnabled)
		timer, svc, timerEnabled = dnfUnit.Timer, dnfUnit.Service, dnfUnit.Enabled
	default:
		return watchdog.Health{}
	}
	lastTs := systemd.ShowValue(svc, "ExecMainExitTimestamp")
	timerTrig := systemd.ShowValue(timer, "LastTriggerUSec")
	health := watchdog.CheckHealth(watchdog.HealthInput{
		Backend:           be,
		TimerEnabled:      timerEnabled,
		SvcResult:         systemd.ShowValue(svc, "Result"),
		HaveSvcExit:       lastTs != "",
		SvcExitEpoch:      parseSystemdTime(lastTs),
		HaveTimerTrigger:  timerTrig != "" && timerTrig != "n/a",
		TimerTriggerEpoch: parseSystemdTime(timerTrig),
		Now:               time.Now().Unix(),
		StaleDays:         stale,
		Disks:             collectDisks(),
	})
	if be == "dnf" {
		health.TxtZH = rewriteDNFHealthUnitNames(health.TxtZH, dnfUnit)
		health.TxtEN = rewriteDNFHealthUnitNames(health.TxtEN, dnfUnit)
	}
	return health
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
		// 用 f_frsize（碎片/基本块大小）而非 f_bsize：GNU df -P -k（Bash 运行时的取值来源）以
		// f_bavail * f_frsize 计算可用量，二者在少数 fs（NFS/overlay 等）上不等；用 frsize 保证与
		// df 一致，从而 Go 与 Bash 的 HEALTH_SIG（去重 hash 字段）不漂移。frsize 为 0 时回退 bsize。
		// 类型随架构而异（386/s390x），一律显式转 int64。
		bs := int64(st.Frsize)
		if bs == 0 {
			bs = int64(st.Bsize)
		}
		availKB := diskAvailableKB(st.Bavail, bs)
		out = append(out, watchdog.DiskAvail{Mount: mp, AvailKB: availKB})
	}
	return out
}

func diskAvailableKB(blocks uint64, blockSize int64) int64 {
	if blockSize <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(blocks, uint64(blockSize))
	// Divide the 128-bit byte count by 1024 without first overflowing uint64.
	if hi >= 1<<10 {
		return math.MaxInt64
	}
	kb := hi<<54 | lo>>10
	if kb > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(kb)
}

// parseSystemdTime 复刻 `date -d "$ts" +%s`：保留一个极小的 date exec 以精确匹配 systemd 人类时间戳
// 到 epoch 的换算（该值进入 HEALTH_SIG，属去重 hash，故要求字节级一致）。空/解析失败返回 0。
func parseSystemdTime(ts string) int64 {
	return parseSystemdTimeWithTimeout(ts, identityCommandTimeout)
}

func parseSystemdTimeWithTimeout(ts string, timeout time.Duration) int64 {
	if ts == "" {
		return 0
	}
	r := sysexec.RunTimeout(timeout, "date", "-d", ts, "+%s")
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
	return hostLabelWithTimeout(cfg, identityCommandTimeout)
}

func hostLabelWithTimeout(cfg *config.Config, timeout time.Duration) string {
	if v := cfg.Get("HOST_LABEL"); v != "" {
		return v
	}
	if r := sysexec.RunTimeout(timeout, "hostname", "-f"); r.Code == 0 {
		if h := strings.TrimSpace(r.Stdout); h != "" {
			return h
		}
	}
	if r := sysexec.RunTimeout(timeout, "hostname"); r.Code == 0 {
		if h := strings.TrimSpace(r.Stdout); h != "" {
			return h
		}
	}
	return "unknown"
}

func kernelRelease() string {
	return kernelReleaseWithTimeout(identityCommandTimeout)
}

func kernelReleaseWithTimeout(timeout time.Duration) string {
	if r := sysexec.RunTimeout(timeout, "uname", "-r"); r.Code == 0 {
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
		// 读到 EOF（上限 128 字节），而非单次 Read：分片响应下单次 Read 可能只拿到半个 IP。
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		ip := strings.Fields(strings.TrimSpace(string(b)))
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
