package run

import (
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/dist"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/statefile"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/version"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

const patchCommandTimeout = 60 * time.Second

type patchCollectOptions struct {
	PersistState    bool
	ForceSelfUpdate bool
	SkipSelfUpdate  bool
	Now             time.Time
	LatestRelease   func(*http.Client, string) (string, error)
}

func collectPatchWatchdog(cfg *config.Config, be string, restart backend.RestartState, currentVersion string, opts patchCollectOptions) (watchdog.Patch, watchdog.Pending) {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.LatestRelease == nil {
		opts.LatestRelease = dist.LatestRelease
	}
	pending, blocked, issues := collectPackageFacts(cfg, be, opts.Now)
	store := statefile.Store{Dir: stateDirPath()}
	now := opts.Now.Unix()

	pendingAge, err := trackedAgeDays(store, "pending-security.first_seen", pending.Count > 0, now, opts.PersistState)
	if err != nil {
		issues = append(issues, stateIssue())
	}
	rebootAge, err := trackedAgeDays(store, "reboot-required.first_seen", restart.RebootRequired, now, opts.PersistState)
	if err != nil {
		issues = append(issues, stateIssue())
	}
	serviceAge, err := trackedAgeDays(store, "service-restart.first_seen", restart.RestartAttention, now, opts.PersistState)
	if err != nil {
		issues = append(issues, stateIssue())
	}

	latest, updateAvailable, updateErr, stateErr := collectSelfUpdate(cfg, currentVersion, store, opts)
	if stateErr != nil {
		issues = append(issues, stateIssue())
	}
	return watchdog.CheckPatch(watchdog.PatchInput{
		Pending: pending, PendingAgeDays: pendingAge, PendingAlertDays: nonNegativeConfig(cfg, "PENDING_ALERT_DAYS", 3),
		BlockedPackages: blocked, Issues: dedupeIssues(issues),
		RebootAgeDays: rebootAge, ServiceAgeDays: serviceAge, RestartAlertDays: nonNegativeConfig(cfg, "RESTART_ALERT_DAYS", 7),
		CurrentVersion: currentVersion, LatestVersion: latest, SelfUpdateAvailable: updateAvailable, SelfUpdateCheckErr: updateErr != nil,
	}), pending
}

func collectPackageFacts(cfg *config.Config, be string, now time.Time) (watchdog.Pending, []string, []watchdog.Issue) {
	healthEnabled := truthyLooseDefault(cfg.Get("CHECK_UPDATE_HEALTH"), true)
	switch be {
	case "apt":
		return collectAPTPackageFacts(healthEnabled, now, staleDays(cfg))
	case "dnf":
		return collectDNFPackageFacts(healthEnabled)
	default:
		return watchdog.Pending{}, nil, nil
	}
}

func collectAPTPackageFacts(healthEnabled bool, now time.Time, stale int) (watchdog.Pending, []string, []watchdog.Issue) {
	regular := sysexec.RunTimeout(patchCommandTimeout, "apt-get", "-s", "upgrade")
	pending := watchdog.CollectPending("apt", regular.Stdout)
	var blocked []string
	var issues []watchdog.Issue
	if !healthEnabled {
		return pending, nil, nil
	}
	if regular.Code != 0 {
		issues = append(issues, watchdog.Issue{Code: "apt-simulation-failed", ZH: "APT 无法计算待安装安全更新", EN: "APT could not calculate pending security updates"})
	}
	held := sysexec.RunTimeout(patchCommandTimeout, "apt-mark", "showhold")
	ignoreHold := sysexec.RunTimeout(patchCommandTimeout, "apt-get", "-s", "--ignore-hold", "upgrade")
	if held.Code == 0 && ignoreHold.Code == 0 {
		blocked = watchdog.BlockedAPT(pending, watchdog.CollectPending("apt", ignoreHold.Stdout), held.Stdout)
	}

	aptConfig := sysexec.RunTimeout(patchCommandTimeout, "apt-config", "dump")
	if aptConfig.Code != 0 {
		issues = append(issues, watchdog.Issue{Code: "apt-config-unreadable", ZH: "无法读取 APT 有效配置", EN: "Could not read the effective APT configuration"})
	} else {
		aptDailyEnabled := sysexec.RunTimeout(patchCommandTimeout, "systemctl", "is-enabled", "apt-daily.timer").Code == 0
		issues = append(issues, watchdog.CheckAPTPolicy(aptConfig.Stdout, aptDailyEnabled)...)
	}
	dpkgAudit := sysexec.RunTimeout(patchCommandTimeout, "dpkg", "--audit")
	if dpkgAudit.Code != 0 || strings.TrimSpace(dpkgAudit.Stdout+dpkgAudit.Stderr) != "" {
		issues = append(issues, watchdog.Issue{Code: "dpkg-audit", ZH: "dpkg 报告未完成或损坏的软件包状态，请运行 dpkg --audit", EN: "dpkg reports incomplete or broken package state; run dpkg --audit"})
	}
	aptCheck := sysexec.RunTimeout(patchCommandTimeout, "apt-get", "check", "-qq")
	if aptCheck.Code != 0 {
		issues = append(issues, watchdog.Issue{Code: "apt-check", ZH: "APT 依赖一致性检查失败，请运行 apt-get check", EN: "APT dependency consistency check failed; run apt-get check"})
	}
	issues = append(issues, checkAPTRepository(now, stale)...)
	return pending, blocked, issues
}

func collectDNFPackageFacts(healthEnabled bool) (watchdog.Pending, []string, []watchdog.Issue) {
	regular := sysexec.RunTimeout(patchCommandTimeout, "dnf", "-q", "updateinfo", "list", "security")
	pending := watchdog.CollectPending("dnf", regular.Stdout)
	var blocked []string
	var issues []watchdog.Issue
	if !healthEnabled {
		return pending, nil, nil
	}
	if regular.Code != 0 {
		code, zh, en := "dnf-repository-failed", "DNF 无法读取安全更新元数据", "DNF could not read security-update metadata"
		if repositorySignatureError(regular.Stderr) {
			code, zh, en = "dnf-repository-signature", "DNF 软件源元数据签名或 TLS 校验失败", "DNF repository metadata signature or TLS verification failed"
		}
		issues = append(issues, watchdog.Issue{Code: code, ZH: zh, EN: en})
	}
	unrestricted := sysexec.RunTimeout(patchCommandTimeout, "dnf", "-q", "--disableplugin=versionlock", "--disableexcludes=all", "updateinfo", "list", "security")
	if unrestricted.Code == 0 {
		blocked = watchdog.BlockedDNF(pending, watchdog.CollectPending("dnf", unrestricted.Stdout))
	}
	content, err := os.ReadFile(dnfAutomaticConfigPath())
	if err != nil {
		issues = append(issues, watchdog.Issue{Code: "dnf-automatic-config", ZH: "无法读取 /etc/dnf/automatic.conf", EN: "Could not read /etc/dnf/automatic.conf"})
	} else {
		issues = append(issues, watchdog.CheckDNFPolicy(string(content))...)
	}
	dnfCheck := sysexec.RunTimeout(patchCommandTimeout, "dnf", "-q", "check")
	if dnfCheck.Code != 0 {
		issues = append(issues, watchdog.Issue{Code: "dnf-check", ZH: "DNF 软件包一致性检查失败，请运行 dnf check", EN: "DNF package consistency check failed; run dnf check"})
	}
	return pending, blocked, issues
}

func checkAPTRepository(now time.Time, stale int) []watchdog.Issue {
	var issues []watchdog.Issue
	show := sysexec.RunTimeout(patchCommandTimeout, "systemctl", "show", "apt-daily.service", "-p", "Result", "--value")
	result := strings.TrimRight(show.Stdout, "\n")
	if result != "" && result != "success" {
		journal := sysexec.RunTimeout(patchCommandTimeout, "journalctl", "-u", "apt-daily.service", "-n", "100", "--no-pager", "-o", "cat")
		if repositorySignatureError(journal.Stdout + journal.Stderr) {
			issues = append(issues, watchdog.Issue{Code: "apt-repository-signature", ZH: "APT 软件源元数据签名、有效期或 TLS 校验失败", EN: "APT repository metadata signature, expiry, or TLS verification failed"})
		} else {
			issues = append(issues, watchdog.Issue{Code: "apt-daily-failed", ZH: "上次 APT 软件源刷新失败（apt-daily.service）", EN: "The last APT metadata refresh failed (apt-daily.service)"})
		}
	}
	return append(issues, inspectAPTMetadata(aptListsPath(), now, stale)...)
}

func inspectAPTMetadata(dir string, now time.Time, stale int) []watchdog.Issue {
	paths, _ := filepath.Glob(filepath.Join(dir, "*InRelease"))
	if len(paths) == 0 {
		return []watchdog.Issue{{Code: "apt-metadata-missing", ZH: "未发现已验证的 APT InRelease 元数据", EN: "No verified APT InRelease metadata was found"}}
	}
	latestSecurity := time.Time{}
	hasSecurity, expired := false, false
	for _, path := range paths {
		name := strings.ToLower(filepath.Base(path))
		isSecurity := strings.Contains(name, "security") || strings.Contains(name, "esm")
		if isSecurity {
			hasSecurity = true
			if info, err := os.Stat(path); err == nil && info.ModTime().After(latestSecurity) {
				latestSecurity = info.ModTime()
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(b) > 256*1024 {
			b = b[:256*1024]
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.ToLower(line), "valid-until:") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if deadline, err := mail.ParseDate(strings.TrimSpace(parts[1])); err == nil && now.After(deadline) {
					expired = true
				}
			}
			break
		}
	}
	var issues []watchdog.Issue
	if !hasSecurity {
		issues = append(issues, watchdog.Issue{Code: "apt-security-metadata-missing", ZH: "未发现安全更新源的 InRelease 元数据", EN: "No InRelease metadata was found for a security-update source"})
	}
	if expired {
		issues = append(issues, watchdog.Issue{Code: "apt-metadata-expired", ZH: "APT 软件源元数据已过有效期", EN: "APT repository metadata has expired"})
	}
	if stale > 0 && !latestSecurity.IsZero() && now.Sub(latestSecurity) > time.Duration(stale)*24*time.Hour {
		issues = append(issues, watchdog.Issue{Code: "apt-metadata-stale", ZH: fmt.Sprintf("APT 软件源元数据已超过 %d 天未刷新", stale), EN: fmt.Sprintf("APT repository metadata has not been refreshed for more than %d days", stale)})
	}
	return issues
}

func collectSelfUpdate(cfg *config.Config, current string, store statefile.Store, opts patchCollectOptions) (latest string, available bool, checkErr, stateErr error) {
	if opts.SkipSelfUpdate || !truthyLooseDefault(cfg.Get("CHECK_SELF_UPDATE"), true) || current == "" {
		return "", false, nil, nil
	}
	now := opts.Now.Unix()
	interval := positiveConfig(cfg, "SELF_UPDATE_CHECK_DAYS", 7)
	checked, err := store.ReadInt("self-update.checked_at")
	if err != nil {
		stateErr = err
	}
	latest, err = store.ReadString("self-update.latest")
	if err != nil && stateErr == nil {
		stateErr = err
	}
	due := opts.ForceSelfUpdate || checked <= 0 || checked > now || now-checked >= int64(interval)*86400
	if due {
		latest, checkErr = opts.LatestRelease(httpx.New(20*time.Second), Repo)
		if checkErr == nil && opts.PersistState {
			if err := store.WriteString("self-update.latest", latest); err != nil {
				stateErr = err
			} else if err := store.WriteInt("self-update.checked_at", now); err != nil {
				stateErr = err
			}
		}
	}
	return latest, version.IsNewer(current, latest), checkErr, stateErr
}

func trackedAgeDays(store statefile.Store, name string, active bool, now int64, persist bool) (int, error) {
	first, err := store.Track(name, active, now, persist)
	if err != nil || first <= 0 || first > now {
		return 0, err
	}
	return int((now - first) / 86400), nil
}

func stateIssue() watchdog.Issue {
	return watchdog.Issue{Code: "patch-state-write", ZH: "无法持久化补丁状态时长，请检查 /var/lib/security-update-notify", EN: "Could not persist patch-state age; inspect /var/lib/security-update-notify"}
}

func dedupeIssues(in []watchdog.Issue) []watchdog.Issue {
	seen := map[string]bool{}
	out := make([]watchdog.Issue, 0, len(in))
	for _, issue := range in {
		if issue.Code == "" || seen[issue.Code] {
			continue
		}
		seen[issue.Code] = true
		out = append(out, issue)
	}
	return out
}

func repositorySignatureError(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{"no_pubkey", "expkeysig", "badsig", "not signed", "signature", "valid-until", "release file expired", "certificate verification", "tls"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func nonNegativeConfig(cfg *config.Config, key string, dflt int) int {
	v := cfg.Get(key)
	if v == "" {
		return dflt
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return dflt
	}
	return n
}

func positiveConfig(cfg *config.Config, key string, dflt int) int {
	n := nonNegativeConfig(cfg, key, dflt)
	if n < 1 {
		return dflt
	}
	return n
}

func aptListsPath() string {
	return envOr("SECURITY_UPDATE_NOTIFY_APT_LISTS_DIR", "/var/lib/apt/lists")
}

func dnfAutomaticConfigPath() string {
	return envOr("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", "/etc/dnf/automatic.conf")
}
