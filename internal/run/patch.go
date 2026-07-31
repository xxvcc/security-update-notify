package run

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/dist"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/statefile"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/systemd"
	"github.com/xxvcc/security-update-notify/internal/version"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

const (
	patchCommandTimeout      = 60 * time.Second
	maxAutomaticConfigBytes  = 1 << 20
	maxAPTMetadataParseBytes = 256 << 10
)

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
	pending, pendingObservation, blocked, issues := collectPackageFacts(cfg, be, opts.Now)
	if restart.ProbeIssue != "" {
		issues = append(issues, restartProbeIssue(restart.ProbeIssue))
	}
	store := statefile.Store{Dir: stateDirPath()}
	now := opts.Now.Unix()

	pendingAge, err := trackedAgeDays(store, "pending-security.first_seen", pendingObservation, now, opts.PersistState)
	if err != nil {
		issues = append(issues, stateIssue())
	}
	rebootAge, err := trackedAgeDays(store, "reboot-required.first_seen", observationFor(restart.RebootRequired, restart.ProbeIssue == ""), now, opts.PersistState)
	if err != nil {
		issues = append(issues, stateIssue())
	}
	serviceAge, err := trackedAgeDays(store, "service-restart.first_seen", observationFor(restart.RestartAttention, restart.ProbeIssue == ""), now, opts.PersistState)
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

func collectPackageFacts(cfg *config.Config, be string, now time.Time) (watchdog.Pending, statefile.Observation, []string, []watchdog.Issue) {
	healthEnabled := truthyLooseDefault(cfg.Get("CHECK_UPDATE_HEALTH"), true)
	switch be {
	case "apt":
		return collectAPTPackageFactsObserved(healthEnabled, now, staleDays(cfg))
	case "dnf":
		return collectDNFPackageFactsObserved(healthEnabled)
	default:
		return watchdog.Pending{}, statefile.ObservationUnknown, nil, nil
	}
}

func collectAPTPackageFacts(healthEnabled bool, now time.Time, stale int) (watchdog.Pending, []string, []watchdog.Issue) {
	pending, _, blocked, issues := collectAPTPackageFactsObserved(healthEnabled, now, stale)
	return pending, blocked, issues
}

func collectAPTPackageFactsObserved(healthEnabled bool, now time.Time, stale int) (watchdog.Pending, statefile.Observation, []string, []watchdog.Issue) {
	regular := sysexec.RunTimeout(patchCommandTimeout, "apt-get", "-s", "upgrade")
	regularUsable := regular.Code == 0 && !commandOutputIncomplete(regular)
	pending := watchdog.Pending{}
	regularParsed := false
	if regularUsable {
		pending, regularParsed = watchdog.CollectAPTPending(regular.Stdout)
	}
	pendingObservation := observationFor(pending.Count > 0, regularUsable && regularParsed)
	var blocked []string
	var issues []watchdog.Issue
	if !healthEnabled {
		return pending, pendingObservation, nil, nil
	}
	if !regularUsable {
		issues = append(issues, watchdog.Issue{Code: "apt-simulation-failed", ZH: "APT 无法计算待安装安全更新", EN: "APT could not calculate pending security updates"})
	} else if !regularParsed {
		issues = append(issues, watchdog.Issue{Code: "apt-simulation-output-invalid", ZH: "APT 返回了无法完整解析的更新模拟结果", EN: "APT returned update-simulation output that could not be fully parsed"})
	}
	held := sysexec.RunTimeout(patchCommandTimeout, "apt-mark", "showhold")
	ignoreHold := sysexec.RunTimeout(patchCommandTimeout, "apt-get", "-s", "--ignore-hold", "upgrade")
	if held.Code == 0 && ignoreHold.Code == 0 && !commandOutputIncomplete(held) && !commandOutputIncomplete(ignoreHold) {
		ignorePending, ignoreParsed := watchdog.CollectAPTPending(ignoreHold.Stdout)
		if regularUsable && regularParsed && ignoreParsed {
			blocked = watchdog.BlockedAPT(pending, ignorePending, held.Stdout)
		} else if !ignoreParsed {
			issues = append(issues, watchdog.Issue{Code: "apt-blocked-query-failed", ZH: "APT 无法检查被 hold 阻塞的安全更新", EN: "APT could not check security updates blocked by package holds"})
		}
	} else {
		issues = append(issues, watchdog.Issue{Code: "apt-blocked-query-failed", ZH: "APT 无法检查被 hold 阻塞的安全更新", EN: "APT could not check security updates blocked by package holds"})
	}

	aptConfig := sysexec.RunTimeout(patchCommandTimeout, "apt-config", "dump")
	if aptConfig.Code != 0 || commandOutputIncomplete(aptConfig) {
		issues = append(issues, watchdog.Issue{Code: "apt-config-unreadable", ZH: "无法读取 APT 有效配置", EN: "Could not read the effective APT configuration"})
	} else {
		aptDailyEnabled := systemd.IsEnabled("apt-daily.timer")
		issues = append(issues, watchdog.CheckAPTPolicy(aptConfig.Stdout, aptDailyEnabled)...)
	}
	dpkgAudit := sysexec.RunTimeout(patchCommandTimeout, "dpkg", "--audit")
	if dpkgAudit.Code != 0 || commandOutputIncomplete(dpkgAudit) || strings.TrimSpace(dpkgAudit.Stdout+dpkgAudit.Stderr) != "" {
		issues = append(issues, watchdog.Issue{Code: "dpkg-audit", ZH: "dpkg 报告未完成或损坏的软件包状态，请运行 dpkg --audit", EN: "dpkg reports incomplete or broken package state; run dpkg --audit"})
	}
	aptCheck := sysexec.RunTimeout(patchCommandTimeout, "apt-get", "check", "-qq")
	if aptCheck.Code != 0 || commandOutputIncomplete(aptCheck) {
		issues = append(issues, watchdog.Issue{Code: "apt-check", ZH: "APT 依赖一致性检查失败，请运行 apt-get check", EN: "APT dependency consistency check failed; run apt-get check"})
	}
	issues = append(issues, checkAPTRepository(now, stale)...)
	return pending, pendingObservation, blocked, issues
}

func collectDNFPackageFacts(healthEnabled bool) (watchdog.Pending, []string, []watchdog.Issue) {
	pending, _, blocked, issues := collectDNFPackageFactsObserved(healthEnabled)
	return pending, blocked, issues
}

func collectDNFPackageFactsObserved(healthEnabled bool) (watchdog.Pending, statefile.Observation, []string, []watchdog.Issue) {
	runtime := detectDNFRuntime(patchCommandTimeout)
	if !runtime.GenerationKnown {
		if !healthEnabled {
			return watchdog.Pending{}, statefile.ObservationUnknown, nil, nil
		}
		return watchdog.Pending{}, statefile.ObservationUnknown, nil, []watchdog.Issue{{
			Code: "dnf-generation-probe-failed",
			ZH:   "无法可靠识别已安装的 DNF 代际，已跳过安全更新查询",
			EN:   "Could not reliably identify the installed DNF generation; security-update queries were skipped",
		}}
	}
	if runtime.isDNF5() {
		return collectDNF5PackageFactsObserved(healthEnabled, runtime)
	}
	regular := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, runtime.advisoryArgs(false)...)
	regularIssue, regularFailed := dnfRepositoryIssue(regular, regular.Code == 0)
	pending := watchdog.Pending{}
	if !regularFailed {
		pending = watchdog.CollectPending("dnf", regular.Stdout)
	}
	pendingObservation := observationFor(pending.Count > 0, !regularFailed)
	var blocked []string
	var issues []watchdog.Issue
	if !healthEnabled {
		return pending, pendingObservation, nil, nil
	}
	if regularFailed {
		issues = append(issues, regularIssue)
	}
	unrestricted := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, runtime.advisoryArgs(true)...)
	if issue, failed := dnfRepositoryIssue(unrestricted, unrestricted.Code == 0); failed {
		issues = append(issues, issue, dnfBlockedQueryIssue())
	} else if !regularFailed {
		blocked = watchdog.BlockedDNF(pending, watchdog.CollectPending("dnf", unrestricted.Stdout))
	}
	content, err := readBoundedFile(dnfAutomaticConfigPath(), maxAutomaticConfigBytes)
	if err != nil {
		issues = append(issues, watchdog.Issue{Code: "dnf-automatic-config", ZH: "无法读取 /etc/dnf/automatic.conf", EN: "Could not read /etc/dnf/automatic.conf"})
	} else {
		issues = append(issues, watchdog.CheckDNFPolicy(string(content))...)
	}
	dnfCheck := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, "-q", "check")
	if dnfCheck.Code != 0 || commandOutputIncomplete(dnfCheck) {
		issues = append(issues, watchdog.Issue{Code: "dnf-check", ZH: "DNF 软件包一致性检查失败，请运行 dnf check", EN: "DNF package consistency check failed; run dnf check"})
	}
	return pending, pendingObservation, blocked, issues
}

func collectDNF5PackageFactsObserved(healthEnabled bool, runtime dnfRuntime) (watchdog.Pending, statefile.Observation, []string, []watchdog.Issue) {
	regular := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, runtime.advisoryArgs(false)...)
	transaction := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, runtime.checkUpgradeArgs(false)...)
	transactionStatusOK := transaction.Code == 0 || transaction.Code == 100
	regularIssue, regularFailed := dnfStructuredRepositoryIssue(regular, regular.Code == 0)
	transactionIssue, transactionFailed := dnfRepositoryIssue(transaction, transactionStatusOK)
	transactionUpgrades, transactionParseErr := backend.ParseDNF5CheckUpgrades(transaction.Stdout)
	transactionUsable := !transactionFailed && transactionParseErr == nil && ((transaction.Code == 0 && len(transactionUpgrades) == 0) ||
		(transaction.Code == 100 && len(transactionUpgrades) > 0))

	normalized := ""
	var parseErr error
	if !regularFailed {
		if transactionUsable {
			normalized, parseErr = backend.NormalizeDNF5Pending(regular.Stdout, transaction.Stdout)
			if parseErr != nil {
				// A valid advisory response is stronger evidence than a failed
				// advisory/transaction join. Conservatively over-report the
				// advisories instead of turning parser drift into a false green.
				normalized, parseErr = backend.NormalizeDNF5Advisories(regular.Stdout)
			}
		} else {
			normalized, parseErr = backend.NormalizeDNF5Advisories(regular.Stdout)
		}
	}
	pending := watchdog.CollectPending("dnf", normalized)
	pendingObservation := observationFor(pending.Count > 0, !regularFailed && parseErr == nil)
	if !healthEnabled {
		return pending, pendingObservation, nil, nil
	}

	var blocked []string
	var issues []watchdog.Issue
	if regularFailed {
		issues = append(issues, regularIssue)
	} else if parseErr != nil {
		issues = append(issues, watchdog.Issue{Code: "dnf-advisory-output-invalid", ZH: "DNF5 返回了无法解析的安全公告数据", EN: "DNF5 returned unparseable security-advisory data"})
	}
	if transactionFailed {
		issues = append(issues, transactionIssue)
	}
	if !transactionStatusOK {
		issues = append(issues, watchdog.Issue{Code: "dnf-security-transaction-failed", ZH: "DNF5 无法计算实际可安装的安全更新", EN: "DNF5 could not calculate transaction-eligible security updates"})
	} else if !transactionUsable {
		issues = append(issues, watchdog.Issue{Code: "dnf-security-transaction-invalid", ZH: "DNF5 安全更新事务输出无法解析", EN: "DNF5 security-update transaction output could not be parsed"})
	}

	if transactionUsable {
		unrestricted := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, runtime.advisoryArgs(true)...)
		unrestrictedTransaction := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, runtime.checkUpgradeArgs(true)...)
		unrestrictedTransactionStatusOK := unrestrictedTransaction.Code == 0 || unrestrictedTransaction.Code == 100
		unrestrictedUpgrades, unrestrictedParseErr := backend.ParseDNF5CheckUpgrades(unrestrictedTransaction.Stdout)
		unrestrictedTransactionUsable := unrestrictedParseErr == nil &&
			((unrestrictedTransaction.Code == 0 && len(unrestrictedUpgrades) == 0) ||
				(unrestrictedTransaction.Code == 100 && len(unrestrictedUpgrades) > 0))
		unrestrictedFailed := false
		if issue, failed := dnfStructuredRepositoryIssue(unrestricted, unrestricted.Code == 0); failed {
			issues = append(issues, issue, dnfBlockedQueryIssue())
			unrestrictedFailed = true
		}
		if issue, failed := dnfRepositoryIssue(unrestrictedTransaction, unrestrictedTransactionStatusOK); failed {
			issues = append(issues, issue, dnfBlockedQueryIssue())
			unrestrictedFailed = true
		} else if !unrestrictedTransactionUsable {
			issues = append(issues, dnfBlockedQueryIssue())
			unrestrictedFailed = true
		}
		if !unrestrictedFailed {
			var err error
			blocked, err = backend.BlockedDNF5(unrestricted.Stdout, transaction.Stdout, unrestrictedTransaction.Stdout)
			if err != nil {
				issues = append(issues, watchdog.Issue{Code: "dnf-advisory-output-invalid", ZH: "DNF5 返回了无法解析的安全公告数据", EN: "DNF5 returned unparseable security-advisory data"})
			}
		}
	}
	content, err := readBoundedFile(dnfAutomaticConfigPath(), maxAutomaticConfigBytes)
	if err != nil {
		issues = append(issues, watchdog.Issue{Code: "dnf-automatic-config", ZH: "无法读取 /etc/dnf/automatic.conf", EN: "Could not read /etc/dnf/automatic.conf"})
	} else {
		issues = append(issues, watchdog.CheckDNFPolicy(string(content))...)
	}
	dnfCheck := sysexec.RunTimeout(patchCommandTimeout, runtime.Command, "-q", "check")
	if dnfCheck.Code != 0 || commandOutputIncomplete(dnfCheck) {
		issues = append(issues, watchdog.Issue{Code: "dnf-check", ZH: "DNF 软件包一致性检查失败，请运行 dnf check", EN: "DNF package consistency check failed; run dnf check"})
	}
	return pending, pendingObservation, blocked, issues
}

func checkAPTRepository(now time.Time, stale int) []watchdog.Issue {
	var issues []watchdog.Issue
	show := sysexec.RunTimeout(patchCommandTimeout, "systemctl", "show", "apt-daily.service", "-p", "Result", "--value")
	result := strings.TrimSpace(show.Stdout)
	if show.Code != 0 || commandOutputIncomplete(show) || strings.TrimSpace(show.Stderr) != "" ||
		result == "" || len(strings.Fields(result)) != 1 {
		issues = append(issues, watchdog.Issue{Code: "apt-daily-status-unreadable", ZH: "无法读取上次 APT 软件源刷新结果（apt-daily.service）", EN: "Could not read the last APT metadata-refresh result (apt-daily.service)"})
		return append(issues, inspectAPTMetadata(aptListsPath(), now, stale)...)
	}
	if result != "success" {
		journal := sysexec.RunTimeout(patchCommandTimeout, "journalctl", "-u", "apt-daily.service", "-n", "100", "--no-pager", "-o", "cat")
		if journal.Code == 0 && !commandOutputIncomplete(journal) && aptRepositorySignatureError(journal.Stdout+journal.Stderr) {
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
	hasSecurity, expired, unreadable := false, false, false
	for _, path := range paths {
		name := strings.ToLower(filepath.Base(path))
		isSecurity := strings.Contains(name, "security") || strings.Contains(name, "esm")
		b, info, err := readFilePrefixChecked(path, maxAPTMetadataParseBytes)
		if err != nil || b == "" {
			unreadable = true
			continue
		}
		if isSecurity {
			hasSecurity = true
			if info.ModTime().After(latestSecurity) {
				latestSecurity = info.ModTime()
			}
		}
		for _, line := range strings.Split(b, "\n") {
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
	if unreadable {
		issues = append(issues, watchdog.Issue{Code: "apt-metadata-unreadable", ZH: "一个或多个 APT InRelease 元数据文件不可安全读取", EN: "One or more APT InRelease metadata files could not be read safely"})
	}
	if !hasSecurity {
		issues = append(issues, watchdog.Issue{Code: "apt-security-metadata-missing", ZH: "未发现安全更新源的 InRelease 元数据", EN: "No InRelease metadata was found for a security-update source"})
	}
	if expired {
		issues = append(issues, watchdog.Issue{Code: "apt-metadata-expired", ZH: "APT 软件源元数据已过有效期", EN: "APT repository metadata has expired"})
	}
	if stale > 0 && !latestSecurity.IsZero() && durationExceedsDays(now.Sub(latestSecurity), stale) {
		issues = append(issues, watchdog.Issue{Code: "apt-metadata-stale", ZH: fmt.Sprintf("APT 软件源元数据已超过 %d 天未刷新", stale), EN: fmt.Sprintf("APT repository metadata has not been refreshed for more than %d days", stale)})
	}
	return issues
}

func collectSelfUpdate(cfg *config.Config, current string, store statefile.Store, opts patchCollectOptions) (latest string, available bool, checkErr, stateErr error) {
	if opts.SkipSelfUpdate || !truthyLooseDefault(cfg.Get("CHECK_SELF_UPDATE"), true) || current == "" {
		return "", false, nil, nil
	}
	if !validUpgradeLocalVersion(current) {
		return "", false, fmt.Errorf("current version is invalid"), nil
	}
	now := opts.Now.Unix()
	interval := positiveConfig(cfg, "SELF_UPDATE_CHECK_DAYS", 7)
	recordStateError := func(err error) {
		if err != nil && stateErr == nil {
			stateErr = err
		}
	}
	checked, checkedErr := store.ReadInt("self-update.checked_at")
	recordStateError(checkedErr)
	latest, latestErr := store.ReadString("self-update.latest")
	recordStateError(latestErr)

	cacheInvalid := checkedErr != nil || latestErr != nil
	if checkedErr == nil && latestErr == nil {
		switch {
		case checked > 0 && latest == "":
			cacheInvalid = true
			recordStateError(fmt.Errorf("self-update cache has a timestamp without a version"))
		case checked <= 0 && latest != "":
			cacheInvalid = true
			recordStateError(fmt.Errorf("self-update cache has a version without a timestamp"))
		case latest != "":
			if !validUpgradeLocalVersion(latest) {
				cacheInvalid = true
				recordStateError(fmt.Errorf("self-update cache has an invalid version"))
			}
		}
	}

	due := opts.ForceSelfUpdate || cacheInvalid || checked <= 0 || checked > now || elapsedWholeDays(now, checked) >= int64(interval)
	if due {
		latest, checkErr = opts.LatestRelease(httpx.New(20*time.Second), Repo)
		if checkErr == nil && !validUpgradeLocalVersion(latest) {
			latest = ""
			checkErr = fmt.Errorf("latest release returned an invalid version")
		}
		if checkErr == nil && opts.PersistState {
			if err := store.WriteString("self-update.latest", latest); err != nil {
				recordStateError(err)
			} else if err := store.WriteInt("self-update.checked_at", now); err != nil {
				recordStateError(err)
			}
		}
	}
	if checkErr != nil || latest == "" {
		return latest, false, checkErr, stateErr
	}
	comparison, err := version.Compare(latest, current)
	if err != nil {
		return latest, false, fmt.Errorf("compare current and latest versions: %w", err), stateErr
	}
	return latest, comparison > 0, nil, stateErr
}

func observationFor(active, known bool) statefile.Observation {
	if active {
		return statefile.ObservationPresent
	}
	if known {
		return statefile.ObservationAbsent
	}
	return statefile.ObservationUnknown
}

func trackedAgeDays(store statefile.Store, name string, observation statefile.Observation, now int64, persist bool) (int, error) {
	first, err := store.Observe(name, observation, now, persist)
	if err != nil || first <= 0 || first > now {
		return 0, err
	}
	days := (now - first) / 86400
	maxInt := int(^uint(0) >> 1)
	if days > int64(maxInt) {
		return maxInt, nil
	}
	return int(days), nil
}

func stateIssue() watchdog.Issue {
	return watchdog.Issue{Code: "patch-state-write", ZH: "无法安全读取或持久化补丁状态，请检查 /var/lib/security-update-notify", EN: "Could not safely read or persist patch state; inspect /var/lib/security-update-notify"}
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

func aptRepositorySignatureError(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{"no_pubkey", "expkeysig", "badsig", "not signed", "signature", "valid-until", "release file expired", "certificate verification", "tls"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func repositoryOperationalError(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"failed to download metadata", "errors during downloading metadata", "cannot download repomd",
		"ignoring repositories", "skipping repository", "all mirrors were tried", "curl error",
		"cannot prepare internal mirrorlist", "failed to synchronize cache", "repomd.xml",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func dnfRepositoryIssue(result sysexec.Result, statusOK bool) (watchdog.Issue, bool) {
	return classifyDNFRepositoryIssue(result, statusOK, false)
}

func dnfStructuredRepositoryIssue(result sysexec.Result, statusOK bool) (watchdog.Issue, bool) {
	return classifyDNFRepositoryIssue(result, statusOK, true)
}

func classifyDNFRepositoryIssue(result sysexec.Result, statusOK, structuredStdout bool) (watchdog.Issue, bool) {
	output := result.Stderr
	// A syntactically valid JSON response is application data. Package and
	// advisory names inside it must never be interpreted as repository errors.
	if !structuredStdout || !json.Valid([]byte(strings.TrimSpace(result.Stdout))) {
		output = result.Stdout + result.Stderr
	}
	if dnfRepositorySignatureError(output) {
		return watchdog.Issue{
			Code: "dnf-repository-signature",
			ZH:   "DNF 软件源元数据签名或 TLS 校验失败",
			EN:   "DNF repository metadata signature or TLS verification failed",
		}, true
	}
	if !statusOK || commandOutputIncomplete(result) || repositoryOperationalError(output) {
		return watchdog.Issue{
			Code: "dnf-repository-failed",
			ZH:   "DNF 无法可靠读取安全更新元数据",
			EN:   "DNF could not reliably read security-update metadata",
		}, true
	}
	return watchdog.Issue{}, false
}

func dnfRepositorySignatureError(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"no_pubkey", "expkeysig", "badsig", "not signed", "gpg check failed",
		"gpg signature verification failed", "signature verification failed",
		"signature could not be verified", "failed to verify signature",
		"certificate verification failed", "certificate verify failed",
		"ssl certificate problem", "certificate issuer has been marked as not trusted",
		"curl error (60)", "tls certificate verification failed", "tls handshake failed",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func commandOutputIncomplete(result sysexec.Result) bool {
	return result.Err != nil || result.StdoutTruncated || result.StderrTruncated
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if info.Size() > limit {
		return nil, io.ErrUnexpectedEOF
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

func durationExceedsDays(elapsed time.Duration, days int) bool {
	if elapsed <= 0 || days <= 0 {
		return false
	}
	const day = 24 * time.Hour
	if int64(days) > math.MaxInt64/int64(day) {
		return false
	}
	return elapsed > time.Duration(days)*day
}

func elapsedWholeDays(now, then int64) int64 {
	if then <= 0 || then > now {
		return 0
	}
	return (now - then) / 86400
}

func dnfBlockedQueryIssue() watchdog.Issue {
	return watchdog.Issue{
		Code: "dnf-blocked-query-failed",
		ZH:   "DNF 无法检查被 versionlock 或 exclude 阻塞的安全更新",
		EN:   "DNF could not check security updates blocked by versionlock or excludes",
	}
}

func restartProbeIssue(code string) watchdog.Issue {
	switch code {
	case "apt-restart-probe-failed":
		return watchdog.Issue{
			Code: code,
			ZH:   "APT 无法可靠检查需要重启的系统或服务",
			EN:   "APT could not reliably check whether the system or services need restarting",
		}
	case "dnf-restart-probe-failed":
		return watchdog.Issue{
			Code: code,
			ZH:   "DNF 无法可靠检查需要重启的系统或服务",
			EN:   "DNF could not reliably check whether the system or services need restarting",
		}
	default:
		return watchdog.Issue{
			Code: "restart-probe-failed",
			ZH:   "无法可靠检查更新后的重启需求",
			EN:   "Could not reliably check restart requirements after updates",
		}
	}
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

func aptPeriodicConfigPath() string {
	return envOr("SECURITY_UPDATE_NOTIFY_APT_PERIODIC_CONF", "/etc/apt/apt.conf.d/20auto-upgrades")
}

func dnfAutomaticConfigPath() string {
	return envOr("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", "/etc/dnf/automatic.conf")
}
