package run

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/delivery"
	"github.com/xxvcc/security-update-notify/internal/dist"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/notify"
	"github.com/xxvcc/security-update-notify/internal/version"
)

// Repo 是发布仓库（与运行时 REPO 一致）。
const Repo = "xxvcc/security-update-notify"

// say 按语言输出一行（Go 版的 say 助手）。
func say(w io.Writer, lang i18n.Lang, zh, en string) {
	fmt.Fprintln(w, lang.Pick(zh, en))
}

// CheckUpgrade 复刻 run_check_upgrade：打印当前版本/仓库/最新版本，并给出可升级/已最新/本地更高。
// 仅在获取最新版本失败时返回 1，其余返回 0（含“已最新”“本地更高”）。
func CheckUpgrade(ver string, lang i18n.Lang) int {
	out := os.Stdout
	say(out, lang, "当前版本: "+ver, "Current version: "+ver)
	say(out, lang, "仓库: "+Repo, "Repository: "+Repo)
	latest, err := dist.LatestRelease(httpx.New(20*time.Second), Repo)
	if err != nil {
		say(os.Stderr, lang, "无法检查最新版本", "Failed to check latest version")
		return 1
	}
	say(out, lang, "最新版本: "+latest, "Latest version: "+latest)
	if latest == ver {
		say(out, lang, "已经是最新版本", "Already up to date")
		return 0
	}
	if version.IsNewer(ver, latest) {
		say(out, lang, "可升级: "+ver+" -> "+latest, "Upgrade available: "+ver+" -> "+latest)
		return 0
	}
	say(out, lang, "本地版本高于 latest release", "Local version is newer than latest release")
	return 0
}

// NotifyUpgradeEvent 复刻 --notify-upgrade-event：仅当 NOTIFY_UPGRADE=1 时发送升级成功通知。
// 升级已经完成，因此通知显式采用 best-effort 语义并始终返回 0，避免部分双发失败后
// 外部重试整个命令、重复已经成功的渠道。
func NotifyUpgradeEvent(cfg *config.Config, ver, from, to string) int {
	if from == "" {
		from = "unknown"
	}
	if to == "" {
		to = ver
	}
	if cfg.Get("NOTIFY_UPGRADE") != "1" {
		return 0
	}
	lang := i18n.NormalizeNotify(orDefault(cfg.Get("NOTIFY_LANG"), "zh"))
	includeIP, publicIP := resolvePublicIP(cfg)
	upgradeMessage := notify.UpgradeMessage{
		Lang:            lang,
		Host:            hostLabel(cfg),
		IncludePublicIP: includeIP,
		PublicIP:        publicIP,
		From:            from,
		To:              to,
		Now:             time.Now().Format("2006-01-02 15:04:05 MST"),
	}
	msg := delivery.Message{
		Text:       notify.RenderUpgrade(upgradeMessage),
		FeishuCard: notify.RenderFeishuUpgradeCard(upgradeMessage),
	}
	channels, err := configuredChannels(cfg)
	if err != nil {
		return 0
	}
	for _, name := range channels {
		sender, err := senderFor(cfg, name)
		if err != nil {
			continue
		}
		_ = sender.Send(context.Background(), msg)
	}
	return 0
}
