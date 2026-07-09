package run

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/dedup"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/lock"
	"github.com/xxvcc/security-update-notify/internal/telegram"
)

// telegramBaseURLEnv 是仅供测试/差分用的 Telegram API 基址覆盖（生产恒为官方地址）。
const telegramBaseURLEnv = "SECURITY_UPDATE_NOTIFY_TELEGRAM_BASE_URL"

// DryRunFlags 扩展 Flags：仅计算并打印 hash 与将发送的正文，不加锁、不发送、不写状态、不记日志。
// 用于人工观察与 bash↔Go 差分测试。
type DryRunFlags struct {
	Flags
	DryRun bool
}

// Execute 跑完整的 检查→通知→去重→落盘 流程，返回进程退出码。复刻运行时末尾的决策、日志事件与退出码：
// 0=成功/无关注/静默OK/去重抑制/锁竞争；1=发送失败；2=缺 token/chat。
func Execute(cfg *config.Config, f DryRunFlags) int {
	if f.DryRun {
		out := Assemble(Collect(cfg, f.Flags))
		fmt.Println("HASH\t" + out.Hash())
		if out.Send {
			fmt.Print(out.Message)
		}
		return 0
	}

	// 单实例锁（与 Bash 一样尽早获取，抢不到说明已有实例在跑，静默退出 0）。
	if err := os.MkdirAll(stateDirPath(), 0o750); err == nil {
		_ = os.Chmod(stateDirPath(), 0o750)
	}
	release, acquired, err := lock.Acquire(lockFilePath())
	if err != nil {
		// 无法获取锁本身即视为失败，不再裸跑：否则与定时器运行并发时会重复告警、竞争状态文件
		// （复刻 Bash `flock -n 9 || exit 0` 不会静默继续无锁运行）。
		fmt.Fprintln(os.Stderr, "lock error: "+err.Error())
		return 1
	}
	if !acquired {
		return 0 // 已有实例在跑，静默退出
	}
	defer release()

	in := Collect(cfg, f.Flags)
	// 不支持的后端（既非 apt 也非 dnf，例如无法识别的发行版 -> auto=unknown）：复刻运行时的 exit 2。
	if in.Backend != "apt" && in.Backend != "dnf" {
		fmt.Fprintf(os.Stderr, "不支持的后端 / Unsupported backend: %s\n", in.Backend)
		return 2
	}
	out := Assemble(in)
	backend, host := in.Backend, in.Host

	if !out.Attention {
		logEvent(fmt.Sprintf("check ok backend=%s host=%s no_attention=1 pending_sec=%d", backend, host, in.Pending.Count))
		if !out.Send { // 无关注且未要求 OK 通知：静默
			logEvent(fmt.Sprintf("silent ok backend=%s host=%s", backend, host))
			return 0
		}
	} else {
		logEvent(fmt.Sprintf("alert backend=%s host=%s reboot=%s svc_attn=%s health=%s eol=%s pending_sec=%d",
			backend, host, b01(in.Restart.RebootRequired), b01(in.Restart.RestartAttention),
			b01(in.Health.Attention), b01(in.EOL.Attention), in.Pending.Count))
	}

	// 去重决策。
	store := dedup.NewStore(stateDirPath())
	lastHash, lastSent := store.ReadLast()
	now := time.Now().Unix()
	curHash := out.Hash()
	mode := orDefault(cfg.Get("DEDUP_MODE"), "daily")
	if !dedup.ShouldSend(f.NoDedupe, curHash, lastHash, lastSent, now, mode, dedupInterval(cfg)) {
		logEvent(fmt.Sprintf("dedup suppressed backend=%s host=%s mode=%s hash=%s", backend, host, mode, curHash))
		return 0
	}

	token := cfg.Get("TELEGRAM_BOT_TOKEN")
	chat := cfg.Get("TELEGRAM_CHAT_ID")
	if token == "" || chat == "" {
		fmt.Fprintln(os.Stderr, "Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
		return 2
	}

	client := &telegram.Client{HTTP: httpx.New(30 * time.Second), BaseURL: os.Getenv(telegramBaseURLEnv)}
	if err := client.SendMessage(context.Background(), token, chat, out.Message); err != nil {
		logEvent(fmt.Sprintf("telegram failed backend=%s host=%s", backend, host))
		fmt.Fprintln(os.Stderr, "Telegram notification failed: "+err.Error())
		return 1
	}
	_ = store.Write(curHash, now)
	logEvent(fmt.Sprintf("telegram sent backend=%s host=%s reboot_required=%s restart_attention=%s hash=%s",
		backend, host, b01(in.Restart.RebootRequired), b01(in.Restart.RestartAttention), curHash))
	return 0
}

func dedupInterval(cfg *config.Config) int {
	n, err := strconv.Atoi(cfg.Get("DEDUP_INTERVAL_DAYS"))
	if err != nil || n < 1 {
		return 3
	}
	return n
}
