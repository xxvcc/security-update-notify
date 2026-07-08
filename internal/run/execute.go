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

const (
	stateDir = "/var/lib/security-update-notify"
	lockFile = "/run/security-update-notify.lock"
)

// telegramBaseURLEnv 是仅供测试/差分用的 Telegram API 基址覆盖（生产恒为官方地址）。
const telegramBaseURLEnv = "SECURITY_UPDATE_NOTIFY_TELEGRAM_BASE_URL"

// DryRun 扩展 Flags：仅计算并打印 hash 与将发送的正文，不加锁、不发送、不写状态。用于人工观察与
// bash↔Go 差分测试。
type DryRunFlags struct {
	Flags
	DryRun bool
}

// Execute 跑完整的 检查→通知→去重→落盘 流程，返回进程退出码。复刻运行时末尾的决策与退出码语义：
// 0=成功/无关注/静默OK/去重抑制/锁竞争；1=发送失败；2=缺 token/chat。
func Execute(cfg *config.Config, f DryRunFlags) int {
	in := Collect(cfg, f.Flags)
	out := Assemble(in)

	if f.DryRun {
		fmt.Println("HASH\t" + out.Hash())
		if out.Send {
			fmt.Print(out.Message)
		}
		return 0
	}

	if !out.Send {
		return 0 // 无关注且未要求 OK 通知：静默
	}

	token := cfg.Get("TELEGRAM_BOT_TOKEN")
	chat := cfg.Get("TELEGRAM_CHAT_ID")
	if token == "" || chat == "" {
		fmt.Fprintln(os.Stderr, "Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
		return 2
	}

	// 单实例锁：抢不到说明已有实例在跑，静默退出 0。
	if err := os.MkdirAll(stateDir, 0o750); err == nil {
		_ = os.Chmod(stateDir, 0o750)
	}
	release, acquired, err := lock.Acquire(lockFile)
	if err == nil && !acquired {
		return 0
	}
	if release != nil {
		defer release()
	}

	store := dedup.NewStore(stateDir)
	lastHash, lastSent := store.ReadLast()
	now := time.Now().Unix()
	curHash := out.Hash()
	mode := orDefault(cfg.Get("DEDUP_MODE"), "daily")
	if !dedup.ShouldSend(f.NoDedupe, curHash, lastHash, lastSent, now, mode, dedupInterval(cfg)) {
		return 0 // 去重抑制
	}

	client := &telegram.Client{HTTP: httpx.New(30 * time.Second), BaseURL: os.Getenv(telegramBaseURLEnv)}
	if err := client.SendMessage(context.Background(), token, chat, out.Message); err != nil {
		fmt.Fprintln(os.Stderr, "Telegram notification failed: "+err.Error())
		return 1
	}
	_ = store.Write(curHash, now)
	return 0
}

func dedupInterval(cfg *config.Config) int {
	n, err := strconv.Atoi(cfg.Get("DEDUP_INTERVAL_DAYS"))
	if err != nil || n < 1 {
		return 3
	}
	return n
}
