package run

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/dedup"
	"github.com/xxvcc/security-update-notify/internal/delivery"
	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/lock"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
)

// DryRunFlags 扩展 Flags：仅计算并打印 hash 与将发送的正文，不加锁、不发送、不写状态、不记日志。
// 用于人工观察与 bash↔Go 差分测试。
type DryRunFlags struct {
	Flags
	DryRun      bool
	RequireLock bool
	LockWait    time.Duration
	LockHeld    bool
}

// AcquireExecutionLock applies the runtime's public lock contract. Default contention is a quiet success;
// an explicit wait timeout returns 75; lock filesystem or flock failures return 1.
func AcquireExecutionLock(require bool, wait time.Duration) (release func(), acquired bool, exitCode int) {
	var err error
	if require {
		release, acquired, err = lock.AcquireWait(lockFilePath(), wait)
	} else {
		release, acquired, err = lock.Acquire(lockFilePath())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lock error: "+err.Error())
		return nil, false, 1
	}
	if !acquired {
		if require {
			fmt.Fprintln(os.Stderr, "Timed out waiting for the security-update-notify lock")
			return nil, false, 75
		}
		return nil, false, 0
	}
	return release, true, 0
}

// Execute 跑完整的 检查→通知→去重→落盘 流程，返回进程退出码。复刻运行时末尾的决策、日志事件与退出码：
// 0=成功/无关注/静默OK/去重抑制/默认模式下的锁竞争；1=发送失败；2=配置错误；
// 75=显式 --wait-lock 超时（安装器据此拒绝把“未发送”误判为验证成功）。
func Execute(cfg *config.Config, f DryRunFlags) int {
	if f.DryRun {
		flags := f.Flags
		flags.NoStateWrites = true
		out := Assemble(Collect(cfg, flags))
		fmt.Print(renderDryRun(out))
		return 0
	}
	channels, err := configuredChannels(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid NOTIFY_CHANNELS: "+err.Error())
		return 2
	}

	// 单实例锁（与 Bash 一样尽早获取，抢不到说明已有实例在跑，静默退出 0）。
	if err := filetrust.EnsureDirectory(stateDirPath(), os.Geteuid()); err != nil {
		fmt.Fprintln(os.Stderr, "state directory error: "+err.Error())
		return 1
	}
	if !f.LockHeld {
		release, acquired, exitCode := AcquireExecutionLock(f.RequireLock, f.LockWait)
		if !acquired {
			return exitCode
		}
		defer release()
	}

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
		logEvent(alertLogLine(in))
	}

	message := delivery.Message{Text: out.Message, FeishuCard: out.FeishuCard}
	return deliverChannels(cfg, channels, message, out.Hash(), backend, host,
		in.Restart.RebootRequired, in.Restart.RestartAttention, f.NoDedupe, time.Now().Unix(), senderFor)
}

func renderDryRun(out Output) string {
	text := "HASH\t" + out.Hash() + "\n"
	if out.Send {
		text += textsafe.Multiline(out.Message)
	}
	return text
}

func alertLogLine(in Input) string {
	return fmt.Sprintf("alert backend=%s host=%s reboot=%s svc_attn=%s health=%s patch=%s update=%s eol=%s pending_sec=%d",
		in.Backend, in.Host, b01(in.Restart.RebootRequired), b01(in.Restart.RestartAttention),
		b01(in.Health.Attention), b01(in.Patch.RiskAttention), b01(in.Patch.UpdateAvailable),
		b01(in.EOL.Attention), in.Pending.Count)
}

type senderFactory func(*config.Config, string) (delivery.Sender, error)

func deliverChannels(cfg *config.Config, channels []string, message delivery.Message, curHash, backend, host string,
	rebootRequired, restartAttention, noDedupe bool, now int64, factory senderFactory,
) int {
	mode := orDefault(cfg.Get("DEDUP_MODE"), "daily")
	configFailed := false
	sendFailed := false
	type pendingDelivery struct {
		name   string
		store  *dedup.Store
		sender delivery.Sender
	}
	var pending []pendingDelivery
	for _, name := range channels {
		store := channelStore(name)
		lastHash, lastSent := store.ReadLast()
		if !dedup.ShouldSend(noDedupe, curHash, lastHash, lastSent, now, mode, dedupInterval(cfg)) {
			logEvent(fmt.Sprintf("dedup suppressed channel=%s backend=%s host=%s mode=%s hash=%s", name, backend, host, mode, curHash))
			continue
		}
		sender, err := factory(cfg, name)
		if err != nil {
			configFailed = true
			logEvent(fmt.Sprintf("%s failed backend=%s host=%s reason=config", name, backend, host))
			fmt.Fprintf(os.Stderr, "%s configuration failed: %v\n", channelLabel(name), err)
			continue
		}
		pending = append(pending, pendingDelivery{name: name, store: store, sender: sender})
	}
	for _, item := range pending {
		if err := item.sender.Send(context.Background(), message); err != nil {
			sendFailed = true
			logEvent(fmt.Sprintf("%s failed backend=%s host=%s", item.name, backend, host))
			fmt.Fprintf(os.Stderr, "%s notification failed: %v\n", channelLabel(item.name), err)
			continue
		}
		if err := item.store.Write(curHash, now); err != nil {
			sendFailed = true
			logEvent(fmt.Sprintf("%s state failed backend=%s host=%s", item.name, backend, host))
			fmt.Fprintf(os.Stderr, "%s notification was sent but delivery state could not be persisted: %v\n", channelLabel(item.name), err)
			continue
		}
		logEvent(fmt.Sprintf("%s sent backend=%s host=%s reboot_required=%s restart_attention=%s hash=%s",
			item.name, backend, host, b01(rebootRequired), b01(restartAttention), curHash))
	}
	if configFailed {
		return 2
	}
	if sendFailed {
		return 1
	}
	return 0
}

func channelStore(name string) *dedup.Store {
	if name == "telegram" {
		return dedup.NewStore(stateDirPath())
	}
	return dedup.NewChannelStore(stateDirPath(), name)
}

func dedupInterval(cfg *config.Config) int {
	n, err := strconv.Atoi(cfg.Get("DEDUP_INTERVAL_DAYS"))
	if err != nil || n < 1 {
		return 3
	}
	return n
}
