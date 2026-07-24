// Package run 组合各纯逻辑包（config/osrel/backend/watchdog/dedup/notify）成运行时的决策核心：
// 由已采集的输入产出去重字段、是否需要关注、要发送的正文、以及是否发送。系统采集（systemctl/df/
// needrestart/hostname/date 等）在更外层用 internal/sysexec 完成；Assemble 保持纯函数以便端到端
// golden 测试逐字节校验整条链。
//
// Package run composes the pure-logic packages into the runtime's decision core: from collected inputs it
// produces the dedup fields, the attention decision, the body to send, and whether to send. System
// collection (systemctl/df/needrestart/hostname/date) happens in an outer layer via internal/sysexec;
// Assemble stays pure so an end-to-end golden test can byte-check the whole chain.
package run

import (
	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/dedup"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/notify"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

// Input 是 run 路径的全部已采集数据（配置解析值 + 显示值 + 后端重启状态 + 看门狗 + 标志）。
type Input struct {
	Host            string    // HOST_LABEL 或 hostname -f 的结果
	Backend         string    // apt|dnf（由配置 BACKEND 或 AutoBackend 解析）
	NotifyLang      i18n.Lang // 已归一化
	IncludePublicIP bool
	PublicIP        string // PUBLIC_IP_VALUE（不显示时为空）
	OS              string
	Kernel          string
	Now             string
	Version         string

	Restart backend.RestartState // check_apt/check_dnf 或 --test-reboot 夹具
	Health  watchdog.Health
	Pending watchdog.Pending
	EOL     watchdog.EOL

	SendOK   bool // --test-ok 或 NOTIFY_OK=1
	NoDedupe bool
}

// Output 是决策结果。
type Output struct {
	Fields     dedup.Fields
	Attention  bool   // reboot || restart_attention || health || eol
	Send       bool   // 是否发送（有关注，或无关注但 SendOK）
	Message    string // 要发送的正文（Send=false 时为空）
	FeishuCard []byte // 飞书 JSON 2.0 卡片（Send=false 时为空）
}

// Assemble 复刻运行时末尾的决策与消息组装（files/security-update-notify:1044-1091）：
// 关注 = 需要整机重启 或 服务重启关注 或 机制异常 或 已过 EOL（pending 与临近 EOL 仅信息，不触发）。
// 有关注 -> 告警正文并发送；无关注 -> 仅当 SendOK 才发 OK 正文，否则静默不发。
func Assemble(in Input) Output {
	fields := dedup.Fields{
		Host:             in.Host,
		Backend:          in.Backend,
		NotifyLang:       string(in.NotifyLang),
		RebootRequired:   in.Restart.RebootRequired,
		RebootPkgs:       in.Restart.RebootPkgs,
		RestartAttention: in.Restart.RestartAttention,
		RestartSignal:    in.Restart.RestartSignal,
		HealthAttention:  in.Health.Attention,
		HealthSig:        in.Health.Sig,
		EolAttention:     in.EOL.Attention,
		EolSig:           in.EOL.Sig,
	}
	attention := in.Restart.RebootRequired || in.Restart.RestartAttention || in.Health.Attention || in.EOL.Attention

	out := Output{Fields: fields, Attention: attention}
	if !attention && !in.SendOK {
		return out // 静默：无关注且不要求 OK 通知
	}
	out.Send = true
	message := notify.Message{
		Alert:            attention,
		Lang:             in.NotifyLang,
		Version:          in.Version,
		Host:             in.Host,
		IncludePublicIP:  in.IncludePublicIP,
		PublicIP:         in.PublicIP,
		OS:               in.OS,
		Backend:          in.Backend,
		Kernel:           in.Kernel,
		Now:              in.Now,
		RebootRequired:   in.Restart.RebootRequired,
		RestartAttention: in.Restart.RestartAttention,
		RebootPkgs:       in.Restart.RebootPkgs,
		RestartSummary:   in.Restart.RestartSummary,
		HealthTxtZH:      in.Health.TxtZH,
		HealthTxtEN:      in.Health.TxtEN,
		HealthAttention:  in.Health.Attention,
		PendingTxtZH:     in.Pending.TxtZH,
		PendingTxtEN:     in.Pending.TxtEN,
		PendingCount:     in.Pending.Count,
		EolTxtZH:         in.EOL.TxtZH,
		EolTxtEN:         in.EOL.TxtEN,
		EolAttention:     in.EOL.Attention,
	}
	out.Message = notify.Render(message)
	out.FeishuCard = notify.RenderFeishuCard(message)
	return out
}

// Hash 是 Output.Fields 的 alert_hash 便捷方法。
func (o Output) Hash() string { return dedup.Hash(o.Fields) }
