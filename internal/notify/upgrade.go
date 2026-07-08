package notify

import "github.com/xxvcc/security-update-notify/internal/i18n"

// UpgradeMessage 是 --notify-upgrade-event 的显示数据。
type UpgradeMessage struct {
	Lang            i18n.Lang
	Host            string
	IncludePublicIP bool
	PublicIP        string
	From            string
	To              string
	Now             string
}

// RenderUpgrade 复刻升级成功通知（files/security-update-notify:848-849）。
func RenderUpgrade(m UpgradeMessage) string {
	if m.Lang == i18n.EN {
		host := "Host: " + m.Host
		if m.IncludePublicIP {
			host += "\nPublic IP: " + m.PublicIP
		}
		return "✅ SUN upgraded\n\n" + host +
			"\nVersion: " + m.From + " → " + m.To +
			"\nTime: " + m.Now +
			"\n\nPost-upgrade self-check completed."
	}
	host := "主机：" + m.Host
	if m.IncludePublicIP {
		host += "\n公网 IP：" + m.PublicIP
	}
	return "✅ SUN 已升级\n\n" + host +
		"\n版本：" + m.From + " → " + m.To +
		"\n时间：" + m.Now +
		"\n\n升级后自检已完成。"
}
