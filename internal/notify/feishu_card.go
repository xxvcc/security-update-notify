package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

const (
	feishuCardSoftLimit = 20 * 1024
	projectURL          = "https://github.com/xxvcc/security-update-notify"
)

type feishuCardMeta struct {
	Title    string
	Subtitle string
	Template string
	Summary  string
	Tags     []any
}

// RenderFeishuCard builds a static Feishu JSON 2.0 card for a regular check.
// The card uses only display components and an open-URL button, so no callback
// subscription, template ID, or CardKit permission is required.
func RenderFeishuCard(m Message) []byte {
	en := m.Lang == i18n.EN
	title, template := checkCardPresentation(m, en)
	meta := feishuCardMeta{
		Title:    title,
		Subtitle: limitCardText(m.Now, 160, en),
		Template: template,
		Summary:  limitCardText(title+" · "+m.Host, 240, en),
		Tags:     checkCardTags(m, en),
	}

	publicIPLabel := "公网 IP"
	backendLabel := "后端"
	osLabel := "系统"
	kernelLabel := "当前内核"
	if en {
		publicIPLabel = "Public IP"
		backendLabel = "Backend"
		osLabel = "OS"
		kernelLabel = "Current kernel"
	}
	secondLabel, secondValue := backendLabel, m.Backend
	if m.IncludePublicIP {
		secondLabel, secondValue = publicIPLabel, m.PublicIP
	}
	elements := []any{
		cardGrid(
			cardCell(pick(en, "主机", "Host"), limitCardText(m.Host, 512, en), "default"),
			cardCell(secondLabel, limitCardText(secondValue, 256, en), "default"),
		),
		cardGrid(
			cardCell(osLabel, limitCardText(m.OS, 768, en), "default"),
			cardCell(kernelLabel, limitCardText(m.Kernel, 256, en), "default"),
		),
		cardDivider(),
		cardGrid(
			cardCell(pick(en, "整机重启", "Full reboot"), requiredState(m.RebootRequired, en), boolColor(m.RebootRequired, "red")),
			cardCell(pick(en, "服务/进程重启", "Service/process restart"), attentionState(m.RestartAttention, en), boolColor(m.RestartAttention, "orange")),
		),
		cardGrid(
			cardCell(pick(en, "自动更新", "Auto updates"), healthState(m.HealthAttention, en), boolColor(m.HealthAttention, "red")),
			cardCell(pick(en, "安全支持", "Security support"), supportState(m, en), supportColor(m)),
		),
	}

	if m.Alert {
		pkgs := m.RebootPkgs
		if strings.TrimSpace(pkgs) == "" {
			pkgs = pick(en, "无", "None")
		}
		elements = appendCardSection(elements,
			pick(en, "相关包 / 安全更新", "Related packages / security updates"),
			limitCardText(pkgs, 2500, en))

		restartSummary := formatRestartSummary(m.Lang, m.Backend, m.RestartSummary, m.RebootRequired)
		restartSummary = limitLines(restartSummary, 80)
		elements = appendCardSection(elements,
			pick(en, "维护详情", "Maintenance details"),
			limitCardText(restartSummary, 4500, en))
	} else {
		elements = append(elements, cardCallout(
			pick(en,
				"未发现整机重启或服务、进程重启需要关注的问题。",
				"No reboot or service/process restart requiring attention was detected."),
			"green"))
	}

	healthText := pick(en, m.HealthTxtZH, m.HealthTxtEN)
	if healthText != "" {
		elements = appendCardSection(elements,
			pick(en, "自动安全更新机制", "Automatic security-update mechanism"),
			limitCardText(healthText, 2000, en))
	}
	pendingText := pick(en, m.PendingTxtZH, m.PendingTxtEN)
	if pendingText != "" {
		elements = appendCardSection(elements,
			pick(en, "待安装安全更新", "Pending security updates"),
			limitCardText(pendingText, 2000, en))
	}
	eolText := pick(en, m.EolTxtZH, m.EolTxtEN)
	if eolText != "" {
		elements = appendCardSection(elements,
			pick(en, "发行版支持状态", "Distribution support status"),
			limitCardText(eolText, 1500, en))
	}

	if m.Alert {
		recommendation := pick(en,
			"请在维护窗口 SSH 登录服务器进行处理。需要整机重启时执行 sudo reboot；仅涉及服务时，请先评估再重启对应服务。",
			"Handle this during a maintenance window over SSH. Run sudo reboot when a full reboot is required; otherwise review and restart only the affected services.")
		elements = append(elements, cardCallout(recommendation, "grey"))
	}
	elements = append(elements, cardDocsButton(en))

	fallback := Render(m)
	return marshalFeishuCard(meta, elements, fallback, en)
}

// RenderFeishuUpgradeCard builds the blue post-upgrade card.
func RenderFeishuUpgradeCard(m UpgradeMessage) []byte {
	en := m.Lang == i18n.EN
	title := pick(en, "SUN 已升级", "SUN upgraded")
	version := limitCardText(m.From+" → "+m.To, 256, en)
	meta := feishuCardMeta{
		Title:    title,
		Subtitle: limitCardText(m.Now, 160, en),
		Template: "blue",
		Summary:  limitCardText(title+" · "+m.Host+" · "+version, 240, en),
		Tags: []any{
			cardTextTag("SUN", "blue"),
			cardTextTag(version, "green"),
		},
	}
	secondLabel, secondValue := pick(en, "版本", "Version"), version
	if m.IncludePublicIP {
		secondLabel, secondValue = pick(en, "公网 IP", "Public IP"), limitCardText(m.PublicIP, 256, en)
	}
	elements := []any{
		cardGrid(
			cardCell(pick(en, "主机", "Host"), limitCardText(m.Host, 512, en), "default"),
			cardCell(secondLabel, secondValue, "default"),
		),
	}
	if m.IncludePublicIP {
		elements = append(elements, cardGrid(
			cardCell(pick(en, "升级前", "Previous version"), limitCardText(m.From, 128, en), "default"),
			cardCell(pick(en, "当前版本", "Current version"), limitCardText(m.To, 128, en), "green"),
		))
	}
	elements = append(elements,
		cardCallout(pick(en, "升级后自检已完成。", "Post-upgrade self-check completed."), "green"),
		cardDocsButton(en),
	)
	return marshalFeishuCard(meta, elements, RenderUpgrade(m), en)
}

func checkCardPresentation(m Message, en bool) (string, string) {
	switch {
	case !m.Alert:
		return pick(en, "安全更新检查正常", "Security update check OK"), "green"
	case m.EolAttention:
		return pick(en, "发行版安全支持已结束", "Distribution security support ended"), "red"
	case m.HealthAttention:
		return pick(en, "自动安全更新机制异常", "Automatic security updates need attention"), "red"
	default:
		return pick(en, "主机需要安全维护", "Host maintenance required"), "orange"
	}
}

func checkCardTags(m Message, en bool) []any {
	tags := []any{cardTextTag("SUN", "blue")}
	if version := strings.TrimSpace(m.Version); version != "" {
		tags = append(tags, cardTextTag(limitCardText("v"+strings.TrimPrefix(version, "v"), 64, en), "neutral"))
	}
	if m.PendingCount > 0 && len(tags) < 3 {
		tags = append(tags, cardTextTag(fmt.Sprintf(pick(en, "待装 %d", "%d pending"), m.PendingCount), "orange"))
	} else if backend := strings.TrimSpace(m.Backend); backend != "" && len(tags) < 3 {
		tags = append(tags, cardTextTag(strings.ToUpper(limitCardText(backend, 24, en)), "neutral"))
	}
	return tags
}

func requiredState(required, en bool) string {
	if required {
		return pick(en, "需要", "Required")
	}
	return pick(en, "暂不需要", "Not required")
}

func attentionState(attention, en bool) string {
	if attention {
		return pick(en, "需要处理", "Action needed")
	}
	return pick(en, "正常", "Normal")
}

func healthState(attention, en bool) string {
	if attention {
		return pick(en, "异常", "Problem")
	}
	return pick(en, "正常", "Healthy")
}

func supportState(m Message, en bool) string {
	if m.EolAttention {
		return pick(en, "已结束", "Ended")
	}
	if pick(en, m.EolTxtZH, m.EolTxtEN) != "" {
		return pick(en, "即将结束", "Ending soon")
	}
	return pick(en, "正常", "Supported")
}

func supportColor(m Message) string {
	if m.EolAttention {
		return "red"
	}
	if m.EolTxtZH != "" || m.EolTxtEN != "" {
		return "orange"
	}
	return "green"
}

func boolColor(attention bool, attentionColor string) string {
	if attention {
		return attentionColor
	}
	return "green"
}

func appendCardSection(elements []any, title, content string) []any {
	if strings.TrimSpace(content) == "" {
		return elements
	}
	return append(elements,
		cardDivider(),
		cardDiv(title, "heading", "default"),
		cardDiv(content, "normal", "default"),
	)
}

func cardGrid(cells ...map[string]any) map[string]any {
	columns := make([]any, 0, len(cells))
	for _, cell := range cells {
		columns = append(columns, cell)
	}
	return map[string]any{
		"tag":                "column_set",
		"flex_mode":          "bisect",
		"horizontal_spacing": "8px",
		"columns":            columns,
	}
}

func cardCell(label, value, valueColor string) map[string]any {
	return map[string]any{
		"tag":              "column",
		"width":            "weighted",
		"weight":           1,
		"background_style": "grey",
		"padding":          "8px",
		"vertical_spacing": "4px",
		"elements": []any{
			cardDiv(label, "normal", "grey"),
			cardDiv(value, "heading", valueColor),
		},
	}
}

func cardCallout(content, color string) map[string]any {
	return map[string]any{
		"tag":       "column_set",
		"flex_mode": "stretch",
		"columns": []any{
			map[string]any{
				"tag":              "column",
				"width":            "weighted",
				"weight":           1,
				"background_style": color,
				"padding":          "10px",
				"elements":         []any{cardDiv(content, "normal", "default")},
			},
		},
	}
}

func cardDiv(content, size, color string) map[string]any {
	text := map[string]any{
		"tag":       "plain_text",
		"content":   content,
		"text_size": size,
	}
	if color != "" {
		text["text_color"] = color
	}
	return map[string]any{"tag": "div", "text": text}
}

func cardDivider() map[string]any { return map[string]any{"tag": "hr"} }

func cardDocsButton(en bool) map[string]any {
	return map[string]any{
		"tag":   "button",
		"text":  map[string]any{"tag": "plain_text", "content": pick(en, "查看 SUN 使用说明", "View SUN documentation")},
		"type":  "default",
		"width": "default",
		"size":  "medium",
		"behaviors": []any{
			map[string]any{"type": "open_url", "default_url": projectURL},
		},
	}
}

func cardTextTag(text, color string) map[string]any {
	return map[string]any{
		"tag":   "text_tag",
		"text":  map[string]any{"tag": "plain_text", "content": text},
		"color": color,
	}
}

func marshalFeishuCard(meta feishuCardMeta, elements []any, fallback string, en bool) []byte {
	doc := map[string]any{
		"schema": "2.0",
		"config": map[string]any{
			"summary":        map[string]any{"content": meta.Summary},
			"enable_forward": false,
			"update_multi":   true,
			"width_mode":     "fill",
		},
		"header": map[string]any{
			"title":         map[string]any{"tag": "plain_text", "content": meta.Title},
			"subtitle":      map[string]any{"tag": "plain_text", "content": meta.Subtitle},
			"text_tag_list": meta.Tags,
			"template":      meta.Template,
			"padding":       "12px 12px 12px 12px",
		},
		"body": map[string]any{
			"direction":        "vertical",
			"padding":          "12px 12px 12px 12px",
			"vertical_spacing": "12px",
			"elements":         elements,
		},
	}
	b, _ := json.Marshal(doc) // all values are JSON-native and cannot make Marshal fail
	if len(b) <= feishuCardSoftLimit {
		return b
	}

	// Preserve delivery if unexpectedly large host data exceeds the designed section caps.
	doc["body"] = map[string]any{
		"direction":        "vertical",
		"padding":          "12px 12px 12px 12px",
		"vertical_spacing": "12px",
		"elements": []any{
			cardDiv(limitCardText(fallback, 8000, en), "normal", "default"),
			cardDocsButton(en),
		},
	}
	b, _ = json.Marshal(doc)
	return b
}

func limitCardText(s string, maxBytes int, en bool) string {
	s = sanitizeCardText(s)
	if len(s) <= maxBytes {
		return s
	}
	suffix := pick(en, "\n…（内容已截断）", "\n...(truncated)")
	limit := maxBytes - len(suffix)
	if limit < 0 {
		return suffix
	}
	for limit > 0 && !utf8.ValidString(s[:limit]) {
		limit--
	}
	return strings.TrimSpace(s[:limit]) + suffix
}

func sanitizeCardText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, s)
	return strings.TrimSpace(s)
}

func pick(en bool, zh, english string) string {
	if en {
		return english
	}
	return zh
}
