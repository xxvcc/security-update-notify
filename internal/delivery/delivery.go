// Package delivery defines the small channel contract shared by Telegram and Feishu.
package delivery

import (
	"context"
	"fmt"
	"strings"
)

const defaultChannels = "telegram"

// Message carries the channel-neutral text plus an optional Feishu-native card.
// Telegram always uses Text. Feishu prefers FeishuCard when it is present.
type Message struct {
	Text       string
	FeishuCard []byte
}

// Sender sends and probes one configured notification channel.
type Sender interface {
	Name() string
	Send(context.Context, Message) error
	Probe(context.Context) error
}

// ParseChannels parses NOTIFY_CHANNELS. An empty value keeps legacy installs on Telegram.
func ParseChannels(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultChannels
	}
	seen := make(map[string]bool)
	var out []string
	for _, part := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			return nil, fmt.Errorf("invalid empty notification channel")
		}
		if name != "telegram" && name != "feishu" {
			return nil, fmt.Errorf("unsupported notification channel: %s", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}
