// Package telegram 用 net/http 复刻运行时内嵌 python 的 Telegram 调用（getMe / sendMessage），
// 干掉 python3 依赖。保留原有语义：token 正则校验、4096 字符按 rune 截断到 4000、发送重试 3 次
// 间隔 1s，且仅对 429/5xx 或网络错误重试（ok=false 或其它 4xx 视为永久失败不重试）。
//
// Package telegram reimplements the runtime's embedded-python Telegram calls (getMe / sendMessage) with
// net/http, dropping the python3 dependency. Semantics preserved: token regex, rune-based 4096→4000
// truncation, 3 send attempts 1s apart, retrying ONLY on 429/5xx or a network error (ok=false or other
// 4xx are permanent, not retried).
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.telegram.org"

// tokenRe 复刻 `^\d+:[A-Za-z0-9_-]+$`。
var tokenRe = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)

// retryStatus 是值得重试的 HTTP 状态码（429 限流 + 5xx）。
var retryStatus = map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true}

// Client 承载 HTTP 客户端与可注入的 BaseURL / Sleep（便于测试）。
type Client struct {
	HTTP    *http.Client
	BaseURL string                // 默认 https://api.telegram.org
	Sleep   func(d time.Duration) // 默认 time.Sleep
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return defaultBaseURL
}

func (c *Client) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

// ErrBadToken 表示 token 格式非法（对应运行时的退出码 2 语义）。
var ErrBadToken = fmt.Errorf("invalid TELEGRAM_BOT_TOKEN format")

func validToken(token string) bool { return tokenRe.MatchString(token) }

// GetMe 校验 token 并请求 getMe，成功要求响应 JSON 的 ok=true。
func (c *Client) GetMe(ctx context.Context, token string) error {
	if !validToken(token) {
		return ErrBadToken
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+"/bot"+token+"/getMe", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !jsonOK(body) {
		return fmt.Errorf("getMe failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

// SendMessage 发送一条消息：按 rune 截断超长正文，最多尝试 3 次（间隔 1s），仅对 429/5xx 或网络错误
// 重试；ok=false 或其它 4xx 立即失败。
func (c *Client) SendMessage(ctx context.Context, token, chatID, text string) error {
	if token == "" || chatID == "" {
		return fmt.Errorf("missing Telegram token or chat id")
	}
	if !validToken(token) {
		return ErrBadToken
	}
	text = truncate(text)
	form := url.Values{
		"chat_id":                  {chatID},
		"text":                     {text},
		"disable_web_page_preview": {"true"},
	}
	endpoint := c.base() + "/bot" + token + "/sendMessage"
	var lastErr string
	for attempt := 0; attempt < 3; attempt++ {
		retryable, ok, msg := c.attempt(ctx, endpoint, form)
		if ok {
			return nil
		}
		lastErr = msg
		if !retryable {
			break
		}
		if attempt < 2 {
			c.sleep(time.Second)
		}
	}
	if lastErr == "" {
		lastErr = "Telegram notification failed"
	}
	return fmt.Errorf("%s", lastErr)
}

// attempt 执行一次发送，返回 (是否可重试, 是否成功, 错误信息)。
func (c *Client) attempt(ctx context.Context, endpoint string, form url.Values) (retryable, ok bool, msg string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, false, err.Error()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return true, false, err.Error() // 网络错误 -> 可重试
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if retryStatus[resp.StatusCode] {
		return true, false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncErr(string(body)))
	}
	if jsonOK(body) {
		return false, true, ""
	}
	// ok=false 或其它非重试状态码：永久失败。
	if resp.StatusCode >= 400 {
		return false, false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncErr(string(body)))
	}
	return false, false, strings.TrimSpace(string(body))
}

// truncate 复刻 4096→4000 rune 截断（RuneCountInString + rune 切片，非字节长度）。
func truncate(text string) string {
	if len([]rune(text)) > 4096 {
		r := []rune(text)
		return string(r[:4000]) + "\n…(truncated)"
	}
	return text
}

func truncErr(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

func jsonOK(body []byte) bool {
	var v struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return false
	}
	return v.OK
}
