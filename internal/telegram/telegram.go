// Package telegram 用 net/http 复刻运行时内嵌 python 的 Telegram 调用（getMe / sendMessage），
// 干掉 python3 依赖。保留原有语义：token 正则校验、4096 字符按 rune 截断到 4000、发送重试 3 次
// 间隔 1s，且仅对 429/5xx 或网络错误重试（ok=false 或其它 4xx 视为永久失败不重试）。
//
// Package telegram reimplements the runtime's embedded-python Telegram calls (getMe / sendMessage) with
// net/http, dropping the python3 dependency. Semantics preserved: token regex, rune-based 4096→4000
// truncation, 3 send attempts 1s apart, retrying ONLY on 429/5xx or a network error (ok=false or other
// 4xx are permanent, not retried).
//
//lint:file-ignore ST1005 Telegram API errors intentionally retain the product's official capitalization.
package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/httpx"
)

const defaultBaseURL = "https://api.telegram.org"

// maxRespBytes 限制 Telegram 响应体的读取量，防止（被 MITM/重定向劫持的）超大响应体撑爆内存。
// 正常 Telegram JSON 仅数百字节，1 MiB 绰绰有余。
const maxRespBytes = 1 << 20

// sanitizeErr 去掉传输错误里的请求 URL——token 就嵌在 URL 路径（/bot<token>/…）里，
// Go 的 *url.Error.Error() 只脱敏 userinfo、不脱敏路径，直接 surface 会把 bot token 写进 stderr/journal。
// 只保留操作名与底层原因（含主机名，但不含 token）。
func sanitizeErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s request failed: %v", ue.Op, ue.Err)
	}
	return err
}

// tokenRe 复刻 `^\d+:[A-Za-z0-9_-]+$`。
var tokenRe = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)

func retryableStatus(status int) bool { return status == 429 || (status >= 500 && status < 600) }

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

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		c.Sleep(d)
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ErrBadToken 表示 token 格式非法（对应运行时的退出码 2 语义）。
var ErrBadToken = fmt.Errorf("invalid TELEGRAM_BOT_TOKEN format")

type temporaryError struct{ err error }

func (e *temporaryError) Error() string   { return e.err.Error() }
func (e *temporaryError) Unwrap() error   { return e.err }
func (e *temporaryError) Temporary() bool { return true }

// IsTemporary reports transport, timeout, rate-limit, and server-side failures
// so installers do not mistake an unavailable API for invalid credentials.
func IsTemporary(err error) bool {
	var temporary interface{ Temporary() bool }
	return errors.As(err, &temporary) && temporary.Temporary()
}

func temporary(err error) error {
	if err == nil || IsTemporary(err) {
		return err
	}
	return &temporaryError{err: err}
}

func validToken(token string) bool { return len(token) <= 256 && tokenRe.MatchString(token) }

func (c *Client) apiClient() (*http.Client, error) { return httpx.NoRedirects(c.HTTP) }

// GetMe 校验 token 并请求 getMe，成功要求响应 JSON 的 ok=true。
func (c *Client) GetMe(ctx context.Context, token string) error {
	if !validToken(token) {
		return ErrBadToken
	}
	base := strings.TrimRight(c.base(), "/")
	if err := httpx.GuardAPIBase(base); err != nil {
		return err
	}
	client, err := c.apiClient()
	if err != nil {
		return err
	}
	endpoint := base + "/bot" + token + "/getMe"
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		retryable, transient, err := c.getMeAttempt(ctx, client, endpoint)
		if err == nil {
			return nil
		}
		last = err
		if !retryable {
			if transient {
				return temporary(err)
			}
			return err
		}
		if attempt < 2 {
			if err := c.sleep(ctx, time.Second); err != nil {
				return temporary(err)
			}
		}
	}
	return temporary(last)
}

func (c *Client) getMeAttempt(ctx context.Context, client *http.Client, endpoint string) (retryable, transient bool, returnErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return true, true, sanitizeErr(err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp.Body)
	if err != nil {
		return false, true, err
	}
	if retryableStatus(resp.StatusCode) {
		return true, true, fmt.Errorf("getMe HTTP %d: %s", resp.StatusCode, truncErr(string(body)))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, false, fmt.Errorf("getMe HTTP %d: %s", resp.StatusCode, truncErr(string(body)))
	}
	ok, valid := decodeOK(body)
	if !valid {
		return false, true, fmt.Errorf("getMe returned an invalid response")
	}
	if !ok {
		return false, false, fmt.Errorf("getMe failed: %s", truncErr(strings.TrimSpace(string(body))))
	}
	return false, false, nil
}

// SendMessage 发送一条消息：按 rune 截断超长正文，最多尝试 3 次（间隔 1s），仅对 429/5xx 或网络错误
// 重试；ok=false 或其它 4xx 立即失败。
func (c *Client) SendMessage(ctx context.Context, token, chatID, text string) error {
	if token == "" || chatID == "" || len(chatID) > 256 {
		return fmt.Errorf("missing Telegram token or chat id")
	}
	if !validToken(token) {
		return ErrBadToken
	}
	base := strings.TrimRight(c.base(), "/")
	if err := httpx.GuardAPIBase(base); err != nil {
		return err
	}
	text = truncate(text)
	form := url.Values{
		"chat_id":                  {chatID},
		"text":                     {text},
		"disable_web_page_preview": {"true"},
	}
	endpoint := base + "/bot" + token + "/sendMessage"
	client, err := c.apiClient()
	if err != nil {
		return err
	}
	var lastErr string
	lastTransient := false
	for attempt := 0; attempt < 3; attempt++ {
		retryable, transient, ok, msg := c.attempt(ctx, client, endpoint, form)
		if ok {
			return nil
		}
		lastErr = msg
		lastTransient = transient
		if !retryable {
			break
		}
		if attempt < 2 {
			if err := c.sleep(ctx, time.Second); err != nil {
				return temporary(err)
			}
		}
	}
	if lastErr == "" {
		lastErr = "Telegram notification failed"
	}
	err = fmt.Errorf("%s", lastErr)
	if lastTransient {
		return temporary(err)
	}
	return err
}

// attempt 执行一次发送，返回 (是否可重试, 是否成功, 错误信息)。
func (c *Client) attempt(ctx context.Context, client *http.Client, endpoint string, form url.Values) (retryable, transient, ok bool, msg string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, false, false, err.Error()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return true, true, false, sanitizeErr(err).Error() // 网络错误 -> 可重试（已剥离含 token 的 URL）
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp.Body)
	if err != nil {
		return false, true, false, err.Error()
	}
	if retryableStatus(resp.StatusCode) {
		return true, true, false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncErr(string(body)))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, false, false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncErr(string(body)))
	}
	ok, valid := decodeOK(body)
	if !valid {
		return false, true, false, "Telegram returned an invalid response"
	}
	if ok {
		return false, false, true, ""
	}
	// ok=false 或其它非重试状态码：永久失败。
	return false, false, false, truncErr(strings.TrimSpace(string(body)))
}

func readResponseBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxRespBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Telegram response")
	}
	if len(body) > maxRespBytes {
		return nil, fmt.Errorf("Telegram response too large")
	}
	return body, nil
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

func decodeOK(body []byte) (bool, bool) {
	var v struct {
		OK *bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.OK == nil {
		return false, false
	}
	return *v.OK, true
}
