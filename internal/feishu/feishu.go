// Package feishu implements tenant-token authentication and bot message delivery.
package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://open.feishu.cn"

const (
	maxRespBytes        = 1 << 20
	maxTextRunes        = 20000
	truncatedTextRunes  = 19900
	truncationSuffix    = "\n…(truncated)"
	maxCardRequestBytes = 30 * 1024
)

var retryStatus = map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true}
var openIDPattern = regexp.MustCompile(`^ou_[A-Za-z0-9_-]+$`)

var (
	errInvalidCardJSON = errors.New("invalid Feishu card JSON")
	errCardSchema      = errors.New("Feishu card schema must be 2.0")
	errCardTooLarge    = errors.New("Feishu card request exceeds 30 KB")
)

// Client carries an injectable HTTP client, API base URL, and sleeper for tests.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	Sleep   func(time.Duration)
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
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

// Probe validates the app credentials without sending a message.
func (c *Client) Probe(ctx context.Context, appID, appSecret string) error {
	_, err := c.tenantToken(ctx, appID, appSecret)
	return err
}

// SendText obtains a tenant token and sends one plain-text bot message to an app-scoped open_id.
func (c *Client) SendText(ctx context.Context, appID, appSecret, receiveID, text string) error {
	if err := validateMessageTarget(appID, appSecret, receiveID); err != nil {
		return err
	}
	text = truncateText(text)
	content, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	body, err := marshalMessageBody(receiveID, "text", content)
	if err != nil {
		return err
	}
	token, err := c.tenantToken(ctx, appID, appSecret)
	if err != nil {
		return err
	}
	endpoint := c.base() + "/open-apis/im/v1/messages?receive_id_type=open_id"
	return c.doJSON(ctx, endpoint, token, body)
}

// SendCard obtains a tenant token and sends one static Feishu JSON 2.0 card.
func (c *Client) SendCard(ctx context.Context, appID, appSecret, receiveID string, card []byte) error {
	if err := validateMessageTarget(appID, appSecret, receiveID); err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, card); err != nil {
		return errInvalidCardJSON
	}
	var doc map[string]any
	if err := json.Unmarshal(compact.Bytes(), &doc); err != nil || doc == nil {
		return errInvalidCardJSON
	}
	if schema, _ := doc["schema"].(string); schema != "2.0" {
		return errCardSchema
	}
	body, err := marshalMessageBody(receiveID, "interactive", compact.Bytes())
	if err != nil {
		return err
	}
	if len(body) > maxCardRequestBytes {
		return errCardTooLarge
	}
	token, err := c.tenantToken(ctx, appID, appSecret)
	if err != nil {
		return err
	}
	endpoint := c.base() + "/open-apis/im/v1/messages?receive_id_type=open_id"
	return c.doJSON(ctx, endpoint, token, body)
}

// IsCardPreflightError reports whether card delivery failed before any Feishu
// message request was sent, making a plain-text fallback non-duplicating.
func IsCardPreflightError(err error) bool {
	return errors.Is(err, errInvalidCardJSON) || errors.Is(err, errCardSchema) || errors.Is(err, errCardTooLarge)
}

func validateMessageTarget(appID, appSecret, receiveID string) error {
	if appID == "" || appSecret == "" || receiveID == "" {
		return fmt.Errorf("missing Feishu app id, app secret, or receive id")
	}
	if !openIDPattern.MatchString(receiveID) {
		return fmt.Errorf("invalid Feishu open_id")
	}
	return nil
}

func marshalMessageBody(receiveID, msgType string, content []byte) ([]byte, error) {
	return json.Marshal(map[string]string{
		"receive_id": receiveID,
		"msg_type":   msgType,
		"content":    string(content),
	})
}

func truncateText(text string) string {
	runes := []rune(text)
	if len(runes) > maxTextRunes {
		return string(runes[:truncatedTextRunes]) + truncationSuffix
	}
	return text
}

func (c *Client) tenantToken(ctx context.Context, appID, appSecret string) (string, error) {
	if appID == "" || appSecret == "" {
		return "", fmt.Errorf("missing Feishu app id or app secret")
	}
	body, err := json.Marshal(map[string]string{"app_id": appID, "app_secret": appSecret})
	if err != nil {
		return "", err
	}
	endpoint := c.base() + "/open-apis/auth/v3/tenant_access_token/internal"
	var token string
	err = c.retry(ctx, func() (bool, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false, 0, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return true, 0, fmt.Errorf("Feishu token request failed: %w", err)
		}
		defer resp.Body.Close()
		respBody, err := readResponseBody(resp.Body)
		if err != nil {
			return false, 0, err
		}
		if retryStatus[resp.StatusCode] {
			return true, retryAfter(resp), fmt.Errorf("Feishu token HTTP %d", resp.StatusCode)
		}
		var v struct {
			Code              int    `json:"code"`
			TenantAccessToken string `json:"tenant_access_token"`
		}
		if err := json.Unmarshal(respBody, &v); err != nil {
			return false, 0, fmt.Errorf("invalid Feishu token response")
		}
		if resp.StatusCode >= 400 || v.Code != 0 || v.TenantAccessToken == "" {
			return false, 0, fmt.Errorf("Feishu token failed: code=%d", v.Code)
		}
		token = v.TenantAccessToken
		return false, 0, nil
	})
	return token, err
}

func (c *Client) doJSON(ctx context.Context, endpoint, token string, body []byte) error {
	return c.retry(ctx, func() (bool, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false, 0, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return true, 0, fmt.Errorf("Feishu message request failed: %w", err)
		}
		defer resp.Body.Close()
		respBody, err := readResponseBody(resp.Body)
		if err != nil {
			return false, 0, err
		}
		if retryStatus[resp.StatusCode] {
			return true, retryAfter(resp), fmt.Errorf("Feishu message HTTP %d", resp.StatusCode)
		}
		var v struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(respBody, &v); err != nil {
			return false, 0, fmt.Errorf("invalid Feishu message response")
		}
		if resp.StatusCode >= 400 || v.Code != 0 {
			return false, 0, fmt.Errorf("Feishu message failed: code=%d", v.Code)
		}
		return false, 0, nil
	})
}

func (c *Client) retry(ctx context.Context, attempt func() (bool, time.Duration, error)) error {
	var last error
	for i := 0; i < 3; i++ {
		retryable, delay, err := attempt()
		if err == nil {
			return nil
		}
		last = err
		if !retryable {
			break
		}
		if i < 2 {
			if delay <= 0 {
				delay = time.Second
			}
			c.sleep(delay)
		}
	}
	return last
}

func readResponseBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxRespBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Feishu response")
	}
	if len(body) > maxRespBytes {
		return nil, fmt.Errorf("Feishu response too large")
	}
	return body, nil
}

func retryAfter(resp *http.Response) time.Duration {
	raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
		return min(time.Duration(seconds)*time.Second, 30*time.Second)
	}
	if when, err := http.ParseTime(raw); err == nil {
		delay := time.Until(when)
		if delay > 0 {
			return min(delay, 30*time.Second)
		}
	}
	return 0
}
