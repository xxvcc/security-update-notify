// Package feishu implements tenant-token authentication and bot message delivery.
//
//lint:file-ignore ST1005 Feishu API errors intentionally retain the product's official capitalization.
package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
)

const defaultBaseURL = "https://open.feishu.cn"

const (
	maxRespBytes        = 1 << 20
	maxAppIDBytes       = 256
	maxAppSecretBytes   = 64 << 10
	maxTextRunes        = 20000
	truncatedTextRunes  = 19900
	truncationSuffix    = "\n…(truncated)"
	maxCardRequestBytes = 30 * 1024
	apiRateLimitCode    = 99991400
)

func retryableStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || (status >= 500 && status < 600)
}

var openIDPattern = regexp.MustCompile(`^ou_[A-Za-z0-9_-]+$`)

var (
	errInvalidCardJSON           = errors.New("invalid Feishu card JSON")
	errCardSchema                = errors.New("Feishu card schema must be 2.0")
	errCardTooLarge              = errors.New("Feishu card request exceeds 30 KB")
	errResponseTooLarge          = errors.New("Feishu response too large")
	errDirectoryResponseTooLarge = errors.New("Feishu directory response too large")
)

type temporaryError struct{ err error }

func (e *temporaryError) Error() string   { return e.err.Error() }
func (e *temporaryError) Unwrap() error   { return e.err }
func (e *temporaryError) Temporary() bool { return true }

// IsTemporary reports transport, timeout, rate-limit, malformed-response, and
// server-side failures so installers do not mistake API unavailability for
// rejected credentials or an invalid recipient.
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

type externalError struct {
	prefix string
	cause  error
	safe   string
}

func (e *externalError) Error() string { return e.prefix + ": " + e.safe }
func (e *externalError) Unwrap() error { return e.cause }

func sanitizeExternalError(prefix string, err error, secrets ...string) error {
	safe := err.Error()
	variants := make(map[string]struct{}, len(secrets)*3)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		for _, encoded := range []string{secret, url.PathEscape(secret), url.QueryEscape(secret)} {
			if encoded != "" {
				variants[encoded] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(variants))
	for variant := range variants {
		ordered = append(ordered, variant)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) == len(ordered[j]) {
			return ordered[i] < ordered[j]
		}
		return len(ordered[i]) > len(ordered[j])
	})
	if len(ordered) > 0 {
		replacements := make([]string, 0, len(ordered)*2)
		for _, variant := range ordered {
			replacements = append(replacements, variant, "[REDACTED]")
		}
		safe = strings.NewReplacer(replacements...).Replace(safe)
	}
	safe = textsafe.SingleLine(safe)
	for len(safe) > 300 {
		_, size := utf8.DecodeLastRuneInString(safe)
		safe = safe[:len(safe)-size]
	}
	return &externalError{prefix: prefix, cause: err, safe: safe}
}

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
	text = truncateText(textsafe.Multiline(text))
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
	if err := validateCredentials(appID, appSecret); err != nil {
		return err
	}
	if receiveID == "" {
		return fmt.Errorf("missing Feishu app id, app secret, or receive id")
	}
	if len(receiveID) > 256 || !openIDPattern.MatchString(receiveID) {
		return fmt.Errorf("invalid Feishu open_id")
	}
	return nil
}

func validateCredentials(appID, appSecret string) error {
	if appID == "" || len(appID) > maxAppIDBytes || appSecret == "" || len(appSecret) > maxAppSecretBytes {
		return fmt.Errorf("missing or invalid Feishu app id or app secret")
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
	if err := validateCredentials(appID, appSecret); err != nil {
		return "", err
	}
	base := c.base()
	if err := httpx.GuardAPIBase(base); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"app_id": appID, "app_secret": appSecret})
	if err != nil {
		return "", err
	}
	endpoint := base + "/open-apis/auth/v3/tenant_access_token/internal"
	client, err := httpx.NoRedirects(c.HTTP)
	if err != nil {
		return "", err
	}
	var token string
	err = c.retry(ctx, func() (bool, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false, 0, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp, err := client.Do(req)
		if err != nil {
			return true, 0, sanitizeExternalError("Feishu token request failed", err, appID, appSecret)
		}
		defer resp.Body.Close()
		respBody, err := readResponseBody(resp.Body)
		if err != nil {
			// Token issuance is safe to repeat; retry interrupted reads, but not a
			// deterministic oversized response.
			return !errors.Is(err, errResponseTooLarge), 0, temporary(err)
		}
		if retryableStatus(resp.StatusCode) {
			return true, retryAfter(resp), fmt.Errorf("Feishu token HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, 0, fmt.Errorf("Feishu token HTTP %d", resp.StatusCode)
		}
		var v struct {
			Code              *int   `json:"code"`
			TenantAccessToken string `json:"tenant_access_token"`
		}
		if err := json.Unmarshal(respBody, &v); err != nil {
			return false, 0, temporary(fmt.Errorf("invalid Feishu token response"))
		}
		if v.Code == nil {
			return false, 0, temporary(fmt.Errorf("invalid Feishu token response"))
		}
		if *v.Code == apiRateLimitCode {
			return true, retryAfter(resp), fmt.Errorf("Feishu token temporarily unavailable")
		}
		if *v.Code != 0 {
			return false, 0, fmt.Errorf("Feishu token failed: code=%d", *v.Code)
		}
		if v.TenantAccessToken == "" || len(v.TenantAccessToken) > 8192 {
			return false, 0, temporary(fmt.Errorf("invalid Feishu token response"))
		}
		token = v.TenantAccessToken
		return false, 0, nil
	})
	return token, err
}

func (c *Client) doJSON(ctx context.Context, endpoint, token string, body []byte) error {
	client, err := httpx.NoRedirects(c.HTTP)
	if err != nil {
		return err
	}
	return c.retry(ctx, func() (bool, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false, 0, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return false, 0, temporary(sanitizeExternalError("Feishu message request failed", err, token))
		}
		defer resp.Body.Close()
		respBody, err := readResponseBody(resp.Body)
		if err != nil {
			return false, 0, temporary(err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return true, retryAfter(resp), fmt.Errorf("Feishu message HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusRequestTimeout || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
			return false, 0, temporary(fmt.Errorf("Feishu message HTTP %d", resp.StatusCode))
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, 0, fmt.Errorf("Feishu message HTTP %d", resp.StatusCode)
		}
		var v struct {
			Code *int `json:"code"`
		}
		if err := json.Unmarshal(respBody, &v); err != nil {
			return false, 0, temporary(fmt.Errorf("invalid Feishu message response"))
		}
		if v.Code == nil {
			return false, 0, temporary(fmt.Errorf("invalid Feishu message response"))
		}
		if *v.Code == apiRateLimitCode {
			return true, retryAfter(resp), fmt.Errorf("Feishu message temporarily unavailable")
		}
		if *v.Code != 0 {
			return false, 0, fmt.Errorf("Feishu message failed: code=%d", *v.Code)
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
			return err
		}
		if i < 2 {
			if delay <= 0 {
				delay = time.Second
			}
			if err := c.sleep(ctx, delay); err != nil {
				return temporary(err)
			}
		}
	}
	return temporary(last)
}

func readResponseBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxRespBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Feishu response")
	}
	if len(body) > maxRespBytes {
		return nil, errResponseTooLarge
	}
	return body, nil
}

func retryAfter(resp *http.Response) time.Duration {
	raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(raw, 10, 64); err == nil {
		const maxRetryAfterSeconds = uint64(30)
		if seconds >= maxRetryAfterSeconds {
			return 30 * time.Second
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(raw); err == nil {
		delay := time.Until(when)
		if delay > 0 {
			return min(delay, 30*time.Second)
		}
	}
	return 0
}
