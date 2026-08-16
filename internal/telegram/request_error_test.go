package telegram

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/httpx"
)

// assertTokenAbsent 检查错误文本里没有任何形式的 bot token——URL 路径、路径转义和查询转义
// 都可能把它带出来，所以三种编码都要查。
//
// assertTokenAbsent rejects the bot token in every encoding a request URL or a form body could have
// produced, because an operator only ever sees these strings after they reach stderr/journal.
func assertTokenAbsent(t *testing.T, where, text, token string) {
	t.Helper()
	for _, encoded := range []string{token, url.PathEscape(token), url.QueryEscape(token)} {
		if strings.Contains(text, encoded) {
			t.Fatalf("%s leaked the bot token as %q: %q", where, encoded, text)
		}
	}
}

// TestSanitizeErrRedactsBotTokenEmbeddedInRequestURL 覆盖 *url.Error：Go 只脱敏 userinfo，
// token 藏在路径 /bot<token>/… 里，必须由 sanitizeErr 丢掉整个 URL 并脱敏底层原因。
func TestSanitizeErrRedactsBotTokenEmbeddedInRequestURL(t *testing.T) {
	const token = "123456:SECRET-TOKEN"
	const endpoint = "https://api.telegram.org/bot" + token + "/getMe"
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{
			name: "transport failure carrying the endpoint",
			err:  &url.Error{Op: "Get", URL: endpoint, Err: errors.New("dial tcp 149.154.167.220:443: connect: connection refused")},
			want: "Get request failed:",
		},
		{
			name: "request construction failure carrying the endpoint",
			err:  &url.Error{Op: "parse", URL: endpoint, Err: errors.New("net/url: invalid control character in URL")},
			want: "parse request failed:",
		},
		{
			name: "endpoint repeated inside the wrapped cause",
			err:  &url.Error{Op: "Post", URL: endpoint, Err: fmt.Errorf("proxy refused %s", endpoint)},
			want: "Post request failed:",
		},
		{
			name: "path escaped token inside the wrapped cause",
			err:  &url.Error{Op: "Post", URL: endpoint, Err: fmt.Errorf("redirected to /bot%s/sendMessage", url.PathEscape(token))},
			want: "[REDACTED]",
		},
		{
			name: "query escaped token inside the wrapped cause",
			err:  &url.Error{Op: "Get", URL: endpoint, Err: fmt.Errorf("blocked by policy: token=%s", url.QueryEscape(token))},
			want: "[REDACTED]",
		},
		{
			name: "plain error mentioning the endpoint",
			err:  fmt.Errorf("net/http: nil Context while requesting %s", endpoint),
			want: "nil Context",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := sanitizeErr(test.err, token).Error()
			assertTokenAbsent(t, "sanitizeErr", got, token)
			if !strings.Contains(got, test.want) {
				t.Fatalf("sanitized error = %q, want it to keep %q", got, test.want)
			}
		})
	}
}

// TestTelegramFailureErrorsNeverContainTheBotToken 把不变量按结构钉住而不是逐例枚举：无论
// Telegram（或劫持它的中间设备）以哪种方式失败，GetMe / SendMessage 返回给调用方的字符串
// 都不能含 token。各夹具把请求路径回显进响应体，因此没有脱敏就一定会失败。
func TestTelegramFailureErrorsNeverContainTheBotToken(t *testing.T) {
	const token = "123456:AA_SECRET-TOKEN_value-xyz"
	const chatID = "-100999"
	for _, test := range []struct {
		name string
		// handler 与 transport 二选一：前者走真实 httptest 服务端，后者伪造传输层故障。
		handler   http.HandlerFunc
		transport roundTripFunc
	}{
		{
			name: "permanent non-2xx",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, fmt.Sprintf(`{"ok":false,"description":"%s rejected"}`, r.URL.Path))
			},
		},
		{
			name: "retryable server failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, fmt.Sprintf(`{"ok":false,"description":"%s is unavailable"}`, r.URL.Path))
			},
		},
		{
			name: "rate limited",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, fmt.Sprintf(`{"ok":false,"description":"too many requests for %s","parameters":{"retry_after":1}}`, r.URL.Path))
			},
		},
		{
			name: "invalid JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "not-json from "+r.URL.Path)
			},
		},
		{
			name: "ok=false",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, fmt.Sprintf(`{"ok":false,"description":"chat not found for %s"}`, r.URL.Path))
			},
		},
		{
			name: "oversized body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, r.URL.Path+strings.Repeat("x", maxRespBytes+1))
			},
		},
		{
			name: "transport failure",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("connection reset by peer")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &Client{Sleep: func(time.Duration) {}}
			if test.transport != nil {
				// client.Do wraps a transport error in a *url.Error holding the full endpoint.
				c.HTTP = &http.Client{Transport: test.transport}
				c.BaseURL = "https://api.telegram.test"
			} else {
				srv := httptest.NewServer(test.handler)
				defer srv.Close()
				c.HTTP = srv.Client()
				c.BaseURL = srv.URL
			}

			getMeErr := c.GetMe(context.Background(), token)
			if getMeErr == nil {
				t.Fatal("expected GetMe to fail")
			}
			assertTokenAbsent(t, "GetMe", getMeErr.Error(), token)

			sendErr := c.SendMessage(context.Background(), token, chatID, "security updates available")
			if sendErr == nil {
				t.Fatal("expected SendMessage to fail")
			}
			assertTokenAbsent(t, "SendMessage", sendErr.Error(), token)
		})
	}
}

// TestRequestConstructionSucceedsForEveryGuardedBaseAndValidToken 说明为什么请求构造分支
// 没有真实的失败夹具：GuardAPIBase 接受的 base 已经能被 url.Parse 解析，而 token 只含
// [0-9:A-Za-z_-]，拼出的路径必然仍可解析，http.NewRequestWithContext 里唯一会带上 URL 的
// 失败（url.Parse）因此不可达。哪天放宽任何一侧的校验，这个测试会先于 journal 里的 token 报警。
func TestRequestConstructionSucceedsForEveryGuardedBaseAndValidToken(t *testing.T) {
	tokens := []string{
		"1:a",
		"123456:AA_SECRET-TOKEN_value-xyz",
		"123456:" + strings.Repeat("a", 249), // 256 bytes, the length ceiling validToken allows
	}
	for _, test := range []struct {
		name string
		base string
	}{
		{name: "api host", base: "https://api.telegram.org"},
		{name: "trailing slash", base: "https://api.telegram.org/"},
		{name: "explicit port", base: "https://api.telegram.org:8443"},
		{name: "uppercase host", base: "https://API.TELEGRAM.ORG"},
		{name: "punycode host", base: "https://xn--80ak6aa92e.com"},
		{name: "loopback plaintext", base: "http://127.0.0.1:8080"},
		{name: "loopback ipv6", base: "http://[::1]:8080"},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := strings.TrimRight(test.base, "/")
			if err := httpx.GuardAPIBase(base); err != nil {
				t.Fatalf("fixture base %q is not one GuardAPIBase accepts: %v", base, err)
			}
			for _, token := range tokens {
				if !validToken(token) {
					t.Fatalf("fixture token %q is not one validToken accepts", token)
				}
				for _, endpoint := range []string{
					base + "/bot" + token + "/getMe",
					base + "/bot" + token + "/sendMessage",
				} {
					if _, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, strings.NewReader("chat_id=-100")); err != nil {
						t.Fatalf("request construction failed for a guarded endpoint: %v", err)
					}
				}
			}
		})
	}
}
