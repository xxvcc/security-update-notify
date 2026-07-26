package feishu

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(h http.HandlerFunc) (*Client, *httptest.Server, *int32) {
	srv := httptest.NewServer(h)
	var slept int32
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, Sleep: func(time.Duration) { atomic.AddInt32(&slept, 1) }}
	return c, srv, &slept
}

func TestSendText(t *testing.T) {
	var auth string
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "secret-value") == false {
				t.Error("token request missing app secret")
			}
			io.WriteString(w, `{"code":0,"msg":"ok","tenant_access_token":"tenant-token"}`)
		case "/open-apis/im/v1/messages":
			auth = r.Header.Get("Authorization")
			if r.URL.Query().Get("receive_id_type") != "open_id" {
				t.Errorf("receive_id_type=%q", r.URL.Query().Get("receive_id_type"))
			}
			var v map[string]string
			if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
				t.Fatal(err)
			}
			if v["receive_id"] != "ou_lanny" || v["msg_type"] != "text" || !strings.Contains(v["content"], "hello") {
				t.Errorf("message payload=%v", v)
			}
			io.WriteString(w, `{"code":0,"msg":"success","data":{}}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()
	if err := c.SendText(context.Background(), "cli_app", "secret-value", "ou_lanny", "hello"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer tenant-token" {
		t.Errorf("authorization=%q", auth)
	}
}

func TestSendCard(t *testing.T) {
	var auth string
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			io.WriteString(w, `{"code":0,"msg":"ok","tenant_access_token":"tenant-token"}`)
		case "/open-apis/im/v1/messages":
			auth = r.Header.Get("Authorization")
			var envelope map[string]string
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Fatal(err)
			}
			if envelope["receive_id"] != "ou_lanny" || envelope["msg_type"] != "interactive" {
				t.Fatalf("message envelope=%v", envelope)
			}
			var card map[string]any
			if err := json.Unmarshal([]byte(envelope["content"]), &card); err != nil {
				t.Fatal(err)
			}
			if card["schema"] != "2.0" {
				t.Fatalf("card=%v", card)
			}
			io.WriteString(w, `{"code":0,"msg":"success","data":{}}`)
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()
	card := []byte(`{
  "schema": "2.0",
  "header": {"title": {"tag": "plain_text", "content": "SUN"}, "template": "green"},
  "body": {"elements": []}
}`)
	if err := c.SendCard(context.Background(), "cli_app", "secret-value", "ou_lanny", card); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer tenant-token" {
		t.Errorf("authorization=%q", auth)
	}
}

func TestSendCardRejectsInvalidOrOversizedCardBeforeAuth(t *testing.T) {
	var requests int32
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()
	for name, tt := range map[string]struct {
		card    []byte
		wantErr string
	}{
		"invalid JSON": {card: []byte(`{"schema":`), wantErr: "invalid Feishu card JSON"},
		"wrong schema": {card: []byte(`{"schema":"1.0"}`), wantErr: "Feishu card schema must be 2.0"},
		"oversized":    {card: []byte(`{"schema":"2.0","body":{"content":"` + strings.Repeat("x", 31*1024) + `"}}`), wantErr: "Feishu card request exceeds 30 KB"},
	} {
		t.Run(name, func(t *testing.T) {
			err := c.SendCard(context.Background(), "cli_app", "secret-value", "ou_lanny", tt.card)
			if err == nil || err.Error() != tt.wantErr || !IsCardPreflightError(err) {
				t.Fatalf("error=%v want local preflight error %q", err, tt.wantErr)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("network requests=%d, want 0", requests)
	}
}

func TestProbeDoesNotSend(t *testing.T) {
	var paths []string
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		io.WriteString(w, `{"code":0,"tenant_access_token":"t"}`)
	})
	defer srv.Close()
	if err := c.Probe(context.Background(), "cli_app", "secret"); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/open-apis/auth/v3/tenant_access_token/internal" {
		t.Errorf("paths=%v", paths)
	}
}

func TestRetryOn429(t *testing.T) {
	var n int32
	var delay time.Duration
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(429)
			io.WriteString(w, `{"code":999}`)
			return
		}
		io.WriteString(w, `{"code":0,"tenant_access_token":"t"}`)
	})
	c.Sleep = func(d time.Duration) {
		delay = d
		atomic.AddInt32(slept, 1)
	}
	defer srv.Close()
	if err := c.Probe(context.Background(), "cli_app", "secret"); err != nil {
		t.Fatal(err)
	}
	if n != 2 || *slept != 1 {
		t.Errorf("requests=%d slept=%d want 2,1", n, *slept)
	}
	if delay != 2*time.Second {
		t.Errorf("retry delay=%v want 2s", delay)
	}
}

func TestRetryOnAny5xx(t *testing.T) {
	var n int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(520)
			_, _ = io.WriteString(w, `{"code":999}`)
			return
		}
		_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"t"}`)
	})
	defer srv.Close()
	if err := c.Probe(context.Background(), "cli_app", "secret"); err != nil {
		t.Fatal(err)
	}
	if n != 2 || *slept != 1 {
		t.Errorf("requests=%d slept=%d want 2,1", n, *slept)
	}
}

func TestMissingOrNullBusinessCodeIsTemporary(t *testing.T) {
	for _, codeField := range []string{"", `"code":null,`} {
		name := "missing"
		if codeField != "" {
			name = "null"
		}
		t.Run("token-"+name, func(t *testing.T) {
			c, srv, slept := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{`+codeField+`"tenant_access_token":"tenant-token"}`)
			})
			defer srv.Close()
			err := c.Probe(context.Background(), "cli_app", "secret")
			if err == nil || !IsTemporary(err) {
				t.Fatalf("error=%v, want temporary malformed-response failure", err)
			}
			if *slept != 0 {
				t.Fatalf("malformed token response was retried %d times", *slept)
			}
		})

		t.Run("message-"+name, func(t *testing.T) {
			requests := 0
			c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if strings.Contains(r.URL.Path, "tenant_access_token") {
					_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"tenant-token"}`)
					return
				}
				_, _ = io.WriteString(w, `{`+codeField+`"msg":"success"}`)
			})
			defer srv.Close()
			err := c.SendText(context.Background(), "cli_app", "secret", "ou_lanny", "hello")
			if err == nil || !IsTemporary(err) {
				t.Fatalf("error=%v, want temporary malformed-response failure", err)
			}
			if requests != 2 || *slept != 0 {
				t.Fatalf("requests=%d sleeps=%d want 2,0", requests, *slept)
			}
		})
	}
}

func TestRetryOnFeishuBusinessRateLimit(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		var requests int32
		c, srv, slept := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
			if atomic.AddInt32(&requests, 1) == 1 {
				_, _ = io.WriteString(w, `{"code":99991400}`)
				return
			}
			_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"tenant-token"}`)
		})
		defer srv.Close()
		if err := c.Probe(context.Background(), "cli_app", "secret"); err != nil {
			t.Fatal(err)
		}
		if requests != 2 || *slept != 1 {
			t.Fatalf("requests=%d sleeps=%d want 2,1", requests, *slept)
		}
	})

	t.Run("message", func(t *testing.T) {
		var messages int32
		c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "tenant_access_token") {
				_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"tenant-token"}`)
				return
			}
			if atomic.AddInt32(&messages, 1) == 1 {
				_, _ = io.WriteString(w, `{"code":99991400}`)
				return
			}
			_, _ = io.WriteString(w, `{"code":0}`)
		})
		defer srv.Close()
		if err := c.SendText(context.Background(), "cli_app", "secret", "ou_lanny", "hello"); err != nil {
			t.Fatal(err)
		}
		if messages != 2 || *slept != 1 {
			t.Fatalf("messages=%d sleeps=%d want 2,1", messages, *slept)
		}
	})
}

func TestPermanentAPIErrorIsNotRetriedOrLeaked(t *testing.T) {
	var n int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(400)
		io.WriteString(w, `{"code":10003,"msg":"top-secret"}`)
	})
	defer srv.Close()
	err := c.Probe(context.Background(), "cli_app", "top-secret")
	if err == nil {
		t.Fatal("expected error")
	}
	if IsTemporary(err) {
		t.Fatalf("permanent credential error was classified temporary: %v", err)
	}
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatal("app secret leaked in error")
	}
	if n != 1 || *slept != 0 {
		t.Errorf("requests=%d slept=%d want 1,0", n, *slept)
	}
}

func TestExhaustedServerFailureIsTemporary(t *testing.T) {
	var requests int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"code":999}`)
	})
	defer srv.Close()
	err := c.Probe(context.Background(), "cli_app", "secret")
	if err == nil || !IsTemporary(err) {
		t.Fatalf("error=%v, want temporary", err)
	}
	if requests != 3 || *slept != 2 {
		t.Fatalf("requests=%d sleeps=%d, want 3,2", requests, *slept)
	}
}

func TestRetryDelayHonorsContext(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"code":99991400}`)
	}))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := c.Probe(ctx, "cli_app", "secret")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !IsTemporary(err) {
		t.Fatalf("error=%v, want temporary context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("context cancellation took %s", elapsed)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("requests=%d, want 1 before cancellation", got)
	}
}

func TestMissingReceiveID(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient}
	if err := c.SendText(context.Background(), "a", "s", "", "text"); err == nil {
		t.Fatal("expected missing receive id")
	}
}

func TestRejectsRemotePlaintextBaseURL(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient, BaseURL: "http://api.example.com"}
	if err := c.Probe(context.Background(), "cli_app", "secret"); err == nil {
		t.Fatal("Probe accepted a remote plaintext base URL")
	}
}

func TestDoesNotFollowCredentialBearingRedirect(t *testing.T) {
	var targetRequests int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&targetRequests, 1)
		_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"stolen"}`)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := &Client{HTTP: source.Client(), BaseURL: source.URL}
	if err := c.Probe(context.Background(), "cli_test", "secret"); err == nil {
		t.Fatal("Probe accepted a redirect")
	}
	if got := atomic.LoadInt32(&targetRequests); got != 0 {
		t.Fatalf("credential-bearing redirect reached target %d times", got)
	}
}

func TestRejectsNon2xxSuccessPayloads(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		c, srv, slept := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusMultipleChoices)
			_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"tenant-token"}`)
		})
		defer srv.Close()
		if err := c.Probe(context.Background(), "cli_test", "secret"); err == nil {
			t.Fatal("3xx token response was accepted")
		}
		if *slept != 0 {
			t.Fatalf("3xx response was retried %d times", *slept)
		}
	})

	t.Run("message", func(t *testing.T) {
		requests := 0
		c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if strings.Contains(r.URL.Path, "tenant_access_token") {
				_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"tenant-token"}`)
				return
			}
			w.WriteHeader(http.StatusMultipleChoices)
			_, _ = io.WriteString(w, `{"code":0}`)
		})
		defer srv.Close()
		if err := c.SendText(context.Background(), "cli_test", "secret", "ou_lanny", "text"); err == nil {
			t.Fatal("3xx message response was accepted")
		}
		if requests != 2 || *slept != 0 {
			t.Fatalf("requests=%d sleeps=%d want 2,0", requests, *slept)
		}
	})
}

func TestNonOpenIDRejected(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient}
	for _, receiveID := range []string{"user_id", "ou_", "ou_bad/value", "ou_bad value"} {
		if err := c.SendText(context.Background(), "a", "s", receiveID, "text"); err == nil {
			t.Fatalf("expected invalid recipient %q to be rejected", receiveID)
		}
	}
}

func TestTextTruncationMatchesBashFallback(t *testing.T) {
	exact := strings.Repeat("界", maxTextRunes)
	if got := truncateText(exact); got != exact {
		t.Fatal("text at the limit was truncated")
	}
	over := exact + "界"
	want := strings.Repeat("界", truncatedTextRunes) + truncationSuffix
	if got := truncateText(over); got != want {
		t.Fatalf("truncated text has %d runes, want %d", len([]rune(got)), len([]rune(want)))
	}
}

func TestOversizedTokenResponseRejected(t *testing.T) {
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", maxRespBytes+1))
	})
	defer srv.Close()
	if err := c.Probe(context.Background(), "cli_app", "secret"); err == nil || !strings.Contains(err.Error(), "too large") || !IsTemporary(err) {
		t.Fatalf("error=%v want too large", err)
	}
}
