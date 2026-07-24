package feishu

import (
	"context"
	"encoding/json"
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
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatal("app secret leaked in error")
	}
	if n != 1 || *slept != 0 {
		t.Errorf("requests=%d slept=%d want 1,0", n, *slept)
	}
}

func TestMissingReceiveID(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient}
	if err := c.SendText(context.Background(), "a", "s", "", "text"); err == nil {
		t.Fatal("expected missing receive id")
	}
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
	if err := c.Probe(context.Background(), "cli_app", "secret"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error=%v want too large", err)
	}
}
