package telegram

import (
	"context"
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
	c := &Client{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		Sleep:   func(time.Duration) { atomic.AddInt32(&slept, 1) },
	}
	return c, srv, &slept
}

func TestSendBadToken(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient, BaseURL: "http://x"}
	if err := c.SendMessage(context.Background(), "not-a-token", "123", "hi"); err != ErrBadToken {
		t.Errorf("err=%v want ErrBadToken", err)
	}
}

func TestSendMissingChat(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient}
	if err := c.SendMessage(context.Background(), "123:abc", "", "hi"); err == nil {
		t.Error("expected error for missing chat id")
	}
}

func TestRejectsRemotePlaintextBaseURL(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient, BaseURL: "http://api.example.com"}
	if err := c.GetMe(context.Background(), "123456:fake_TOKEN"); err == nil {
		t.Fatal("GetMe accepted a remote plaintext base URL")
	}
	if err := c.SendMessage(context.Background(), "123456:fake_TOKEN", "123", "text"); err == nil {
		t.Fatal("SendMessage accepted a remote plaintext base URL")
	}
}

func TestDoesNotFollowCredentialBearingRedirect(t *testing.T) {
	var targetRequests int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&targetRequests, 1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := &Client{HTTP: source.Client(), BaseURL: source.URL}
	if err := c.GetMe(context.Background(), "123:secret"); err == nil {
		t.Fatal("GetMe accepted a redirect")
	}
	if err := c.SendMessage(context.Background(), "123:secret", "-100", "text"); err == nil {
		t.Fatal("SendMessage accepted a redirect")
	}
	if got := atomic.LoadInt32(&targetRequests); got != 0 {
		t.Fatalf("credential-bearing redirect reached target %d times", got)
	}
}

func TestSendSuccess(t *testing.T) {
	var n int32
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		io.WriteString(w, `{"ok":true}`)
	})
	defer srv.Close()
	if err := c.SendMessage(context.Background(), "123:abc_DEF-ghi", "-100", "hi"); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("requests=%d want 1", n)
	}
}

func TestSendOKFalseNoRetry(t *testing.T) {
	var n int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		io.WriteString(w, `{"ok":false,"description":"bad chat"}`)
	})
	defer srv.Close()
	if err := c.SendMessage(context.Background(), "123:abc", "-100", "hi"); err == nil {
		t.Error("expected error on ok=false")
	} else if IsTemporary(err) {
		t.Errorf("ok=false error=%v, want permanent", err)
	}
	if n != 1 {
		t.Errorf("requests=%d want 1 (ok=false is not retried)", n)
	}
	if *slept != 0 {
		t.Errorf("slept=%d want 0", *slept)
	}
}

func TestSendRetryOn429ThenSuccess(t *testing.T) {
	var n int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(429)
			io.WriteString(w, `{"ok":false}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	})
	defer srv.Close()
	if err := c.SendMessage(context.Background(), "123:abc", "-100", "hi"); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("requests=%d want 2 (429 retried once)", n)
	}
	if *slept != 1 {
		t.Errorf("slept=%d want 1", *slept)
	}
}

func TestSend5xxExhausts(t *testing.T) {
	var n int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(520)
	})
	defer srv.Close()
	if err := c.SendMessage(context.Background(), "123:abc", "-100", "hi"); err == nil {
		t.Error("expected error after exhausting retries")
	} else if !IsTemporary(err) {
		t.Errorf("exhausted 5xx error=%v, want temporary", err)
	}
	if n != 3 {
		t.Errorf("requests=%d want 3", n)
	}
	if *slept != 2 {
		t.Errorf("slept=%d want 2", *slept)
	}
}

func TestOversizedResponseRejected(t *testing.T) {
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxRespBytes+1))
	})
	defer srv.Close()
	if err := c.GetMe(context.Background(), "123:abc"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("GetMe error=%v want too large", err)
	} else if !IsTemporary(err) {
		t.Fatalf("GetMe oversized response error=%v, want temporary", err)
	}
	if err := c.SendMessage(context.Background(), "123:abc", "-100", "hi"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("SendMessage error=%v want too large", err)
	} else if !IsTemporary(err) {
		t.Fatalf("SendMessage oversized response error=%v, want temporary", err)
	}
}

func TestSend4xxPermanent(t *testing.T) {
	var n int32
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(400)
		io.WriteString(w, `{"ok":false}`)
	})
	defer srv.Close()
	if err := c.SendMessage(context.Background(), "123:abc", "-100", "hi"); err == nil {
		t.Error("expected error on 400")
	}
	if n != 1 {
		t.Errorf("requests=%d want 1 (400 is permanent)", n)
	}
}

func TestSendRejectsNon2xxOKResponse(t *testing.T) {
	var n int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusMultipleChoices)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	defer srv.Close()
	if err := c.SendMessage(context.Background(), "123:abc", "-100", "hi"); err == nil {
		t.Fatal("3xx response with ok=true was accepted")
	}
	if n != 1 || *slept != 0 {
		t.Fatalf("requests=%d sleeps=%d want 1,0", n, *slept)
	}
}

func TestSendTruncatesOKFalseError(t *testing.T) {
	c, srv, _ := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":false,"description":"`+strings.Repeat("x", 1000)+`"}`)
	})
	defer srv.Close()
	err := c.SendMessage(context.Background(), "123:abc", "-100", "hi")
	if err == nil || len(err.Error()) > 300 {
		t.Fatalf("error length=%d err=%v", len(err.Error()), err)
	}
}

func TestSendTruncatesLongText(t *testing.T) {
	var got string
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got = r.PostForm.Get("text")
		if r.PostForm.Get("disable_web_page_preview") != "true" {
			t.Error("missing disable_web_page_preview=true")
		}
		io.WriteString(w, `{"ok":true}`)
	})
	defer srv.Close()
	long := strings.Repeat("好", 5000) // 5000 runes > 4096
	if err := c.SendMessage(context.Background(), "123:abc", "-100", long); err != nil {
		t.Fatal(err)
	}
	runes := []rune(got)
	if len(runes) != 4000+len([]rune("\n…(truncated)")) {
		t.Errorf("truncated len=%d want %d", len(runes), 4000+len([]rune("\n…(truncated)")))
	}
	if !strings.HasSuffix(got, "\n…(truncated)") {
		t.Error("missing truncation suffix")
	}
}

func TestGetMe(t *testing.T) {
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getMe") {
			io.WriteString(w, `{"ok":true,"result":{"username":"bot"}}`)
		}
	})
	defer srv.Close()
	if err := c.GetMe(context.Background(), "123:abc"); err != nil {
		t.Fatal(err)
	}
	if err := c.GetMe(context.Background(), "bad token"); err != ErrBadToken {
		t.Errorf("err=%v want ErrBadToken", err)
	}
}

func TestGetMeTemporaryClassification(t *testing.T) {
	t.Run("server failure", func(t *testing.T) {
		var requests int32
		c, srv, _ := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&requests, 1)
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		defer srv.Close()
		err := c.GetMe(context.Background(), "123:abc")
		if !IsTemporary(err) {
			t.Fatalf("error=%v, want temporary", err)
		}
		if requests != 3 {
			t.Fatalf("requests=%d, want 3", requests)
		}
	})

	t.Run("invalid response", func(t *testing.T) {
		c, srv, _ := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "not-json")
		})
		defer srv.Close()
		err := c.GetMe(context.Background(), "123:abc")
		if !IsTemporary(err) {
			t.Fatalf("error=%v, want temporary", err)
		}
	})

	t.Run("network failure", func(t *testing.T) {
		c, srv, _ := newTestClient(func(http.ResponseWriter, *http.Request) {})
		srv.Close()
		err := c.GetMe(context.Background(), "123:abc")
		if !IsTemporary(err) {
			t.Fatalf("error=%v, want temporary", err)
		}
	})

	t.Run("credential rejection", func(t *testing.T) {
		c, srv, _ := newTestClient(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		defer srv.Close()
		err := c.GetMe(context.Background(), "123:abc")
		if err == nil || IsTemporary(err) {
			t.Fatalf("error=%v temporary=%v, want permanent", err, IsTemporary(err))
		}
	})
}
