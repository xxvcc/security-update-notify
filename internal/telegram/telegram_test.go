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
		w.WriteHeader(503)
	})
	defer srv.Close()
	if err := c.SendMessage(context.Background(), "123:abc", "-100", "hi"); err == nil {
		t.Error("expected error after exhausting retries")
	}
	if n != 3 {
		t.Errorf("requests=%d want 3", n)
	}
	if *slept != 2 {
		t.Errorf("slept=%d want 2", *slept)
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
