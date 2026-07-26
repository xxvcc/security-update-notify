package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGuardHTTPS(t *testing.T) {
	if err := GuardHTTPS("https://example.com/x"); err != nil {
		t.Errorf("https should pass: %v", err)
	}
	for _, bad := range []string{"http://example.com", "ftp://x", "file:///etc/passwd"} {
		if err := GuardHTTPS(bad); err == nil {
			t.Errorf("GuardHTTPS(%q) should reject", bad)
		}
	}
}

func TestGuardAPIBase(t *testing.T) {
	for _, good := range []string{"https://api.example.com", "https://api.example.com:8443/", "http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost:8080"} {
		if err := GuardAPIBase(good); err != nil {
			t.Errorf("GuardAPIBase(%q): %v", good, err)
		}
	}
	for _, bad := range []string{"http://api.example.com", "https:///missing-host", "https://user@example.com", "https://example.com/path", "https://example.com?query=1", "file:///tmp/socket"} {
		if err := GuardAPIBase(bad); err == nil {
			t.Errorf("GuardAPIBase(%q) should reject", bad)
		}
	}
}

func TestNoRedirects(t *testing.T) {
	var redirected int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected++
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client, err := NoRedirects(source.Client())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || redirected != 0 {
		t.Fatalf("status=%d redirected=%d", resp.StatusCode, redirected)
	}
	if _, err := NoRedirects(nil); err == nil {
		t.Fatal("nil client was accepted")
	}
}

// 重定向到非 https 目标必须被拒（复刻 --proto-redir '=https' / HTTPSOnlyRedirectHandler）。
func TestRejectsNonHTTPSRedirect(t *testing.T) {
	// 一个 http 服务器 302 跳到另一个 http URL；HTTPS-only 客户端应在跳转时报错。
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound) // target.URL 是 http://
	}))
	defer redirector.Close()

	client := New(5 * time.Second)
	resp, err := client.Get(redirector.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected error on non-https redirect")
	}
}
