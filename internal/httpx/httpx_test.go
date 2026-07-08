package httpx

import (
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
