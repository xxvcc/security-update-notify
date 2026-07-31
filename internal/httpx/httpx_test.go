package httpx

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGuardHTTPS(t *testing.T) {
	if err := GuardHTTPS("https://example.com/x?cache=1"); err != nil {
		t.Errorf("https should pass: %v", err)
	}
	for _, bad := range []string{
		"http://example.com", "ftp://x", "file:///etc/passwd", "https:///missing-host",
		"https:opaque", "https://user-token:secret@example.com/path",
	} {
		if err := GuardHTTPS(bad); err == nil {
			t.Errorf("GuardHTTPS(%q) should reject", bad)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user-token") {
			t.Errorf("GuardHTTPS(%q) leaked URL credentials: %v", bad, err)
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

func TestNewRejectsInitialRemotePlaintextRequestAtTransport(t *testing.T) {
	client := New(5 * time.Second)
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/path?secret=value", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Transport.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "remote non-https") {
		t.Fatalf("remote plaintext request error=%v", err)
	}
}

func TestNewAllowsInitialLoopbackHTTPForIntegrationFixtures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	client := New(5 * time.Second)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "ok" {
		t.Fatalf("loopback response=%q err=%v", body, err)
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

func TestHTTPSRedirectsRejectsPlaintextHopAndPreservesCallerPolicy(t *testing.T) {
	t.Run("plaintext hop", func(t *testing.T) {
		var plaintextRequests int
		var tlsServer *httptest.Server
		plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plaintextRequests++
			http.Redirect(w, r, tlsServer.URL+"/final", http.StatusFound)
		}))
		defer plaintext.Close()
		tlsServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/start" {
				http.Redirect(w, r, plaintext.URL+"/middle", http.StatusFound)
				return
			}
			_, _ = io.WriteString(w, "final")
		}))
		defer tlsServer.Close()

		client, err := HTTPSRedirects(tlsServer.Client())
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Get(tlsServer.URL + "/start")
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatal("HTTPS to HTTP redirect was followed")
		}
		if plaintextRequests != 0 {
			t.Fatalf("plaintext endpoint received %d requests", plaintextRequests)
		}
	})

	t.Run("caller policy", func(t *testing.T) {
		want := errors.New("caller rejected redirect")
		base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return want }}
		client, err := HTTPSRedirects(base)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://example.test/next", nil)
		if err := client.CheckRedirect(req, []*http.Request{{}}); !errors.Is(err, want) {
			t.Fatalf("redirect error=%v, want caller policy", err)
		}
	})

	t.Run("caller policy cannot rewrite to plaintext", func(t *testing.T) {
		base := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			req.URL.Scheme = "http"
			return nil
		}}
		client, err := HTTPSRedirects(base)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://example.test/next", nil)
		if err := client.CheckRedirect(req, []*http.Request{{}}); err == nil {
			t.Fatal("caller redirect policy rewrote an HTTPS hop to plaintext")
		}
	})

	t.Run("userinfo redirect is rejected without leaking credentials", func(t *testing.T) {
		client, err := HTTPSRedirects(&http.Client{})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://user-token:secret@example.test/next", nil)
		err = client.CheckRedirect(req, []*http.Request{{}})
		if err == nil {
			t.Fatal("redirect containing userinfo was accepted")
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user-token") {
			t.Fatalf("redirect rejection leaked credentials: %v", err)
		}
	})

	if _, err := HTTPSRedirects(nil); err == nil {
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
