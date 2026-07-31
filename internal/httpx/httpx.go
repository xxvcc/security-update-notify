// Package httpx 提供一个加固的 HTTP 客户端，取代 Bash 的 `curl --proto '=https' --proto-redir '=https'`
// 与所有内嵌 python 的 urllib（含自定义 HTTPSOnlyRedirectHandler）：显式超时、TLS 下限、拒绝任何远程非
// https 的初始 URL，并拒绝任何非 https 的重定向跳转 / 最终 URL，禁用代理影响。仅为本机集成测试
// 保留显式的 loopback HTTP 初始请求。这是“干掉 python3 + curl”的传输底座。
//
// Package httpx provides a hardened HTTP client replacing Bash's `curl --proto '=https'
// --proto-redir '=https'` and all embedded-python urllib (incl. the custom HTTPSOnlyRedirectHandler):
// explicit timeout, a TLS floor, rejection of remote non-HTTPS initial URLs and every non-HTTPS redirect
// or final URL, with proxy influence disabled. Explicit loopback HTTP is retained only for local integration
// fixtures. This is the transport base for dropping python3 + curl.
package httpx

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type remoteHTTPSOnlyTransport struct {
	next http.RoundTripper
}

func (t remoteHTTPSOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("refusing request without a URL")
	}
	if err := guardRemoteHTTPS(req.URL); err != nil {
		return nil, err
	}
	return t.next.RoundTrip(req)
}

// New 构造一个远程 HTTPS-only 的客户端：初始请求在传输层复核，每一次重定向
// 跳转都必须是 https，最多 10 跳。loopback HTTP 仅用于本地集成测试夹具。
func New(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // 不受环境代理影响
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := GuardHTTPS(req.URL.String()); err != nil {
				return fmt.Errorf("refusing unsafe redirect: %w", err)
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
		Transport: remoteHTTPSOnlyTransport{next: transport},
	}
}

func guardRemoteHTTPS(u *url.URL) error {
	if u == nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("refusing invalid request URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if u.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing remote non-https request")
}

// GuardAPIBase accepts an HTTPS API root, plus plain HTTP only on the local loopback interface for
// deterministic integration tests. Credentials must never be sent to a remote plaintext endpoint.
func GuardAPIBase(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid API base URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("refusing non-https API base URL")
}

// NoRedirects returns a shallow copy of client that exposes redirect responses to the caller.
// API requests carry credentials, so even an HTTPS redirect must not be followed to another host.
func NoRedirects(client *http.Client) (*http.Client, error) {
	if client == nil {
		return nil, fmt.Errorf("missing HTTP client")
	}
	clone := *client
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone, nil
}

// HTTPSRedirects returns a shallow copy of client that rejects every non-HTTPS
// redirect before the redirected request is sent. It preserves a caller's
// stricter redirect policy; when none is configured it retains net/http's
// default ten-hop limit.
func HTTPSRedirects(client *http.Client) (*http.Client, error) {
	if client == nil {
		return nil, fmt.Errorf("missing HTTP client")
	}
	clone := *client
	original := client.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := GuardHTTPS(req.URL.String()); err != nil {
			return fmt.Errorf("refusing unsafe redirect: %w", err)
		}
		if original != nil {
			if err := original(req, via); err != nil {
				return err
			}
			// A CheckRedirect callback receives a mutable request. Revalidate after
			// it returns so even an accidental URL rewrite cannot downgrade the hop.
			if err := GuardHTTPS(req.URL.String()); err != nil {
				return fmt.Errorf("refusing unsafe redirect after caller policy: %w", err)
			}
			return nil
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &clone, nil
}

// GuardHTTPS requires an absolute HTTPS URL without embedded userinfo. Rejection errors deliberately
// omit the URL: url.URL.Redacted hides only passwords, while usernames and query strings can also carry
// credentials and must not be copied into logs.
func GuardHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid HTTPS URL")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("refusing invalid or non-https URL")
	}
	return nil
}
