// Package httpx 提供一个加固的 HTTP 客户端，取代 Bash 的 `curl --proto '=https' --proto-redir '=https'`
// 与所有内嵌 python 的 urllib（含自定义 HTTPSOnlyRedirectHandler）：显式超时、TLS 下限、拒绝任何非
// https 的初始 URL / 重定向跳转 / 最终 URL，禁用代理影响。这是“干掉 python3 + curl”的传输底座。
//
// Package httpx provides a hardened HTTP client replacing Bash's `curl --proto '=https'
// --proto-redir '=https'` and all embedded-python urllib (incl. the custom HTTPSOnlyRedirectHandler):
// explicit timeout, a TLS floor, and rejection of any non-https initial URL / redirect hop / final URL,
// with proxy influence disabled. This is the transport base for dropping python3 + curl.
package httpx

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// New 构造一个 HTTPS-only 的客户端：每一次重定向跳转都必须是 https，最多 10 跳。
func New(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing non-https redirect to %s", req.URL.Redacted())
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy:           nil, // 不受环境代理影响
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// GuardHTTPS 校验一个 URL 的 scheme 必须是 https（用于初始 URL 与最终 URL 的复核）。
func GuardHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https URL: %s", raw)
	}
	return nil
}
