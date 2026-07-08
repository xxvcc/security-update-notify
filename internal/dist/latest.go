package dist

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/httpx"
)

// LatestRelease 复刻 latest_release_version：请求 GitHub releases/latest，取 tag_name 并去掉一个前导 v。
// 强制 HTTPS-only（初始 URL、最终 URL），取代运行时内嵌 python 的 GitHub API 调用。
//
// githubAPIBase 是 GitHub API 基址；仅供测试覆盖（生产恒为官方 https 地址）。
var githubAPIBase = "https://api.github.com"

// LatestRelease reproduces latest_release_version: GET GitHub releases/latest, take tag_name, strip one
// leading v. HTTPS-only (initial + final URL), replacing the runtime's embedded-python GitHub API call.
func LatestRelease(client *http.Client, repo string) (string, error) {
	url := githubAPIBase + "/repos/" + repo + "/releases/latest"
	if err := httpx.GuardHTTPS(url); err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "security-update-notify")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.Request != nil {
		if err := httpx.GuardHTTPS(resp.Request.URL.String()); err != nil { // 最终 URL 复核
			return "", err
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	var v struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	tag := strings.TrimPrefix(v.TagName, "v")
	if tag == "" {
		return "", fmt.Errorf("empty tag_name")
	}
	return tag, nil
}
