package dist

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/httpx"
)

// DefaultReleaseMirrorBase 是发布镜像的固定 HTTPS 根路径。镜像只改善可用性，不是信任根；
// 下载后的发布包仍必须通过内置公钥和固定指纹验签。
const DefaultReleaseMirrorBase = "https://dl.ll.cd/security-update-notify"

// 这些变量仅供同包测试覆盖；生产值固定为 HTTPS 地址。
var (
	releaseMirrorBase  = DefaultReleaseMirrorBase
	githubAPIBase      = "https://api.github.com"
	githubDownloadBase = "https://github.com"
)

// LatestRelease 先读取镜像 latest.json，镜像传输或格式失败时再请求 GitHub releases/latest。
// 镜像 manifest 的 base_url 必须等于固定镜像根路径派生值，不能把客户端下载重定向到任意主机。
func LatestRelease(client *http.Client, repo string) (string, error) {
	var mirrorErr error
	if releaseMirrorBase != "" {
		if version, err := latestFromMirror(client); err == nil {
			return version, nil
		} else {
			mirrorErr = err
		}
	}
	version, err := latestFromGitHub(client, repo)
	if err != nil && mirrorErr != nil {
		return "", fmt.Errorf("release mirror: %v; GitHub: %w", mirrorErr, err)
	}
	return version, err
}

func latestFromMirror(client *http.Client) (string, error) {
	base := strings.TrimRight(releaseMirrorBase, "/")
	url := base + "/latest.json"
	resp, err := getReleaseJSON(client, url, "application/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var manifest struct {
		Version string `json:"version"`
		Tag     string `json:"tag"`
		BaseURL string `json:"base_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return "", err
	}
	if manifest.Version == "" || manifest.Tag != "v"+manifest.Version {
		return "", fmt.Errorf("mirror manifest has inconsistent version/tag")
	}
	if manifest.BaseURL != base+"/"+manifest.Tag {
		return "", fmt.Errorf("mirror manifest has unexpected base_url")
	}
	return manifest.Version, nil
}

func latestFromGitHub(client *http.Client, repo string) (string, error) {
	url := githubAPIBase + "/repos/" + repo + "/releases/latest"
	resp, err := getReleaseJSON(client, url, "application/vnd.github+json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
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

func getReleaseJSON(client *http.Client, url, accept string) (*http.Response, error) {
	if err := httpx.GuardHTTPS(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "security-update-notify")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Request != nil {
		if err := httpx.GuardHTTPS(resp.Request.URL.String()); err != nil { // 最终 URL 复核
			resp.Body.Close()
			return nil, err
		}
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	return resp, nil
}

// ReleaseBases 返回同一已签名版本的下载根路径，按镜像优先、GitHub 回退排序。
func ReleaseBases(repo, version string) []string {
	bases := make([]string, 0, 2)
	if releaseMirrorBase != "" {
		bases = append(bases, strings.TrimRight(releaseMirrorBase, "/")+"/v"+version)
	}
	return append(bases, strings.TrimRight(githubDownloadBase, "/")+"/"+repo+"/releases/download/v"+version)
}
