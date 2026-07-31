package dist

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/version"
)

const maxReleaseJSONBytes = 1 << 20

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
	body, err := getReleaseJSON(client, url, "application/json")
	if err != nil {
		return "", err
	}
	var manifest struct {
		Version string `json:"version"`
		Tag     string `json:"tag"`
		BaseURL string `json:"base_url"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", err
	}
	if manifest.Version == "" || manifest.Tag != "v"+manifest.Version {
		return "", fmt.Errorf("mirror manifest has inconsistent version/tag")
	}
	if !validReleaseVersion(manifest.Version) {
		return "", fmt.Errorf("mirror manifest has invalid version")
	}
	if manifest.BaseURL != base+"/"+manifest.Tag {
		return "", fmt.Errorf("mirror manifest has unexpected base_url")
	}
	return manifest.Version, nil
}

func latestFromGitHub(client *http.Client, repo string) (string, error) {
	url := githubAPIBase + "/repos/" + repo + "/releases/latest"
	body, err := getReleaseJSON(client, url, "application/vnd.github+json")
	if err != nil {
		return "", err
	}
	var v struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	if !strings.HasPrefix(v.TagName, "v") {
		return "", fmt.Errorf("tag_name must have exactly one v prefix")
	}
	tag := strings.TrimPrefix(v.TagName, "v")
	if !validReleaseVersion(tag) {
		return "", fmt.Errorf("invalid tag_name")
	}
	return tag, nil
}

func validReleaseVersion(v string) bool {
	// Published asset names and tags use one canonical shape: v<version> for
	// the tag and an unprefixed, numeric release value everywhere else.
	if len(v) == 0 || len(v) > 128 || v[0] < '0' || v[0] > '9' {
		return false
	}
	for i := 1; i < len(v); i++ {
		if !isReleaseVersionAlphaNum(v[i]) && v[i] != '.' && v[i] != '_' && v[i] != '-' {
			return false
		}
	}
	_, err := version.Compare(v, v)
	return err == nil
}

func isReleaseVersionAlphaNum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func getReleaseJSON(client *http.Client, url, accept string) ([]byte, error) {
	if err := httpx.GuardHTTPS(url); err != nil {
		return nil, err
	}
	client, err := httpx.HTTPSRedirects(client)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create release metadata request failed")
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "security-update-notify")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("release metadata request failed")
	}
	if resp.Request != nil {
		if err := httpx.GuardHTTPS(resp.Request.URL.String()); err != nil { // 最终 URL 复核
			resp.Body.Close()
			return nil, err
		}
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("release metadata returned HTTP %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxReleaseJSONBytes {
		return nil, fmt.Errorf("release JSON exceeds size limit")
	}
	return body, nil
}

// ReleaseBases 返回同一已签名版本的下载根路径，按镜像优先、GitHub 回退排序。
func ReleaseBases(repo, version string) []string {
	bases := make([]string, 0, 2)
	if releaseMirrorBase != "" {
		bases = append(bases, strings.TrimRight(releaseMirrorBase, "/")+"/v"+version)
	}
	return append(bases, strings.TrimRight(githubDownloadBase, "/")+"/"+repo+"/releases/download/v"+version)
}
