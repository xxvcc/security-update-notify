package dist

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/httpx"
)

// Download 把 url 下载到 dest（HTTPS-only，初始+最终 URL 复核，最多重试 3 次）。取代 curl/python 下载。
func Download(client *http.Client, url, dest string) error {
	if err := httpx.GuardHTTPS(url); err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := downloadOnce(client, url, dest); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// DownloadReleaseSet 从每个候选根路径下载同一版本的完整资产集合。只有传输失败才尝试下一个
// 根路径；调用方在选定一套完整资产后执行校验，校验失败不得回退，以免掩盖镜像篡改。
func DownloadReleaseSet(client *http.Client, bases []string, filename, destDir string, withSignature bool) (string, error) {
	suffixes := []string{"", ".sha256"}
	if withSignature {
		suffixes = append(suffixes, ".asc")
	}
	var lastErr error
	for _, rawBase := range bases {
		base := strings.TrimRight(rawBase, "/")
		ok := true
		for _, suffix := range suffixes {
			dest := filepath.Join(destDir, filename+suffix)
			if err := Download(client, base+"/"+filename+suffix, dest); err != nil {
				lastErr = fmt.Errorf("%s: %w", base, err)
				ok = false
				break
			}
		}
		if ok {
			return base, nil
		}
		for _, suffix := range suffixes {
			_ = os.Remove(filepath.Join(destDir, filename+suffix))
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no release download source configured")
	}
	return "", lastErr
}

func downloadOnce(client *http.Client, url, dest string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "security-update-notify")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.Request != nil {
		if err := httpx.GuardHTTPS(resp.Request.URL.String()); err != nil {
			return err
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	// 限制落盘字节数，防止（被劫持的）无上限响应体撑满 /tmp 磁盘。发布包实际仅数十 KB；
	// 与 Extract 的 maxArchiveBytes 同一纵深防御量级，超限即报错。
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return err
	}
	if n > maxArchiveBytes {
		return fmt.Errorf("download exceeds size limit (%d bytes)", maxArchiveBytes)
	}
	return f.Sync()
}
