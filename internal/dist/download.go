package dist

import (
	"fmt"
	"io"
	"net/http"
	"os"

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
