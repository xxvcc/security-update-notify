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

const maxReleaseMetadataBytes = 1 << 20

// Download 把 url 下载到 dest（HTTPS-only，初始+最终 URL 复核，最多重试 3 次）。取代 curl/python 下载。
func Download(client *http.Client, url, dest string) error {
	return downloadWithLimit(client, url, dest, maxArchiveBytes)
}

func downloadWithLimit(client *http.Client, url, dest string, maxBytes int64) error {
	if err := httpx.GuardHTTPS(url); err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := downloadOnce(client, url, dest, maxBytes); err != nil {
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
	if filename == "" || filename == "." || filename == ".." || filepath.Base(filename) != filename || strings.Contains(filename, `\`) {
		return "", fmt.Errorf("invalid release asset filename %q", filename)
	}
	destInfo, err := os.Lstat(destDir)
	if err != nil {
		return "", fmt.Errorf("inspect release destination: %w", err)
	}
	if !destInfo.IsDir() || destInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("release destination must be a real directory")
	}
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
			limit := int64(maxArchiveBytes)
			if suffix != "" {
				limit = maxReleaseMetadataBytes
			}
			if err := downloadWithLimit(client, base+"/"+filename+suffix, dest, limit); err != nil {
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

func downloadOnce(client *http.Client, url, dest string, maxBytes int64) error {
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
	if maxBytes < 1 {
		return fmt.Errorf("invalid download size limit")
	}
	f, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	// 限制落盘字节数，防止（被劫持的）无上限响应体撑满 /tmp 磁盘。发布包实际仅数十 KB；
	// 与 Extract 的 maxArchiveBytes 同一纵深防御量级，超限即报错。
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if n > maxBytes {
		return fmt.Errorf("download exceeds size limit (%d bytes)", maxBytes)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	committed = true
	return nil
}
