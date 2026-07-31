package dist

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xxvcc/security-update-notify/internal/httpx"
)

const maxReleaseMetadataBytes = 1 << 20

// Download 把 url 下载到 dest（HTTPS-only，初始+最终 URL 复核，最多重试 3 次）。取代 curl/python 下载。
func Download(client *http.Client, url, dest string) error {
	return downloadWithLimit(client, url, dest, maxArchiveBytes)
}

func downloadWithLimit(client *http.Client, url, dest string, maxBytes int64) error {
	cleanDest := filepath.Clean(dest)
	if dest == "" || cleanDest != dest {
		return fmt.Errorf("invalid download destination")
	}
	destination := filepath.Base(cleanDest)
	if destination == "." || destination == string(filepath.Separator) {
		return fmt.Errorf("invalid download destination")
	}
	directory, err := openRealDirectory(filepath.Dir(cleanDest))
	if err != nil {
		return fmt.Errorf("open download destination directory: %w", err)
	}
	defer directory.Close()
	temporary, err := downloadToTempWithLimit(client, url, directory, maxBytes)
	if err != nil {
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), destination); err != nil {
		_ = syscall.Unlinkat(int(directory.Fd()), temporary)
		return err
	}
	return nil
}

func downloadToTempWithLimit(client *http.Client, url string, directory *os.File, maxBytes int64) (string, error) {
	if err := httpx.GuardHTTPS(url); err != nil {
		return "", err
	}
	client, err := httpx.HTTPSRedirects(client)
	if err != nil {
		return "", err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		temporary, err := downloadOnceToTemp(client, url, directory, maxBytes)
		if err != nil {
			lastErr = err
			continue
		}
		return temporary, nil
	}
	return "", lastErr
}

// DownloadReleaseSet 从每个候选根路径下载同一版本的完整资产集合。只有传输失败才尝试下一个
// 根路径；调用方在选定一套完整资产后执行校验，校验失败不得回退，以免掩盖镜像篡改。
func DownloadReleaseSet(client *http.Client, bases []string, filename, destDir string, withSignature bool) (string, error) {
	if filename == "" || filename == "." || filename == ".." || filepath.Base(filename) != filename || strings.Contains(filename, `\`) {
		return "", fmt.Errorf("invalid release asset filename %q", filename)
	}
	directory, err := openRealDirectory(destDir)
	if err != nil {
		return "", fmt.Errorf("open release destination: %w", err)
	}
	defer directory.Close()
	suffixes := []string{"", ".sha256"}
	if withSignature {
		suffixes = append(suffixes, ".asc")
	}
	var lastErr error
	for sourceIndex, rawBase := range bases {
		base := strings.TrimRight(rawBase, "/")
		ok := true
		staged := make([][2]string, 0, len(suffixes))
		for _, suffix := range suffixes {
			limit := int64(maxArchiveBytes)
			if suffix != "" {
				limit = maxReleaseMetadataBytes
			}
			temporary, err := downloadToTempWithLimit(client, base+"/"+filename+suffix, directory, limit)
			if err != nil {
				lastErr = fmt.Errorf("release source %d: %w", sourceIndex+1, err)
				ok = false
				break
			}
			staged = append(staged, [2]string{temporary, filename + suffix})
		}
		if ok {
			if err := commitDownloadedSet(directory, staged); err != nil {
				for _, pair := range staged {
					_ = syscall.Unlinkat(int(directory.Fd()), pair[0])
				}
				return "", fmt.Errorf("commit downloaded release set: %w", err)
			}
			return base, nil
		}
		for _, pair := range staged {
			_ = syscall.Unlinkat(int(directory.Fd()), pair[0])
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no release download source configured")
	}
	return "", lastErr
}

func downloadOnceToTemp(client *http.Client, url string, directory *os.File, maxBytes int64) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create download request failed")
	}
	req.Header.Set("User-Agent", "security-update-notify")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request failed")
	}
	defer resp.Body.Close()
	if resp.Request != nil {
		if err := httpx.GuardHTTPS(resp.Request.URL.String()); err != nil {
			return "", err
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	if maxBytes < 1 {
		return "", fmt.Errorf("invalid download size limit")
	}
	f, temporary, err := createPrivateTempFileAt(directory, ".download-")
	if err != nil {
		return "", err
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = syscall.Unlinkat(int(directory.Fd()), temporary)
		}
	}()
	// 限制落盘字节数，防止（被劫持的）无上限响应体撑满 /tmp 磁盘。发布包实际为数十 MiB；
	// 与 Extract 的 maxArchiveBytes 同一纵深防御量级，超限即报错。
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBytes {
		return "", fmt.Errorf("download exceeds size limit (%d bytes)", maxBytes)
	}
	// Keep metadata changes bound to the already-open temporary file. A
	// pathname chmod after Close would create an avoidable replacement window
	// when this reusable helper is called with a non-private destination.
	if err := f.Chmod(0o600); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	complete = true
	return temporary, nil
}

func commitDownloadedSet(directory *os.File, staged [][2]string) (returnErr error) {
	type backup struct{ temporary, destination string }
	backups := make([]backup, 0, len(staged))
	committed := make([]string, 0, len(staged))
	rollback := func(cause error) error {
		errs := []error{cause}
		for i := len(committed) - 1; i >= 0; i-- {
			if err := syscall.Unlinkat(int(directory.Fd()), committed[i]); err != nil && err != syscall.ENOENT {
				errs = append(errs, fmt.Errorf("remove partial download %q: %w", committed[i], err))
			}
		}
		for i := len(backups) - 1; i >= 0; i-- {
			if err := syscall.Renameat(int(directory.Fd()), backups[i].temporary, int(directory.Fd()), backups[i].destination); err != nil {
				errs = append(errs, fmt.Errorf("restore previous download %q: %w", backups[i].destination, err))
			}
		}
		return errors.Join(errs...)
	}
	for _, pair := range staged {
		placeholder, backupName, err := createPrivateTempFileAt(directory, ".download-backup-")
		if err != nil {
			return rollback(err)
		}
		if err := placeholder.Close(); err != nil {
			_ = syscall.Unlinkat(int(directory.Fd()), backupName)
			return rollback(err)
		}
		// Rename the destination directly onto a reserved name. ENOENT now comes
		// from the directory-relative syscall itself, so this transaction does not
		// depend on /proc/self/fd pathname inspection or a racy preflight stat.
		if err := syscall.Renameat(int(directory.Fd()), pair[1], int(directory.Fd()), backupName); errors.Is(err, syscall.ENOENT) {
			if cleanupErr := syscall.Unlinkat(int(directory.Fd()), backupName); cleanupErr != nil && !errors.Is(cleanupErr, syscall.ENOENT) {
				return rollback(fmt.Errorf("remove unused download backup %q: %w", backupName, cleanupErr))
			}
			continue
		} else if err != nil {
			_ = syscall.Unlinkat(int(directory.Fd()), backupName)
			return rollback(fmt.Errorf("back up previous download %q: %w", pair[1], err))
		}
		backups = append(backups, backup{backupName, pair[1]})
		fd, err := syscall.Openat(
			int(directory.Fd()), backupName,
			syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
			0,
		)
		if err != nil {
			return rollback(fmt.Errorf("inspect previous download %q: %w", pair[1], err))
		}
		previous := os.NewFile(uintptr(fd), backupName)
		if previous == nil {
			_ = syscall.Close(fd)
			return rollback(fmt.Errorf("inspect previous download %q: create file handle", pair[1]))
		}
		info, statErr := previous.Stat()
		closeErr := previous.Close()
		if statErr != nil {
			return rollback(fmt.Errorf("inspect previous download %q: %w", pair[1], statErr))
		}
		if closeErr != nil {
			return rollback(fmt.Errorf("close previous download %q: %w", pair[1], closeErr))
		}
		if !info.Mode().IsRegular() {
			return rollback(fmt.Errorf("previous download %q is not a regular file", pair[1]))
		}
	}
	for _, pair := range staged {
		if err := syscall.Renameat(int(directory.Fd()), pair[0], int(directory.Fd()), pair[1]); err != nil {
			return rollback(fmt.Errorf("commit download %q: %w", pair[1], err))
		}
		committed = append(committed, pair[1])
	}
	for _, backup := range backups {
		if err := syscall.Unlinkat(int(directory.Fd()), backup.temporary); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove download backup %q: %w", backup.temporary, err))
		}
	}
	return returnErr
}
