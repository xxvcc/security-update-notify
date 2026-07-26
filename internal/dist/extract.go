package dist

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extract 把 tarball 安全解包到 destDir，复刻 `tar --no-same-owner --no-same-permissions -xzf`：
// 只解普通文件与目录，拒绝符号/硬链接/设备等特殊条目与路径穿越；用 Perm()(0777 掩码) 落盘从而剥离
// setuid/setgid/sticky（纵深防御，即便签名者被攻破也不落地 setuid 文件）；不 chown（归当前用户）。
// 建议调用方先用 CheckArchive 校验顶层目录，再 Extract。
func Extract(tarball, destDir string) error {
	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	limited := &io.LimitedReader{R: gz, N: maxArchiveBytes + 1}
	tr := tar.NewReader(limited)
	var written int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxArchiveEntries {
			return fmt.Errorf("archive exceeds entry limit (%d)", maxArchiveEntries)
		}
		switch hdr.Typeflag {
		case tar.TypeReg, legacyTarTypeReg, tar.TypeDir:
		default:
			return fmt.Errorf("unsupported archive entry type %q for %q", string(hdr.Typeflag), hdr.Name)
		}
		name := hdr.Name
		if strings.HasPrefix(name, "/") {
			return fmt.Errorf("absolute path entry: %q", hdr.Name)
		}
		if name == ".." || strings.HasPrefix(name, "../") ||
			strings.Contains(name, "/../") || strings.HasSuffix(name, "/..") {
			return fmt.Errorf("path traversal entry: %q", hdr.Name)
		}
		target := filepath.Join(destDir, name)
		// 二次防护：解析后必须仍在 destDir 之内。
		if target != destDir && !strings.HasPrefix(target, destDir+string(os.PathSeparator)) {
			return fmt.Errorf("entry escapes destination: %q", hdr.Name)
		}
		if hdr.Mode < 0 || hdr.Mode > 0o7777 {
			return fmt.Errorf("invalid archive mode %#o for %q", hdr.Mode, hdr.Name)
		}
		perm := os.FileMode(hdr.Mode).Perm() // 剥离 setuid/setgid/sticky
		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, perm); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if hdr.Size < 0 || hdr.Size > maxArchiveBytes-written {
			return fmt.Errorf("archive exceeds size limit")
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
		if err != nil {
			return err
		}
		n, err := io.CopyN(out, tr, hdr.Size)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		written += n
		if err := os.Chmod(target, perm); err != nil {
			return err
		}
	}
	if limited.N == 0 {
		return fmt.Errorf("archive exceeds size limit")
	}
	return nil
}
