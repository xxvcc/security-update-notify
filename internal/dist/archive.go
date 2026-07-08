package dist

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

// maxArchiveBytes 限制单个发布包的解压总量，防止解压炸弹。发布包实际仅数十 KB，此上限只作纵深防御。
// maxArchiveBytes bounds total decompressed bytes to defend against a decompression bomb. Real release
// packages are tens of KB; this ceiling is purely defense in depth.
const maxArchiveBytes = 256 << 20 // 256 MiB

// CheckArchive 复刻 safe_release_archive：只允许普通文件与目录，拒绝符号链接 / 硬链接 / 设备 /
// FIFO 等特殊条目，拒绝路径穿越；所有条目必须落在 topDir 之内。用类型安全的 tar.Header.Typeflag
// 取代 Bash 里对 `tar -tzvf` 装饰性列表取首字符的脆弱判断。
//
// 与 Bash 一致地对“原始条目名”做前缀匹配（不先 path.Clean）：一个 `./topDir/...` 形式的名字在
// Bash 的 `case "$topdir"/*` 下会被拒绝，Go 若先 Clean 成 `topDir/...` 反而会误放行——故此处
// 直接按原始名匹配以保持等价，并额外显式拒绝任何 `..` 穿越段（fail-closed，比 Bash 更严）。
//
// CheckArchive reproduces safe_release_archive: only regular files and directories are allowed; symlinks,
// hardlinks, devices, FIFOs and path traversal are rejected; every entry must live under topDir. It
// matches the RAW entry name (without path.Clean) exactly like the Bash glob, so a `./topDir/...` name is
// rejected the same way (path.Clean would wrongly normalize it to `topDir/...`), and it additionally
// rejects any `..` segment explicitly (fail-closed, stricter than Bash).
func CheckArchive(tarball, topDir string) error {
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

	tr := tar.NewReader(io.LimitReader(gz, maxArchiveBytes))
	sawTop := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
			// 普通文件 / 目录：允许 / regular file or directory: allowed
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
		if name == topDir || name == topDir+"/" || strings.HasPrefix(name, topDir+"/") {
			sawTop = true
		} else {
			return fmt.Errorf("entry outside top dir %q: %q", topDir, hdr.Name)
		}
	}
	if !sawTop {
		return fmt.Errorf("archive has no entries under top dir %q", topDir)
	}
	return nil
}
