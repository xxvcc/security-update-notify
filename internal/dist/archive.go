package dist

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// maxArchiveBytes 限制单个发布包的解压总量，防止解压炸弹。发布包实际为数十 MiB，此上限只作纵深防御。
// maxArchiveBytes bounds total decompressed bytes to defend against a decompression bomb. Real release
// packages are tens of MiB; this ceiling is purely defense in depth.
const maxArchiveBytes = 256 << 20 // 256 MiB
const maxArchiveEntries = 10_000
const maxArchivePathBytes = 4 << 10
const maxArchivePathDepth = 64
const maxArchiveComponentBytes = 255
const maxArchivePathComponents = 100_000
const legacyTarTypeReg = byte(0) // POSIX tar permits NUL as the regular-file type flag.

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
	if _, err := archivePathComponents(topDir, false); err != nil {
		return fmt.Errorf("invalid expected top directory: %w", err)
	}
	f, _, err := openRegularInput(tarball, maxArchiveBytes)
	if err != nil {
		return fmt.Errorf("open archive for inspection: %w", err)
	}
	defer f.Close()
	compressed := bufio.NewReader(f)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	gz.Multistream(false)
	defer gz.Close()

	limited := &io.LimitedReader{R: gz, N: maxArchiveBytes + 1}
	tr := tar.NewReader(limited)
	sawTop := false
	entries := 0
	pathComponents := 0
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
			// 普通文件 / 目录：允许 / regular file or directory: allowed
		default:
			return fmt.Errorf("unsupported archive entry type %q for %q", string(hdr.Typeflag), hdr.Name)
		}
		components, err := archivePathComponents(hdr.Name, hdr.Typeflag == tar.TypeDir)
		if err != nil {
			return err
		}
		pathComponents += len(components)
		if pathComponents > maxArchivePathComponents {
			return fmt.Errorf("archive exceeds path-component limit (%d)", maxArchivePathComponents)
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
	return finishCompressedArchive(limited, compressed)
}

// tar.Reader stops at the archive end blocks and can leave tar padding and the
// gzip footer unread. Only zero padding is valid after the tar end marker;
// rejecting other bytes prevents an archive from also acting as a hidden
// payload container. Draining also validates gzip CRC/ISIZE, while the buffered
// compressed reader lets us reject a concatenated member or trailing bytes.
func finishCompressedArchive(limited *io.LimitedReader, compressed *bufio.Reader) error {
	var buffer [32 << 10]byte
	for {
		n, err := limited.Read(buffer[:])
		for _, value := range buffer[:n] {
			if value != 0 {
				return fmt.Errorf("archive contains non-zero data after the tar end marker")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("validate compressed archive footer: %w", err)
		}
	}
	if limited.N == 0 {
		return fmt.Errorf("archive exceeds size limit")
	}
	if _, err := compressed.ReadByte(); err == nil {
		return fmt.Errorf("archive contains trailing data or multiple gzip members")
	} else if err != io.EOF {
		return fmt.Errorf("inspect compressed archive trailer: %w", err)
	}
	return nil
}
