package dist

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// Extract 把 tarball 安全解包到 destDir，复刻 `tar --no-same-owner --no-same-permissions -xzf`：
// 只解普通文件与目录，拒绝符号/硬链接/设备等特殊条目与路径穿越；用 Perm()(0777 掩码) 落盘从而剥离
// setuid/setgid/sticky（纵深防御，即便签名者被攻破也不落地 setuid 文件）；不 chown（归当前用户）。
// 建议调用方先用 CheckArchive 校验顶层目录，再 Extract。
func Extract(tarball, destDir string) error {
	destination, err := openRealDirectory(destDir)
	if err != nil {
		return fmt.Errorf("open extraction destination: %w", err)
	}
	defer destination.Close()
	return extractIntoDirectory(tarball, destination)
}

func extractIntoDirectory(tarball string, destination *os.File) error {
	f, _, err := openRegularInput(tarball, maxArchiveBytes)
	if err != nil {
		return fmt.Errorf("open archive for extraction: %w", err)
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
	var written int64
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
		default:
			return fmt.Errorf("unsupported archive entry type %q for %q", string(hdr.Typeflag), hdr.Name)
		}
		isDirectory := hdr.Typeflag == tar.TypeDir
		components, err := archivePathComponents(hdr.Name, isDirectory)
		if err != nil {
			return err
		}
		pathComponents += len(components)
		if pathComponents > maxArchivePathComponents {
			return fmt.Errorf("archive exceeds path-component limit (%d)", maxArchivePathComponents)
		}
		if hdr.Mode < 0 || hdr.Mode > 0o7777 {
			return fmt.Errorf("invalid archive mode %#o for %q", hdr.Mode, hdr.Name)
		}
		perm := os.FileMode(hdr.Mode).Perm() // 剥离 setuid/setgid/sticky
		if isDirectory {
			if hdr.Size != 0 {
				return fmt.Errorf("archive directory %q has non-zero size", hdr.Name)
			}
			directory, owned, err := openOrCreateExtractionDirectory(destination, components, perm)
			if owned && directory != nil {
				_ = directory.Close()
			}
			if err != nil {
				return fmt.Errorf("create archive directory %q: %w", hdr.Name, err)
			}
			continue
		}
		if hdr.Size < 0 || hdr.Size > maxArchiveBytes-written {
			return fmt.Errorf("archive exceeds size limit")
		}
		parent, owned, err := openOrCreateExtractionDirectory(destination, components[:len(components)-1], 0o755)
		if err != nil {
			return fmt.Errorf("create archive parent for %q: %w", hdr.Name, err)
		}
		// O_EXCL refuses both pre-existing files and symlinks atomically. Release
		// extraction is staged in a fresh private directory, so overwriting an
		// existing path is never required and would only widen the attack surface.
		leaf := components[len(components)-1]
		fd, err := syscall.Openat(
			int(parent.Fd()), leaf,
			syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
			uint32(perm),
		)
		if err != nil {
			if owned {
				_ = parent.Close()
			}
			return err
		}
		out := os.NewFile(uintptr(fd), leaf)
		if out == nil {
			_ = syscall.Close(fd)
			_ = syscall.Unlinkat(int(parent.Fd()), leaf)
			if owned {
				_ = parent.Close()
			}
			return fmt.Errorf("create archive output handle")
		}
		n, err := io.CopyN(out, tr, hdr.Size)
		if err == nil {
			err = out.Chmod(perm)
		}
		closeErr := out.Close()
		if err != nil {
			_ = syscall.Unlinkat(int(parent.Fd()), leaf)
			if owned {
				_ = parent.Close()
			}
			return err
		}
		if closeErr != nil {
			_ = syscall.Unlinkat(int(parent.Fd()), leaf)
			if owned {
				_ = parent.Close()
			}
			return closeErr
		}
		if owned {
			_ = parent.Close()
		}
		written += n
	}
	return finishCompressedArchive(limited, compressed)
}

func archivePathComponents(name string, directory bool) ([]string, error) {
	if name == "" || len(name) > maxArchivePathBytes || strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("invalid archive path entry %q", name)
	}
	if directory {
		name = strings.TrimSuffix(name, "/")
	} else if strings.HasSuffix(name, "/") {
		return nil, fmt.Errorf("regular archive entry has a trailing slash: %q", name)
	}
	components := strings.Split(name, "/")
	if len(components) > maxArchivePathDepth {
		return nil, fmt.Errorf("archive path exceeds depth limit (%d): %q", maxArchivePathDepth, name)
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." ||
			len(component) > maxArchiveComponentBytes || strings.IndexByte(component, 0) >= 0 {
			return nil, fmt.Errorf("non-canonical or traversing archive entry: %q", name)
		}
	}
	return components, nil
}

// openOrCreateExtractionDirectory walks only relative to the already-open root
// descriptor. Renaming destDir or replacing any pathname ancestor cannot steer
// subsequent writes outside that directory object.
func openOrCreateExtractionDirectory(root *os.File, components []string, finalMode os.FileMode) (*os.File, bool, error) {
	current := root
	owned := false
	for index, component := range components {
		mode := os.FileMode(0o755)
		if index == len(components)-1 {
			mode = finalMode
		}
		if err := syscall.Mkdirat(int(current.Fd()), component, uint32(mode.Perm())); err != nil && !errors.Is(err, syscall.EEXIST) {
			if owned {
				_ = current.Close()
			}
			return nil, false, err
		}
		fd, err := syscall.Openat(
			int(current.Fd()), component,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
			0,
		)
		if err != nil {
			if owned {
				_ = current.Close()
			}
			return nil, false, err
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = syscall.Close(fd)
			if owned {
				_ = current.Close()
			}
			return nil, false, fmt.Errorf("create extraction directory handle")
		}
		if owned {
			_ = current.Close()
		}
		current = next
		owned = true
	}
	return current, owned, nil
}
