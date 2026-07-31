package releasepkg

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func writeDeterministicArchive(target, pkgDir, pkgName string, epoch int64) (err error) {
	if epoch < 0 {
		return fmt.Errorf("source-date-epoch must not be negative")
	}
	if pkgName == "" || pkgName == "." || pkgName == ".." || filepath.Base(pkgName) != pkgName {
		return fmt.Errorf("invalid package directory name %q", pkgName)
	}
	root, err := openPackageDirectory(pkgDir)
	if err != nil {
		return fmt.Errorf("open package tree: %w", err)
	}
	defer root.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()

	gz, err := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	// gzip -n compatibility: no filename and a zero header timestamp.
	gz.Header.ModTime = time.Time{}
	gz.Header.Name = ""
	gz.Header.Comment = ""
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)

	expected := expectedPackagePaths()
	paths := make([]string, 0, len(expected))
	for path := range expected {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		return filepath.ToSlash(paths[i]) < filepath.ToSlash(paths[j])
	})
	mtime := time.Unix(epoch, 0).UTC()
	var total int64
	for _, relative := range paths {
		expectedMode := expected[relative]
		wantDirectory := expectedMode&fs.ModeDir != 0
		entry, owned, err := openPackageEntry(root, relative, wantDirectory)
		if err != nil {
			return fmt.Errorf("open archive entry %q: %w", filepath.ToSlash(relative), err)
		}
		info, err := entry.Stat()
		if err != nil {
			if owned {
				_ = entry.Close()
			}
			return fmt.Errorf("inspect archive entry %q: %w", filepath.ToSlash(relative), err)
		}
		if info.Mode().Perm() != expectedMode.Perm() || info.IsDir() != wantDirectory ||
			!wantDirectory && !info.Mode().IsRegular() {
			if owned {
				_ = entry.Close()
			}
			return fmt.Errorf("archive entry %q changed type or mode", filepath.ToSlash(relative))
		}
		if !wantDirectory {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat == nil || stat.Nlink != 1 {
				if owned {
					_ = entry.Close()
				}
				return fmt.Errorf("archive entry %q must have exactly one hard link", filepath.ToSlash(relative))
			}
			if info.Size() < 0 || total > maxUncompressedSize-info.Size() {
				if owned {
					_ = entry.Close()
				}
				return fmt.Errorf("release payload exceeds %d bytes", maxUncompressedSize)
			}
			total += info.Size()
		}
		name := pkgName
		if relative != "." {
			name += "/" + filepath.ToSlash(relative)
		}
		header := &tar.Header{
			Name: name, Mode: int64(info.Mode().Perm()), Uid: 0, Gid: 0,
			ModTime: mtime, Format: tar.FormatUSTAR,
		}
		if info.IsDir() {
			header.Name += "/"
			header.Typeflag = tar.TypeDir
			header.Size = 0
		} else if info.Mode().IsRegular() {
			header.Typeflag = tar.TypeReg
			header.Size = info.Size()
		} else {
			return fmt.Errorf("unsupported archive entry %q", name)
		}
		if err := tw.WriteHeader(header); err != nil {
			if owned {
				_ = entry.Close()
			}
			return fmt.Errorf("write archive header %q: %w", name, err)
		}
		if info.Mode().IsRegular() {
			_, copyErr := io.CopyN(tw, entry, info.Size())
			if copyErr != nil {
				_ = entry.Close()
				return fmt.Errorf("write archive entry %q: %w", name, copyErr)
			}
			var extra [1]byte
			if count, readErr := entry.Read(extra[:]); count != 0 || !errors.Is(readErr, io.EOF) {
				_ = entry.Close()
				return fmt.Errorf("archive entry %q changed size while being read", name)
			}
			after, statErr := entry.Stat()
			if statErr != nil || !sameRegularMetadata(info, after) {
				_ = entry.Close()
				return fmt.Errorf("archive entry %q changed while being read", name)
			}
		}
		if owned {
			if err := entry.Close(); err != nil {
				return fmt.Errorf("close archive entry %q: %w", name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar stream: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip stream: %w", err)
	}
	if err := out.Chmod(0o644); err != nil {
		return fmt.Errorf("normalize archive mode: %w", err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync archive: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	ok = true
	return nil
}

func readArchiveRegularFile(archivePath, member string, maxSize int64) ([]byte, error) {
	if member == "" || maxSize <= 0 {
		return nil, errors.New("archive member and positive size limit are required")
	}
	f, archiveInfo, err := openBoundedRegular(archivePath, maxUncompressedSize, true)
	if err != nil {
		return nil, fmt.Errorf("open archive for member %q: %w", member, err)
	}
	defer f.Close()
	compressed := bufio.NewReader(f)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream for member %q: %w", member, err)
	}
	gz.Multistream(false)
	defer gz.Close()

	limited := &io.LimitedReader{R: gz, N: maxUncompressedSize + 1}
	tr := tar.NewReader(limited)
	var content []byte
	count := 0
	entries := 0
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive for member %q: %w", member, err)
		}
		entries++
		if entries > 10_000 {
			return nil, fmt.Errorf("archive exceeds entry limit")
		}
		if header.Name != member {
			continue
		}
		count++
		if count > 1 {
			return nil, fmt.Errorf("archive contains multiple %q members", member)
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxSize {
			return nil, fmt.Errorf("archive member %q is not a bounded regular file", member)
		}
		content, err = io.ReadAll(io.LimitReader(tr, maxSize+1))
		if err != nil {
			return nil, fmt.Errorf("read archive member %q: %w", member, err)
		}
		if int64(len(content)) != header.Size {
			return nil, fmt.Errorf("archive member %q size mismatch", member)
		}
	}
	if count != 1 {
		return nil, fmt.Errorf("archive must contain exactly one %q member", member)
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return nil, fmt.Errorf("validate archive footer for member %q: %w", member, err)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("archive exceeds uncompressed size limit")
	}
	if _, err := compressed.ReadByte(); err == nil {
		return nil, fmt.Errorf("archive contains trailing data or multiple gzip members")
	} else if err != io.EOF {
		return nil, fmt.Errorf("inspect compressed archive trailer for member %q: %w", member, err)
	}
	openedAfter, err := f.Stat()
	if err != nil || !sameRegularMetadata(archiveInfo, openedAfter) {
		return nil, fmt.Errorf("archive changed while reading member %q", member)
	}
	if err := validateOpenedRegularPath(archivePath, archiveInfo); err != nil {
		return nil, fmt.Errorf("archive path changed while reading member %q", member)
	}
	return content, nil
}

func openPackageDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create package-directory handle")
	}
	return directory, nil
}

func openPackageEntry(root *os.File, relative string, directory bool) (*os.File, bool, error) {
	if relative == "." {
		if !directory {
			return nil, false, fmt.Errorf("package root must be a directory")
		}
		return root, false, nil
	}
	if relative == "" || filepath.IsAbs(relative) {
		return nil, false, fmt.Errorf("invalid package path")
	}
	components := strings.Split(filepath.ToSlash(relative), "/")
	current := root
	owned := false
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			if owned {
				_ = current.Close()
			}
			return nil, false, fmt.Errorf("invalid package path component")
		}
		last := index == len(components)-1
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !last || directory {
			flags |= syscall.O_DIRECTORY
		} else {
			flags |= syscall.O_NONBLOCK
		}
		fd, err := syscall.Openat(int(current.Fd()), component, flags, 0)
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
			return nil, false, fmt.Errorf("create package-entry handle")
		}
		if owned {
			_ = current.Close()
		}
		current = next
		owned = true
	}
	return current, owned, nil
}
