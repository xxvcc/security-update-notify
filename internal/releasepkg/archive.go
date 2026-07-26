package releasepkg

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func writeDeterministicArchive(target, pkgDir, pkgName string, epoch int64) (err error) {
	if epoch < 0 {
		return fmt.Errorf("source-date-epoch must not be negative")
	}
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

	paths := make([]string, 0, len(expectedPackagePaths()))
	err = filepath.WalkDir(pkgDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return fmt.Errorf("list package tree: %w", err)
	}
	sort.Slice(paths, func(i, j int) bool {
		left, _ := filepath.Rel(filepath.Dir(pkgDir), paths[i])
		right, _ := filepath.Rel(filepath.Dir(pkgDir), paths[j])
		return filepath.ToSlash(left) < filepath.ToSlash(right)
	})
	mtime := time.Unix(epoch, 0).UTC()
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("stat archive entry: %w", err)
		}
		rel, err := filepath.Rel(pkgDir, path)
		if err != nil {
			return fmt.Errorf("resolve archive entry: %w", err)
		}
		name := pkgName
		if rel != "." {
			name += "/" + filepath.ToSlash(rel)
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
			return fmt.Errorf("write archive header %q: %w", name, err)
		}
		if info.Mode().IsRegular() {
			in, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open archive entry %q: %w", name, err)
			}
			_, copyErr := io.Copy(tw, in)
			closeErr := in.Close()
			if copyErr != nil {
				return fmt.Errorf("write archive entry %q: %w", name, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close archive entry %q: %w", name, closeErr)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar stream: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip stream: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		return fmt.Errorf("normalize archive mode: %w", err)
	}
	ok = true
	return nil
}
