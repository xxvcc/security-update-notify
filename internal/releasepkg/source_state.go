package releasepkg

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type releaseSourceState struct {
	repository  repositoryState
	fingerprint [sha256.Size]byte
}

func captureReleaseSourceState(ctx context.Context, root, version string) (releaseSourceState, error) {
	repository, err := inspectRepository(ctx, root, version)
	if err != nil {
		return releaseSourceState{}, err
	}
	fingerprint, err := fingerprintReleaseSources(root)
	if err != nil {
		return releaseSourceState{}, fmt.Errorf("fingerprint release sources: %w", err)
	}
	return releaseSourceState{repository: repository, fingerprint: fingerprint}, nil
}

func verifyReleaseSourceState(ctx context.Context, root, version string, before releaseSourceState) error {
	after, err := captureReleaseSourceState(ctx, root, version)
	if err != nil {
		return fmt.Errorf("revalidate release sources: %w", err)
	}
	if !sameRepositoryIdentity(before.repository, after.repository) {
		return errors.New("release repository identity changed while packaging; restart from a stable source tree")
	}
	if before.fingerprint != after.fingerprint {
		return errors.New("release source files changed while packaging; restart from a stable source tree")
	}
	return nil
}

func sameRepositoryIdentity(left, right repositoryState) bool {
	return left.InWorkTree == right.InWorkTree &&
		left.Dirty == right.Dirty &&
		slices.Equal(left.DirtyFiles, right.DirtyFiles) &&
		left.TagExists == right.TagExists &&
		left.TagObject == right.TagObject &&
		left.TagEpoch == right.TagEpoch &&
		left.HeadCommit == right.HeadCommit &&
		left.HeadEpoch == right.HeadEpoch
}

func fingerprintReleaseSources(root string) ([sha256.Size]byte, error) {
	digest := sha256.New()
	seen := make(map[string]bool)
	for _, source := range releaseSourcePaths {
		rel := filepath.Clean(filepath.FromSlash(source))
		if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return [sha256.Size]byte{}, fmt.Errorf("unsafe release source path %q", source)
		}
		path := filepath.Join(root, rel)
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			writeSourceFingerprintRecord(digest, 'm', filepath.ToSlash(rel), 0, 0)
			continue
		}
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("inspect %s: %w", source, err)
		}
		if !info.IsDir() {
			if err := fingerprintSourceEntry(digest, root, path, seen); err != nil {
				return [sha256.Size]byte{}, err
			}
			continue
		}
		if err := filepath.WalkDir(path, func(entryPath string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			return fingerprintSourceEntry(digest, root, entryPath, seen)
		}); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("fingerprint %s: %w", source, err)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func fingerprintSourceEntry(digest hash.Hash, root, path string, seen map[string]bool) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	if seen[rel] {
		return fmt.Errorf("release source path %q is covered more than once", rel)
	}
	seen[rel] = true

	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %q: %w", rel, err)
	}
	if before.IsDir() {
		writeSourceFingerprintRecord(digest, 'd', rel, uint32(before.Mode()), 0)
		return nil
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("release source %q must be a regular file or directory, got mode %s", rel, before.Mode())
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q: %w", rel, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened %q: %w", rel, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !sameSourceMetadata(before, opened) {
		return fmt.Errorf("release source %q changed while it was opened", rel)
	}
	writeSourceFingerprintRecord(digest, 'f', rel, uint32(opened.Mode()), opened.Size())
	if _, err := io.CopyN(digest, file, opened.Size()); err != nil {
		return fmt.Errorf("read %q: %w", rel, err)
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("release source %q changed size while it was read", rel)
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect opened %q: %w", rel, err)
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect %q: %w", rel, err)
	}
	if !sameSourceMetadata(opened, after) || !os.SameFile(opened, pathAfter) || !sameSourceMetadata(opened, pathAfter) {
		return fmt.Errorf("release source %q changed while it was read", rel)
	}
	return nil
}

func sameSourceMetadata(left, right fs.FileInfo) bool {
	return left.Mode() == right.Mode() &&
		left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}

func writeSourceFingerprintRecord(digest hash.Hash, kind byte, path string, mode uint32, size int64) {
	_, _ = digest.Write([]byte{kind})
	var metadata [20]byte
	binary.BigEndian.PutUint64(metadata[0:8], uint64(len(path)))
	binary.BigEndian.PutUint32(metadata[8:12], mode)
	binary.BigEndian.PutUint64(metadata[12:20], uint64(size))
	_, _ = digest.Write(metadata[:])
	_, _ = digest.Write([]byte(path))
}
