package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRootFSRejectsSymlinkedAncestor(t *testing.T) {
	rootDir := t.TempDir()
	outside := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Symlink(outside, "/etc"); err != nil {
		t.Fatal(err)
	}

	operations := map[string]func() error{
		"write":      func() error { return filesystem.WriteFileAtomic("/etc/escaped", []byte("x"), 0o600) },
		"mkdir-all":  func() error { return filesystem.MkdirAll("/etc/nested", 0o700) },
		"remove-all": func() error { return filesystem.RemoveAll("/etc/nested") },
		"lock": func() error {
			unlock, err := (FileLocker{FS: filesystem}).Acquire(context.Background(), "/etc/install.lock", 0)
			if err == nil {
				_ = unlock()
			}
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil || !strings.Contains(err.Error(), "symlinked path component") {
				t.Fatalf("operation crossed symlinked ancestor: %v", err)
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(outside, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("write escaped RootFS: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "nested")); !os.IsNotExist(err) {
		t.Fatalf("mkdir escaped RootFS: %v", err)
	}
}

func TestRootFSDoesNotFollowLeafSymlink(t *testing.T) {
	rootDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Symlink(outside, "/managed"); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystem.ReadFile("/managed"); err == nil {
		t.Fatal("ReadFile followed a leaf symlink")
	}
	if err := filesystem.Chmod("/managed", 0o600); err == nil {
		t.Fatal("Chmod followed a leaf symlink")
	}
	if err := filesystem.Remove("/managed"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("outside target changed: data=%q err=%v", data, err)
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("outside mode changed to %04o", info.Mode().Perm())
	}
}

func TestRootFSReadFileFollowAllowsContainedOSReleaseSymlink(t *testing.T) {
	rootDir := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.MkdirAll("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.MkdirAll("/usr/lib", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.WriteFileAtomic("/usr/lib/os-release", []byte("ID=debian\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Symlink("../usr/lib/os-release", "/etc/os-release"); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystem.ReadFile("/etc/os-release"); err == nil {
		t.Fatal("strict ReadFile followed an os-release symlink")
	}
	data, info, err := filesystem.ReadFileFollow("/etc/os-release", 1024)
	if err != nil || string(data) != "ID=debian\n" || !info.Mode().IsRegular() {
		t.Fatalf("contained os-release symlink data=%q info=%v err=%v", data, info, err)
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Remove("/etc/os-release"); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Symlink(outside, "/etc/os-release"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := filesystem.ReadFileFollow("/etc/os-release", 1024); err == nil {
		t.Fatal("ReadFileFollow accepted an absolute target outside the logical root")
	}
}

func TestRootFSCopyRegularFilePreservesMetadata(t *testing.T) {
	rootDir := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.WriteFileAtomic("/source", []byte("contents"), 0o750); err != nil {
		t.Fatal(err)
	}
	wantTime := time.Unix(1_700_000_000, 0)
	sourcePath := filepath.Join(rootDir, "source")
	if err := os.Chtimes(sourcePath, wantTime, wantTime); err != nil {
		t.Fatal(err)
	}
	xattrsSupported := true
	if err := syscall.Setxattr(sourcePath, "user.security-update-notify-test", []byte("kept"), 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
			xattrsSupported = false
		} else {
			t.Fatal(err)
		}
	}
	if err := filesystem.CopyRegularFileAtomic("/source", "/destination", 1024); err != nil {
		t.Fatal(err)
	}
	data, info, err := filesystem.ReadRegularFile("/destination", 1024)
	if err != nil || string(data) != "contents" {
		t.Fatalf("copied data=%q err=%v", data, err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("copied mode=%04o", info.Mode().Perm())
	}
	if !info.ModTime().Equal(wantTime) {
		t.Fatalf("copied mtime=%s want %s", info.ModTime(), wantTime)
	}
	if xattrsSupported {
		value := make([]byte, 16)
		n, err := syscall.Getxattr(filepath.Join(rootDir, "destination"), "user.security-update-notify-test", value)
		if err != nil || string(value[:n]) != "kept" {
			t.Fatalf("copied xattr=%q err=%v", value[:n], err)
		}
	}
}

func TestRootFSRemoveNeverRemovesDirectoryAndRemoveAllUnlinksSymlink(t *testing.T) {
	rootDir := t.TempDir()
	outside := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.MkdirAll("/empty", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Remove("/empty"); err == nil {
		t.Fatal("file removal unexpectedly removed a directory")
	}
	if _, err := filesystem.Lstat("/empty"); err != nil {
		t.Fatalf("directory disappeared: %v", err)
	}
	if err := filesystem.Symlink(outside, "/outside-link"); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.RemoveAll("/outside-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystem.Lstat("/outside-link"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leaf symlink remained: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside target was removed: %v", err)
	}
}

func TestNewRootFSRejectsSymlinkedRoot(t *testing.T) {
	parent := t.TempDir()
	target := t.TempDir()
	linkedRoot := filepath.Join(parent, "root")
	if err := os.Symlink(target, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRootFS(linkedRoot); err == nil || !strings.Contains(err.Error(), "symlinked component") {
		t.Fatalf("symlinked root accepted: %v", err)
	}
}
