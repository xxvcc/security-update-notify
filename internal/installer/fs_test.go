package installer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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
			unlock, err := (FileLocker{FS: filesystem, OwnerUID: uint32(os.Geteuid())}).Acquire(context.Background(), "/etc/install.lock", 0)
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

func TestRootFSAcceptsOnlyStandardLocalSbinAlias(t *testing.T) {
	rootDir := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := filesystem.MkdirAll("/usr/local/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Symlink("bin", "/usr/local/sbin"); err != nil {
		t.Fatal(err)
	}
	const binary = "/usr/local/sbin/security-update-notify"
	if err := filesystem.WriteFileAtomic(binary, []byte("runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(rootDir, "usr/local/bin/security-update-notify")); err != nil || string(got) != "runtime" {
		t.Fatalf("standard alias target data=%q err=%v", got, err)
	}
	if err := filesystem.Remove(binary); err != nil {
		t.Fatal(err)
	}
	if target, err := filesystem.Readlink("/usr/local/sbin"); err != nil || target != "bin" {
		t.Fatalf("standard alias changed: target=%q err=%v", target, err)
	}

	if err := filesystem.Remove("/usr/local/sbin"); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.Symlink("../escape", "/usr/local/sbin"); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.WriteFileAtomic(binary, []byte("escaped"), 0o755); err == nil || !strings.Contains(err.Error(), "symlinked path component") {
		t.Fatalf("nonstandard /usr/local/sbin alias accepted: %v", err)
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

func TestRootFSReadlinkUsesOpenedLinkAfterPathReplacement(t *testing.T) {
	rootDir := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(rootDir, "managed-link")
	held := link + ".held"
	if err := os.Symlink("original-target", link); err != nil {
		t.Fatal(err)
	}
	got, err := filesystem.readlink("/managed-link", func() error {
		if err := os.Rename(link, held); err != nil {
			return err
		}
		return os.Symlink("replacement-target", link)
	})
	if err != nil || got != "original-target" {
		t.Fatalf("descriptor-bound readlink target=%q err=%v", got, err)
	}
	if got, err := os.Readlink(link); err != nil || got != "replacement-target" {
		t.Fatalf("replacement link target=%q err=%v", got, err)
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
	wantTime := time.Unix(1_700_000_000, 123_456_789)
	sourcePath := filepath.Join(rootDir, "source")
	if err := os.Chtimes(sourcePath, wantTime, wantTime); err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !sourceInfo.ModTime().Equal(wantTime) {
		t.Skipf("filesystem does not preserve nanosecond mtimes: got %s want %s", sourceInfo.ModTime(), wantTime)
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

func TestRootFSCopyTrustedRegularFileRejectsUnsafeSourceMetadata(t *testing.T) {
	tests := []struct {
		name         string
		ownerUID     func() uint32
		prepare      func(string) error
		wantReason   string
		checkDefault bool
	}{
		{
			name: "wrong owner",
			ownerUID: func() uint32 {
				return uint32(os.Geteuid()) + 1
			},
			prepare:    func(string) error { return nil },
			wantReason: "does not match effective uid",
		},
		{
			name:     "group writable",
			ownerUID: func() uint32 { return uint32(os.Geteuid()) },
			prepare: func(source string) error {
				return os.Chmod(source, 0o620)
			},
			wantReason:   "has forbidden permissions",
			checkDefault: true,
		},
		{
			name:     "hard linked",
			ownerUID: func() uint32 { return uint32(os.Geteuid()) },
			prepare: func(source string) error {
				return os.Link(source, source+"-link")
			},
			wantReason:   "must have exactly one hard link",
			checkDefault: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootDir := t.TempDir()
			filesystem, err := NewRootFS(rootDir)
			if err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(rootDir, "source")
			if err := os.WriteFile(sourcePath, []byte("untrusted-source"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := test.prepare(sourcePath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootDir, "destination"), []byte("trusted-existing"), 0o600); err != nil {
				t.Fatal(err)
			}

			err = filesystem.CopyTrustedRegularFileAtomic("/source", "/destination", 1024, test.ownerUID())
			if err == nil || !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf("unsafe source error = %v, want %q", err, test.wantReason)
			}
			if got, readErr := os.ReadFile(filepath.Join(rootDir, "destination")); readErr != nil || string(got) != "trusted-existing" {
				t.Fatalf("destination data=%q err=%v", got, readErr)
			}
			entries, readErr := os.ReadDir(rootDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".security-update-notify.") {
					t.Fatalf("temporary file was created before source validation: %s", entry.Name())
				}
			}
			if test.checkDefault {
				err = filesystem.CopyRegularFileAtomic("/source", "/destination", 1024)
				if err == nil || !strings.Contains(err.Error(), test.wantReason) {
					t.Fatalf("default copy unsafe source error = %v, want %q", err, test.wantReason)
				}
			}
		})
	}
}

func TestRootFSMaximumReadLimitDoesNotOverflow(t *testing.T) {
	rootDir := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "source"), []byte("contents"), 0o640); err != nil {
		t.Fatal(err)
	}
	maximum := int64(^uint64(0) >> 1)
	data, _, err := filesystem.ReadRegularFile("/source", maximum)
	if err != nil || string(data) != "contents" {
		t.Fatalf("maximum-limit read data=%q err=%v", data, err)
	}
	if err := filesystem.CopyRegularFileAtomic("/source", "/destination", maximum); err != nil {
		t.Fatalf("maximum-limit copy: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(rootDir, "destination")); err != nil || string(data) != "contents" {
		t.Fatalf("maximum-limit copied data=%q err=%v", data, err)
	}
}

func TestRootFSCopyRegularFileRejectsSameSizeConcurrentChange(t *testing.T) {
	checkpoints := []struct {
		name       string
		checkpoint copyRegularFileCheckpoint
	}{
		{name: "after contents", checkpoint: copyRegularFileContentsCopied},
		{name: "after xattrs", checkpoint: copyRegularFileXattrsCaptured},
		{name: "before publish", checkpoint: copyRegularFileReadyToPublish},
	}
	for _, test := range checkpoints {
		t.Run(test.name, func(t *testing.T) {
			rootDir := t.TempDir()
			filesystem, err := NewRootFS(rootDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := filesystem.WriteFileAtomic("/source", []byte("original"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := filesystem.WriteFileAtomic("/destination", []byte("trusted-existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(rootDir, "source")
			initialTime := time.Unix(1_700_000_000, 0)
			changedTime := initialTime.Add(time.Second)
			if err := os.Chtimes(sourcePath, initialTime, initialTime); err != nil {
				t.Fatal(err)
			}

			var mutationErr error
			mutations := 0
			err = filesystem.copyRegularFileAtomic("/source", "/destination", 1024, func(got copyRegularFileCheckpoint) {
				if got != test.checkpoint {
					return
				}
				mutations++
				mutationDone := make(chan error, 1)
				go func() {
					err := os.WriteFile(sourcePath, []byte("modified"), 0o640)
					if err == nil {
						err = os.Chtimes(sourcePath, changedTime, changedTime)
					}
					mutationDone <- err
				}()
				mutationErr = <-mutationDone
			})
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			if mutations != 1 {
				t.Fatalf("mutation hook called %d times, want 1", mutations)
			}
			if err == nil || !strings.Contains(err.Error(), "source file changed while copying") {
				t.Fatalf("same-size source change accepted: %v", err)
			}
			data, readErr := os.ReadFile(filepath.Join(rootDir, "destination"))
			if readErr != nil || string(data) != "trusted-existing" {
				t.Fatalf("destination data=%q err=%v", data, readErr)
			}
			entries, readErr := os.ReadDir(rootDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".security-update-notify.") {
					t.Fatalf("temporary backup remained after failure: %s", entry.Name())
				}
			}
		})
	}
}

func TestRootFSCopyRegularFileRejectsConcurrentMetadataChange(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(string) error
	}{
		{name: "mode", mutate: func(source string) error { return os.Chmod(source, 0o640) }},
		{name: "link count", mutate: func(source string) error { return os.Link(source, source+"-alias") }},
	}
	if os.Geteuid() == 0 {
		mutations = append(mutations, struct {
			name   string
			mutate func(string) error
		}{name: "owner", mutate: func(source string) error { return os.Chown(source, 1, 1) }})
	}
	checkpoints := []struct {
		name       string
		checkpoint copyRegularFileCheckpoint
	}{
		{name: "after contents", checkpoint: copyRegularFileContentsCopied},
		{name: "after xattrs", checkpoint: copyRegularFileXattrsCaptured},
		{name: "before publish", checkpoint: copyRegularFileReadyToPublish},
	}
	for _, mutation := range mutations {
		for _, boundary := range checkpoints {
			t.Run(mutation.name+"/"+boundary.name, func(t *testing.T) {
				rootDir := t.TempDir()
				filesystem, err := NewRootFS(rootDir)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootDir, "source"), []byte("trusted-source"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootDir, "destination"), []byte("trusted-existing"), 0o600); err != nil {
					t.Fatal(err)
				}
				mutationCalls := 0
				var mutationErr error
				err = filesystem.copyRegularFileAtomic("/source", "/destination", 1024, func(got copyRegularFileCheckpoint) {
					if got != boundary.checkpoint {
						return
					}
					mutationCalls++
					mutationErr = mutation.mutate(filepath.Join(rootDir, "source"))
				})
				if mutationErr != nil {
					t.Fatal(mutationErr)
				}
				if mutationCalls != 1 {
					t.Fatalf("mutation hook calls = %d, want 1", mutationCalls)
				}
				if err == nil || !strings.Contains(err.Error(), "source file changed while copying") {
					t.Fatalf("concurrent %s change accepted at %s: %v", mutation.name, boundary.name, err)
				}
				if got, readErr := os.ReadFile(filepath.Join(rootDir, "destination")); readErr != nil || string(got) != "trusted-existing" {
					t.Fatalf("destination data=%q err=%v", got, readErr)
				}
			})
		}
	}
}

func TestRootFSAtomicPublishRejectsReplacedTemporaryEntry(t *testing.T) {
	for _, operation := range []string{"write", "copy"} {
		t.Run(operation, func(t *testing.T) {
			rootDir := t.TempDir()
			filesystem, err := NewRootFS(rootDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootDir, "destination"), []byte("trusted-existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootDir, "source"), []byte("trusted-source"), 0o640); err != nil {
				t.Fatal(err)
			}

			calls := 0
			temporary := ""
			filesystem.beforeAtomicPublish = func(directory *os.File, name string) error {
				calls++
				temporary = name
				return replaceAtomicTemporary(directory, name, "untrusted-replacement")
			}
			if operation == "write" {
				err = filesystem.WriteFileAtomic("/destination", []byte("new-managed-data"), 0o600)
			} else {
				err = filesystem.CopyRegularFileAtomic("/source", "/destination", 1024)
			}
			if err == nil || !strings.Contains(err.Error(), "atomic temporary file changed before publish") ||
				!strings.Contains(err.Error(), "atomic temporary entry changed; retained") {
				t.Fatalf("atomic %s error = %v, want replaced-temporary refusal", operation, err)
			}
			if calls != 1 {
				t.Fatalf("publish hook calls = %d, want 1", calls)
			}
			if got, readErr := os.ReadFile(filepath.Join(rootDir, "destination")); readErr != nil || string(got) != "trusted-existing" {
				t.Fatalf("destination data=%q err=%v", got, readErr)
			}
			if got, readErr := os.ReadFile(filepath.Join(rootDir, temporary)); readErr != nil || string(got) != "untrusted-replacement" {
				t.Fatalf("unowned temporary data=%q err=%v", got, readErr)
			}
		})
	}
}

func replaceAtomicTemporary(directory *os.File, name, contents string) error {
	suffix, found := strings.CutPrefix(name, ".security-update-notify.")
	if !found || len(suffix) != 32 {
		return fmt.Errorf("temporary name is not randomized: %q", name)
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		return fmt.Errorf("temporary name is not hexadecimal: %q: %w", name, err)
	}
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
		return err
	}
	fd, err := syscall.Openat(
		int(directory.Fd()), name,
		syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return err
	}
	replacement := os.NewFile(uintptr(fd), name)
	if replacement == nil {
		_ = syscall.Close(fd)
		return errors.New("could not create replacement file handle")
	}
	_, writeErr := replacement.WriteString(contents)
	return errors.Join(writeErr, replacement.Close())
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

func TestRootFSRemovalDoesNotDeleteConcurrentReplacement(t *testing.T) {
	t.Run("leaf", func(t *testing.T) {
		rootDir := t.TempDir()
		filesystem, err := NewRootFS(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(rootDir, "managed")
		held := target + ".held"
		if err := os.WriteFile(target, []byte("managed"), 0o600); err != nil {
			t.Fatal(err)
		}
		err = filesystem.remove("/managed", func() error {
			if err := os.Rename(target, held); err != nil {
				return err
			}
			return os.WriteFile(target, []byte("administrator replacement"), 0o640)
		})
		if err == nil || !strings.Contains(err.Error(), "entry changed before removal") {
			t.Fatalf("Remove error = %v, want replacement refusal", err)
		}
		assertHostFile(t, held, "managed")
		assertHostFile(t, target, "administrator replacement")
	})

	t.Run("tree after directory open", func(t *testing.T) {
		rootDir := t.TempDir()
		filesystem, err := NewRootFS(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(rootDir, "tree")
		held := target + ".held"
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "managed"), []byte("managed"), 0o600); err != nil {
			t.Fatal(err)
		}
		err = filesystem.removeAll("/tree", func() error {
			if err := os.Rename(target, held); err != nil {
				return err
			}
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(target, "administrator.conf"), []byte("keep"), 0o640)
		})
		if err == nil || !strings.Contains(err.Error(), "entry changed before removal") {
			t.Fatalf("RemoveAll error = %v, want replacement refusal", err)
		}
		assertHostFile(t, filepath.Join(held, "managed"), "managed")
		assertHostFile(t, filepath.Join(target, "administrator.conf"), "keep")
		entries, readErr := os.ReadDir(rootDir)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".security-update-notify-remove.") {
				t.Fatalf("removal quarantine remained after conflict restoration: %s", entry.Name())
			}
		}
	})
}

func TestRootFSRemovalRecoversInterruptedQuarantines(t *testing.T) {
	rootDir := t.TempDir()
	filesystem, err := NewRootFS(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	fileArtifact := removalPrefix + strings.Repeat("a", 32)
	directoryArtifact := removalPrefix + strings.Repeat("b", 32)
	nearMatch := removalPrefix + "not-a-valid-artifact"
	if err := os.WriteFile(filepath.Join(rootDir, fileArtifact), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootDir, directoryArtifact), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, directoryArtifact, "credential"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, nearMatch), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The original path is already absent, as it would be after a crash between
	// quarantine rename and deletion. A retry must still discover the residue.
	if err := filesystem.RemoveAll("/already-absent"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{fileArtifact, directoryArtifact} {
		if _, err := os.Lstat(filepath.Join(rootDir, name)); !os.IsNotExist(err) {
			t.Fatalf("interrupted removal artifact %s survived retry: %v", name, err)
		}
	}
	assertHostFile(t, filepath.Join(rootDir, nearMatch), "keep")
}

func assertHostFile(t *testing.T, name, want string) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil || string(got) != want {
		t.Fatalf("file %s data=%q err=%v, want %q", name, got, err, want)
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
