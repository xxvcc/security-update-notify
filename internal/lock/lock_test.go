package lock

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAcquireWaitTimesOutAndThenAcquires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.lock")
	releaseFirst, acquired, err := Acquire(path)
	if err != nil || !acquired {
		t.Fatalf("initial acquire: acquired=%v err=%v", acquired, err)
	}

	start := time.Now()
	if release, acquired, err := AcquireWait(path, 20*time.Millisecond); err != nil || acquired || release != nil {
		t.Fatalf("contended acquire: release=%v acquired=%v err=%v", release != nil, acquired, err)
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond || elapsed > time.Second {
		t.Fatalf("unexpected timeout duration: %v", elapsed)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		releaseFirst()
		close(released)
	}()
	releaseSecond, acquired, err := AcquireWait(path, time.Second)
	if err != nil || !acquired || releaseSecond == nil {
		t.Fatalf("acquire while waiting for release: acquired=%v err=%v", acquired, err)
	}
	<-released
	releaseSecond()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode=%v, want 0600", info.Mode().Perm())
	}
}

func TestAcquireRejectsSymlinkAndHardlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.lock")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if release, acquired, err := Acquire(symlink); err == nil || acquired || release != nil {
		t.Fatalf("symlink acquire: release=%v acquired=%v err=%v", release != nil, acquired, err)
	}

	hardlink := filepath.Join(dir, "hardlink.lock")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if release, acquired, err := Acquire(hardlink); err == nil || acquired || release != nil {
		t.Fatalf("hardlink acquire: release=%v acquired=%v err=%v", release != nil, acquired, err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "unchanged" {
		t.Fatalf("target changed: %q err=%v", got, err)
	}
}

func TestAcquireRejectsSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	external := t.TempDir()
	linkedParent := filepath.Join(dir, "linked")
	if err := os.Symlink(external, linkedParent); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(linkedParent, "notify.lock")
	if release, acquired, err := Acquire(path); err == nil || acquired || release != nil {
		t.Fatalf("symlinked-parent acquire: release=%v acquired=%v err=%v", release != nil, acquired, err)
	}
	if _, err := os.Lstat(filepath.Join(external, "notify.lock")); !os.IsNotExist(err) {
		t.Fatalf("lock was created through symlinked parent: %v", err)
	}
}

func TestValidateLockPathDetectsReplacementAndNewHardlink(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "notify.lock")
		file, parent, name, err := openLockFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		defer parent.Close()
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateLockPath(parent, name, file, os.Geteuid()); err == nil {
			t.Fatal("replacement lock path was accepted")
		}
	})

	t.Run("hardlink-after-open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "notify.lock")
		file, parent, name, err := openLockFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		defer parent.Close()
		if err := os.Link(path, path+".alias"); err != nil {
			t.Fatal(err)
		}
		if err := validateLockPath(parent, name, file, os.Geteuid()); err == nil {
			t.Fatal("hard link added after open was accepted")
		}
	})
}

func TestAcquireRejectsWrongOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	path := filepath.Join(t.TempDir(), "notify.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Skipf("filesystem does not allow constructing a foreign-owned lock: %v", err)
	}
	if release, acquired, err := Acquire(path); err == nil || acquired || release != nil {
		t.Fatalf("wrong-owner acquire: release=%v acquired=%v err=%v", release != nil, acquired, err)
	}
}

func TestAcquireInheritedUsesParentOpenFileDescription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.lock")
	parentLock, parentDir, _, err := openLockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := parentDir.Close(); err != nil {
		t.Fatal(err)
	}
	defer parentLock.Close()
	if err := parentLock.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(parentLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(parentLock.Fd()), syscall.LOCK_UN)

	inheritedFD, err := syscall.Dup(int(parentLock.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	release, err := AcquireInherited(path, inheritedFD)
	if err != nil {
		t.Fatalf("adopt inherited lock: %v", err)
	}
	release()

	// Closing the child descriptor must not issue LOCK_UN against the shared
	// open file description while the installer parent is still active.
	if releaseOther, acquired, err := Acquire(path); err != nil || acquired || releaseOther != nil {
		t.Fatalf("parent lock after child release: release=%v acquired=%v err=%v", releaseOther != nil, acquired, err)
	}
}

func TestAcquireInheritedRejectsForgedDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.lock")
	parentLock, parentDir, _, err := openLockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := parentDir.Close(); err != nil {
		t.Fatal(err)
	}
	defer parentLock.Close()
	if err := parentLock.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(parentLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(parentLock.Fd()), syscall.LOCK_UN)

	t.Run("different inode", func(t *testing.T) {
		other, err := os.OpenFile(filepath.Join(t.TempDir(), "other.lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		descriptor, err := syscall.Dup(int(other.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if release, err := AcquireInherited(path, descriptor); err == nil || release != nil ||
			!strings.Contains(err.Error(), "path") {
			t.Fatalf("different-inode inherited lock: release=%v err=%v", release != nil, err)
		}
	})

	t.Run("different open file description", func(t *testing.T) {
		other, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		descriptor := int(other.Fd())
		// AcquireInherited owns and closes descriptor on every return path.
		if release, err := AcquireInherited(path, descriptor); err == nil || release != nil ||
			!strings.Contains(err.Error(), "ownership") {
			t.Fatalf("separate-open inherited lock: release=%v err=%v", release != nil, err)
		}
	})
}
