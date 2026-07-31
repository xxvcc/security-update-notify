package statefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTrackLifecycleAndClockRollback(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	first, err := s.Track("pending.first_seen", true, 100, true)
	if err != nil || first != 100 {
		t.Fatalf("first=%d err=%v", first, err)
	}
	first, err = s.Track("pending.first_seen", true, 200, true)
	if err != nil || first != 100 {
		t.Fatalf("persisted first=%d err=%v", first, err)
	}
	first, err = s.Track("pending.first_seen", true, 50, true)
	if err != nil || first != 50 {
		t.Fatalf("clock rollback first=%d err=%v", first, err)
	}
	if _, err := s.Track("pending.first_seen", false, 300, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "pending.first_seen")); !os.IsNotExist(err) {
		t.Fatalf("state was not removed: %v", err)
	}
}

func TestObservePreservesConfirmedStateAcrossUnknown(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	first, err := s.Observe("pending.first_seen", ObservationPresent, 100, true)
	if err != nil || first != 100 {
		t.Fatalf("present observation=(%d, %v), want (100, nil)", first, err)
	}
	first, err = s.Observe("pending.first_seen", ObservationUnknown, 200, true)
	if err != nil || first != 0 {
		t.Fatalf("unknown observation=(%d, %v), want (0, nil)", first, err)
	}
	first, err = s.Observe("pending.first_seen", ObservationPresent, 300, true)
	if err != nil || first != 100 {
		t.Fatalf("present after unknown=(%d, %v), want original first_seen", first, err)
	}
	if _, err := s.Observe("pending.first_seen", ObservationAbsent, 400, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "pending.first_seen")); !os.IsNotExist(err) {
		t.Fatalf("confirmed absence did not remove state: %v", err)
	}
	first, err = s.Observe("pending.first_seen", ObservationPresent, 500, true)
	if err != nil || first != 500 {
		t.Fatalf("present after absence=(%d, %v), want new first_seen", first, err)
	}
}

func TestObserveRejectsInvalidState(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.Observe("pending.first_seen", Observation(99), 100, true); err == nil {
		t.Fatal("Observe accepted an invalid observation")
	}
}

func TestReadOnlyTrackDoesNotCreateState(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	first, err := s.Track("reboot.first_seen", true, 123, false)
	if err != nil || first != 123 {
		t.Fatalf("first=%d err=%v", first, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "reboot.first_seen")); !os.IsNotExist(err) {
		t.Fatalf("read-only tracking created a file: %v", err)
	}
}

func TestTrackRejectsInvalidStoredTimestampsWithoutOverwritingThem(t *testing.T) {
	for _, value := range []string{"broken", "0", "-1"} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "pending.first_seen")
			original := []byte(value + "\n")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			store := Store{Dir: dir}
			if first, err := store.Track("pending.first_seen", true, 123, true); err == nil || first != 0 {
				t.Fatalf("Track()=(%d, %v), want 0 and an error", first, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, original) {
				t.Fatalf("invalid state was overwritten: got %q want %q", got, original)
			}
		})
	}
}

func TestRejectsPathTraversal(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	for _, name := range []string{"../escape", ".", "..", "a/b", `a\b`} {
		if err := s.WriteString(name, "x"); err == nil {
			t.Errorf("WriteString(%q) accepted an invalid state name", name)
		}
		if err := s.Remove(name); err == nil {
			t.Errorf("Remove(%q) accepted an invalid state name", name)
		}
	}
	if _, err := os.Stat(s.Dir); err != nil {
		t.Fatalf("invalid state name changed the store directory: %v", err)
	}
	if err := (Store{}).Remove("state"); err == nil {
		t.Fatal("zero-value store accepted a path relative to the process working directory")
	}
}

func TestRemoveUnlinksFilesAndSymlinksButNeverDirectories(t *testing.T) {
	dir := t.TempDir()
	store := Store{Dir: dir}

	file := filepath.Join(dir, "state")
	if err := os.WriteFile(file, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("state"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Fatalf("state file still exists: %v", err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("link"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep\n" {
		t.Fatalf("symlink target changed: contents=%q err=%v", got, err)
	}

	emptyDir := filepath.Join(dir, "empty")
	if err := os.Mkdir(emptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("empty"); err == nil {
		t.Fatal("Remove accepted an empty directory")
	}
	if info, err := os.Lstat(emptyDir); err != nil || !info.IsDir() {
		t.Fatalf("empty directory was changed: info=%v err=%v", info, err)
	}

	nonEmptyDir := filepath.Join(dir, "non-empty")
	if err := os.Mkdir(nonEmptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(nonEmptyDir, "child")
	if err := os.WriteFile(child, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("non-empty"); err == nil {
		t.Fatal("Remove accepted a non-empty directory")
	}
	if got, err := os.ReadFile(child); err != nil || string(got) != "keep\n" {
		t.Fatalf("directory contents changed: contents=%q err=%v", got, err)
	}
}

func TestOperationsStayBoundToValidatedDirectoryAfterPathExchange(t *testing.T) {
	for _, operation := range []string{"read", "write", "remove"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "state")
			replacement := filepath.Join(root, "replacement")
			openedDirectory := filepath.Join(root, "opened-state")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(replacement, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "state"), []byte("validated\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(replacement, "state"), []byte("replacement\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			store := Store{Dir: directory}
			store.afterDirectoryOpen = func() {
				if err := os.Rename(directory, openedDirectory); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(replacement, directory); err != nil {
					t.Fatal(err)
				}
			}

			switch operation {
			case "read":
				got, err := store.ReadString("state")
				if err != nil || got != "validated" {
					t.Fatalf("ReadString()=(%q, %v), want validated directory contents", got, err)
				}
			case "write":
				if err := store.WriteString("state", "new"); err != nil {
					t.Fatal(err)
				}
				if got, err := os.ReadFile(filepath.Join(openedDirectory, "state")); err != nil || string(got) != "new\n" {
					t.Fatalf("validated directory state=(%q, %v)", got, err)
				}
			case "remove":
				if err := store.Remove("state"); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(filepath.Join(openedDirectory, "state")); !os.IsNotExist(err) {
					t.Fatalf("validated directory state was not removed: %v", err)
				}
			}

			if got, err := os.ReadFile(filepath.Join(replacement, "state")); err != nil || string(got) != "replacement\n" {
				t.Fatalf("replacement directory was modified: contents=%q err=%v", got, err)
			}
		})
	}
}

func TestStateFilesAreBoundedAndNonBlocking(t *testing.T) {
	dir := t.TempDir()
	store := Store{Dir: dir}
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, maxStateFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadString("oversized"); err == nil {
		t.Fatal("oversized state file was accepted")
	}
	if err := store.WriteString("too-large", string(bytes.Repeat([]byte{'x'}, maxStateFileBytes))); err == nil {
		t.Fatal("oversized state value was written")
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := store.ReadString("fifo")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO state file was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("reading a FIFO state file blocked")
	}
}

func TestWriteRejectsUnsafeDirectoryWithoutChangingItsMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	store := Store{Dir: dir}
	if err := store.WriteString("state", "value"); err == nil {
		t.Fatal("group/other-writable state directory was accepted")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("state directory was chmodded before validation: %#o", info.Mode().Perm())
	}

	root := t.TempDir()
	link := filepath.Join(root, "state-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := (Store{Dir: link}).WriteString("state", "new"); err == nil {
		t.Fatal("symlinked state directory was accepted")
	}
}

func TestWriteCreatesMissingDirectoryAndPreservesStrictExistingMode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	store := Store{Dir: dir}
	if err := store.WriteString("state", "value"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("created state directory mode=%#o", info.Mode().Perm())
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteString("state", "new"); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("strict state directory was widened to %#o", info.Mode().Perm())
	}
}

func TestWriteStringSyncOrderingAndFailureSemantics(t *testing.T) {
	t.Run("syncs file before rename and directory after rename", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state")
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		phase := 0
		store := Store{
			Dir: dir,
			fileSync: func(file *os.File) error {
				phase++
				if phase != 1 {
					t.Fatalf("temporary file sync occurred at phase %d", phase)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != "old\n" {
					t.Fatalf("destination changed before temporary file sync: contents=%q err=%v", got, err)
				}
				return file.Sync()
			},
			directorySync: func(directory *os.File) error {
				phase++
				if phase != 2 {
					t.Fatalf("directory sync occurred at phase %d", phase)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != "new\n" {
					t.Fatalf("destination was not renamed before directory sync: contents=%q err=%v", got, err)
				}
				return directory.Sync()
			},
		}
		if err := store.WriteString("state", "new"); err != nil {
			t.Fatal(err)
		}
		if phase != 2 {
			t.Fatalf("completed at phase %d, want 2", phase)
		}
	})

	t.Run("file sync failure preserves destination", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state")
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		wantErr := errors.New("file sync failed")
		store := Store{Dir: dir, fileSync: func(*os.File) error { return wantErr }}
		if err := store.WriteString("state", "new"); !errors.Is(err, wantErr) {
			t.Fatalf("WriteString error=%v, want %v", err, wantErr)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != "old\n" {
			t.Fatalf("file sync failure changed destination: contents=%q err=%v", got, err)
		}
		if leftovers, err := filepath.Glob(filepath.Join(dir, ".patch-state.*")); err != nil || len(leftovers) != 0 {
			t.Fatalf("file sync failure left temporary files: files=%v err=%v", leftovers, err)
		}
	})

	t.Run("directory sync failure reports committed replacement", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state")
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		wantErr := errors.New("directory sync failed")
		store := Store{Dir: dir, directorySync: func(*os.File) error { return wantErr }}
		if err := store.WriteString("state", "new"); !errors.Is(err, wantErr) {
			t.Fatalf("WriteString error=%v, want %v", err, wantErr)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != "new\n" {
			t.Fatalf("post-rename sync failure was treated as a rollback: contents=%q err=%v", got, err)
		}
	})
}

func TestRemoveSyncsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	synced := false
	store := Store{Dir: dir, directorySync: func(directory *os.File) error {
		synced = true
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("directory synced before state removal: %v", err)
		}
		return directory.Sync()
	}}
	if err := store.Remove("state"); err != nil {
		t.Fatal(err)
	}
	if !synced {
		t.Fatal("state removal did not sync its directory")
	}
}
