package statefile

import (
	"os"
	"path/filepath"
	"testing"
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

func TestRejectsPathTraversal(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.WriteString("../escape", "x"); err == nil {
		t.Fatal("expected invalid name error")
	}
}
