package lock

import (
	"path/filepath"
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
}
