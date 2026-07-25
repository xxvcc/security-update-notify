// Package statefile persists small runtime facts used by multi-day patch-health checks.
// Files are written atomically with mode 0600 inside the existing root-owned state directory.
package statefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Store struct {
	Dir string
}

func (s Store) path(name string) (string, error) {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return "", fmt.Errorf("invalid state file name %q", name)
	}
	return filepath.Join(s.Dir, name), nil
}

func (s Store) ReadString(name string) (string, error) {
	p, err := s.path(name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

func (s Store) ReadInt(name string) (int64, error) {
	v, err := s.ReadString(name)
	if err != nil || v == "" {
		return 0, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, nil
	}
	return n, nil
}

func (s Store) WriteString(name, value string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return err
	}
	_ = os.Chmod(s.Dir, 0o750)
	tmp, err := os.CreateTemp(s.Dir, ".patch-state.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	clean := func() {
		tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.WriteString(value + "\n"); err != nil {
		clean()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		clean()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func (s Store) WriteInt(name string, value int64) error {
	return s.WriteString(name, strconv.FormatInt(value, 10))
}

func (s Store) Remove(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Track returns the first time an active condition was observed. When mutate is false it is read-only;
// a missing timestamp is treated as newly observed. Clock rollback resets a future timestamp.
func (s Store) Track(name string, active bool, now int64, mutate bool) (int64, error) {
	if !active {
		if mutate {
			return 0, s.Remove(name)
		}
		return 0, nil
	}
	first, err := s.ReadInt(name)
	if err != nil {
		return 0, err
	}
	if first > 0 && first <= now {
		return first, nil
	}
	if mutate {
		if err := s.WriteInt(name, now); err != nil {
			return 0, err
		}
	}
	return now, nil
}
