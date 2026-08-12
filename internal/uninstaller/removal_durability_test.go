package uninstaller

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOwnedRemovalIdentityIntegerEncodingIsReversible(t *testing.T) {
	suffix := strings.Repeat("a", 32)
	for _, value := range []int64{math.MinInt64, -1, 0, math.MaxInt64} {
		identity, mode, ok := parseOwnedRemovalName(
			"." + uninstallRemovalOwnedPrefix + "." + suffix + ".2.1.2.ffffffff.fffffffe.fffffffd." +
				strings.Join([]string{
					formatRemovalIdentityWord(uint64(value)),
					formatRemovalIdentityWord(uint64(value)),
					formatRemovalIdentityWord(uint64(value)),
				}, "."),
		)
		if !ok || mode != removalTree {
			t.Fatalf("parse value %d: ok=%t mode=%d", value, ok, mode)
		}
		if identity.size != value || identity.mtimeSec != value || identity.nsec != value {
			t.Fatalf("value %d decoded as size=%d mtime=%d nsec=%d", value, identity.size, identity.mtimeSec, identity.nsec)
		}
		if identity.mode != math.MaxUint32 || identity.uid != math.MaxUint32-1 || identity.gid != math.MaxUint32-2 {
			t.Fatalf("bounded uint32 fields changed: %#v", identity)
		}
	}
}

func TestOwnedRemovalIdentityRejectsNarrowingOverflow(t *testing.T) {
	suffix := strings.Repeat("b", 32)
	valid := []string{"2", "1", "2", "ffffffff", "fffffffe", "fffffffd", "0", "0", "0"}
	for _, test := range []struct {
		name  string
		index int
		value string
	}{
		{name: "mode", index: 0, value: "3"},
		{name: "file mode", index: 3, value: "100000000"},
		{name: "uid", index: 4, value: "100000000"},
		{name: "gid", index: 5, value: "100000000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := append([]string(nil), valid...)
			fields[test.index] = test.value
			name := "." + uninstallRemovalOwnedPrefix + "." + suffix + "." + strings.Join(fields, ".")
			if _, _, ok := parseOwnedRemovalName(name); ok {
				t.Fatalf("accepted overflowing %s field %q", test.name, test.value)
			}
		})
	}
}

func formatRemovalIdentityWord(value uint64) string {
	return strconv.FormatUint(value, 16)
}

func TestLogicalRemovalFinalSyncFailureAndMissingRetry(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T, string) string
		remove func(string, func(*os.File) error) error
	}{
		{
			name: "file",
			setup: func(t *testing.T, root string) string {
				return writeFixture(t, root, "/etc/logrotate.d/security-update-notify", "managed")
			},
			remove: func(root string, syncParent func(*os.File) error) error {
				return removeLogicalFileWithSync(root, "/etc/logrotate.d/security-update-notify", nil, syncParent)
			},
		},
		{
			name: "empty directory",
			setup: func(t *testing.T, root string) string {
				target := hostPath(root, "/etc/systemd/system/security-update-notify.service.d")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				return target
			},
			remove: func(root string, syncParent func(*os.File) error) error {
				return removeLogicalEmptyDirectoryWithSync(root, "/etc/systemd/system/security-update-notify.service.d", nil, syncParent)
			},
		},
		{
			name: "tree",
			setup: func(t *testing.T, root string) string {
				target := hostPath(root, "/etc/security-update-notify")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				return target
			},
			remove: func(root string, syncParent func(*os.File) error) error {
				return removeLogicalTreeWithSync(root, "/etc/security-update-notify", nil, syncParent)
			},
		},
		{
			name: "prefix",
			setup: func(t *testing.T, root string) string {
				return writeFixture(t, root, "/var/log/security-update-notify.log.1", "managed")
			},
			remove: func(root string, syncParent func(*os.File) error) error {
				return removeLogicalFilesWithPrefixWithSync(root, "/var/log", "security-update-notify.log.", nil, syncParent)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			target := test.setup(t, root)
			finalSyncFailure := errors.New("forced final removal directory sync failure")
			syncCalls := 0
			syncParent := func(parent *os.File) error {
				syncCalls++
				if syncCalls == 3 {
					return finalSyncFailure
				}
				return syncLogicalRemovalParent(parent)
			}

			err := test.remove(root, syncParent)
			if !errors.Is(err, finalSyncFailure) {
				t.Fatalf("first removal error = %v, want final sync failure", err)
			}
			if syncCalls != 3 {
				t.Fatalf("first removal sync calls = %d, want pre-delete, post-delete, and final sync", syncCalls)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("target remained after successful removal: %v", err)
			}

			if err := test.remove(root, syncParent); err != nil {
				t.Fatalf("missing-target retry error = %v", err)
			}
			if syncCalls != 4 {
				t.Fatalf("retry sync calls = %d, want missing-target durability sync", syncCalls)
			}
		})
	}
}

func TestLogicalRemovalJoinsOperationSyncAndCloseErrors(t *testing.T) {
	root := t.TempDir()
	target := writeFixture(t, root, "/etc/logrotate.d/security-update-notify", "managed")
	operationFailure := errors.New("forced removal operation failure")
	syncFailure := errors.New("forced removal directory sync failure")
	err := removeLogicalFileWithSync(root, "/etc/logrotate.d/security-update-notify", func() error {
		return operationFailure
	}, func(parent *os.File) error {
		if err := parent.Close(); err != nil {
			t.Fatalf("close parent before injected sync failure: %v", err)
		}
		return syncFailure
	})
	if !errors.Is(err, operationFailure) || !errors.Is(err, syncFailure) || !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("joined error = %v, want operation, sync, and close errors", err)
	}
	if got, readErr := os.ReadFile(target); readErr != nil || string(got) != "managed" {
		t.Fatalf("failed operation changed target: data=%q err=%v", got, readErr)
	}
}

func TestPrefixRemovalSyncsPhysicalDirectory(t *testing.T) {
	root := t.TempDir()
	target := writeFixture(t, root, "/var/log/security-update-notify.log.1", "managed")
	wantDirectory := filepath.Dir(target)
	err := removeLogicalFilesWithPrefixWithSync(root, "/var/log", "security-update-notify.log.", nil, func(parent *os.File) error {
		if parent.Name() != wantDirectory {
			t.Fatalf("sync directory = %q, want %q", parent.Name(), wantDirectory)
		}
		return syncLogicalRemovalParent(parent)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRemoveClaimedTreeJoinsChildAndInnerDirectorySyncErrors(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "outer", "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(inner, "child")
	if err := os.WriteFile(child, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	outer, err := os.Open(filepath.Dir(inner))
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	directory, err := openRemovalDirectory(outer, filepath.Base(inner))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	childFailure := errors.New("forced recursive child removal failure")
	syncFailure := errors.New("forced inner directory sync failure")
	syncCalls := 0
	err = removeClaimedTreeWithSync(directory, func(name string) error {
		if name != filepath.Base(child) {
			t.Fatalf("recursive child = %q, want %q", name, filepath.Base(child))
		}
		return childFailure
	}, func(got *os.File) error {
		syncCalls++
		if got != directory {
			t.Fatal("recursive sync did not receive the held inner directory descriptor")
		}
		gotInfo, statErr := got.Stat()
		if statErr != nil {
			t.Fatal(statErr)
		}
		wantInfo, statErr := os.Stat(inner)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if !os.SameFile(gotInfo, wantInfo) {
			t.Fatalf("recursive sync descriptor = %q, want inner directory %q", got.Name(), inner)
		}
		return syncFailure
	})
	if !errors.Is(err, childFailure) || !errors.Is(err, syncFailure) {
		t.Fatalf("recursive removal error = %v, want child and inner sync failures", err)
	}
	if syncCalls != 1 {
		t.Fatalf("inner directory sync calls = %d, want 1", syncCalls)
	}
	if got, readErr := os.ReadFile(child); readErr != nil || string(got) != "managed" {
		t.Fatalf("failed recursive child removal changed child: data=%q err=%v", got, readErr)
	}
}
