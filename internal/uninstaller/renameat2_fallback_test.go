package uninstaller

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// flagRejectingRename simulates a filesystem that implements renameat2 but
// refuses its flags, the behaviour of OpenZFS before 2.2, NFS, and several FUSE
// backends that are reachable on officially supported distributions. Unflagged
// renames are the plain POSIX operation those filesystems do support, so they
// run for real. The counter proves the flagged attempt happened, without which
// a fallback test could pass while never leaving the renameat2 path.
func flagRejectingRename(rejections *int) func(directory int, oldName, newName string, flags uintptr) error {
	return func(directory int, oldName, newName string, flags uintptr) error {
		if flags != 0 {
			*rejections++
			return syscall.EINVAL
		}
		return renameRestoreEntry(directory, oldName, newName, flags)
	}
}

// restoreAPT opens its own restore directory, so the seam is only reachable by
// driving restoreFile against the same apt fixture the purge path uses.
func TestRestoreFileExchangeFallbackPublishesRestoredBytesWhenRenameFlagsAreRejected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()

	sourceName := filepath.Base(aptStableLogical)
	destinationName := filepath.Base(aptPeriodicLogical)
	sourceSnapshot, err := directory.readRegular(sourceName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	destinationSnapshot, err := directory.readRegular(destinationName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	if !destinationSnapshot.exists {
		t.Fatal("fixture must have a live destination so publishing takes the exchange path")
	}
	rejections := 0
	directory.renameAt = flagRejectingRename(&rejections)

	if _, err := directory.restoreFile(sourceName, destinationName, sourceSnapshot, destinationSnapshot); err != nil {
		t.Fatalf("restoreFile() error = %v", err)
	}
	if rejections != 1 {
		t.Fatalf("flagged renames = %d, want exactly one rejected exchange", rejections)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	names, err := directory.names()
	if err != nil {
		t.Fatal(err)
	}
	// The displaced configuration and the reserved name the fallback borrows are
	// both consumed; only the destination and the untouched backup may remain.
	want := []string{destinationName, sourceName}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("apt configuration directory = %v, want %v", names, want)
	}
}

func TestRestoreFileNoReplaceFallbackPublishesSingleLinkedFileWhenRenameFlagsAreRejected(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()

	sourceName := filepath.Base(aptStableLogical)
	destinationName := filepath.Base(aptPeriodicLogical)
	sourceSnapshot, err := directory.readRegular(sourceName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	destinationSnapshot, err := directory.readRegular(destinationName, restoreConfigLimit)
	if err != nil {
		t.Fatal(err)
	}
	if destinationSnapshot.exists {
		t.Fatal("fixture must have no destination so publishing takes the no-replace path")
	}
	rejections := 0
	directory.renameAt = flagRejectingRename(&rejections)

	if _, err := directory.restoreFile(sourceName, destinationName, sourceSnapshot, destinationSnapshot); err != nil {
		t.Fatalf("restoreFile() error = %v", err)
	}
	if rejections != 1 {
		t.Fatalf("flagged renames = %d, want exactly one rejected no-replace rename", rejections)
	}
	assertContent(t, root, aptPeriodicLogical, "vendor baseline")
	// The linkat fallback publishes a second name for the same inode, so the
	// source must be unlinked before the caller sees it: sameRestoreFileInfo
	// compares link counts and readTrustedRegular refuses anything but one link,
	// which would wedge every later restore decision about this file.
	published, err := os.Lstat(hostPath(root, aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := published.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("published restore file has no stat information")
	}
	if stat.Nlink != 1 {
		t.Fatalf("published link count = %d, want 1", stat.Nlink)
	}
	names, err := directory.names()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{destinationName, sourceName}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("apt configuration directory = %v, want %v", names, want)
	}
}

func TestRenameNoReplaceFallbackRefusesToOverwriteExistingDestination(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, aptPeriodicLogical, "managed")
	writeFixture(t, root, aptStableLogical, "vendor baseline")
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	rejections := 0
	directory.renameAt = flagRejectingRename(&rejections)

	err = directory.renameNoReplace(filepath.Base(aptStableLogical), filepath.Base(aptPeriodicLogical))
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("renameNoReplace() error = %v, want the EEXIST renameat2 would have reported", err)
	}
	if rejections != 1 {
		t.Fatalf("flagged renames = %d, want exactly one rejected no-replace rename", rejections)
	}
	assertContent(t, root, aptPeriodicLogical, "managed")
	assertContent(t, root, aptStableLogical, "vendor baseline")
}

func TestRemovalQuarantinePromotionFallsBackToPlainRenameWhenRenameFlagsAreRejected(t *testing.T) {
	tests := []struct {
		name    string
		logical string
		mode    removalMode
		prepare func(*testing.T, string)
	}{
		{
			name:    "managed leaf file",
			logical: "/etc/logrotate.d/security-update-notify",
			mode:    removalLeaf,
			prepare: func(t *testing.T, root string) {
				writeFixture(t, root, "/etc/logrotate.d/security-update-notify", "managed")
			},
		},
		{
			name:    "empty service drop-in directory",
			logical: "/etc/systemd/system/security-update-notify.service.d",
			mode:    removalEmptyDirectory,
			prepare: func(t *testing.T, root string) {
				path := hostPath(root, "/etc/systemd/system/security-update-notify.service.d")
				if err := os.MkdirAll(path, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:    "managed configuration tree",
			logical: "/etc/security-update-notify",
			mode:    removalTree,
			prepare: func(t *testing.T, root string) {
				writeFixture(t, root, "/etc/security-update-notify/telegram.env", "secret")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.prepare(t, root)
			parent, name, err := openLogicalParent(root, test.logical)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			expected, err := readRemovalEntry(parent, name)
			if err != nil {
				t.Fatal(err)
			}
			rejections := 0

			if err := removeValidatedEntryAtWithHooks(parent, name, expected, test.mode, removalHooks{
				renameAt: flagRejectingRename(&rejections),
			}); err != nil {
				t.Fatalf("removeValidatedEntryAtWithHooks() error = %v", err)
			}
			if rejections != 1 {
				t.Fatalf("flagged renames = %d, want exactly one rejected promotion", rejections)
			}
			assertMissing(t, root, test.logical)
			entries, err := os.ReadDir(filepath.Dir(hostPath(root, test.logical)))
			if err != nil {
				t.Fatal(err)
			}
			retained := make([]string, 0, len(entries))
			for _, entry := range entries {
				retained = append(retained, entry.Name())
			}
			if len(retained) != 0 {
				t.Fatalf("%s entries = %v, want no retained quarantine", filepath.Dir(test.logical), retained)
			}
		})
	}
}

func TestRenameFlagsUnsupportedSelectsFallbackOnlyForRejectedFlags(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "syscall absent", err: syscall.ENOSYS, want: true},
		{name: "flag rejected by the filesystem", err: syscall.EINVAL, want: true},
		{name: "flag unsupported by the filesystem", err: syscall.EOPNOTSUPP, want: true},
		{name: "wrapped flag rejection", err: fmt.Errorf("publish restored file: %w", syscall.EINVAL), want: true},
		{name: "destination already exists", err: syscall.EEXIST, want: false},
		{name: "source disappeared", err: syscall.ENOENT, want: false},
		{name: "cross-device rename", err: syscall.EXDEV, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := renameFlagsUnsupported(test.err); got != test.want {
				t.Fatalf("renameFlagsUnsupported(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
