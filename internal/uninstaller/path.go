package uninstaller

import (
	"errors"
	"fmt"

	"os"
	"path/filepath"
	"strings"
	"syscall"

	"unsafe"
)

func normalizeRoot(root string) (string, error) {
	if root == "" {
		root = string(filepath.Separator)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("uninstaller RootDir must be absolute: %q", root)
	}
	clean := filepath.Clean(root)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("resolve uninstaller RootDir: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect uninstaller RootDir: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("uninstaller RootDir must be a real directory: %q", root)
	}
	return resolved, nil
}

func rooted(root, logical string) string {
	return filepath.Join(root, strings.TrimPrefix(logical, string(filepath.Separator)))
}

// safePath rejects symlinked ancestors beneath RootDir before non-recursive
// operations. The leaf may be a symlink only when includeLeaf is false, in
// which case unlink removes the link itself rather than following it.
func safePath(root, logical string, includeLeaf bool) (string, error) {
	if !filepath.IsAbs(logical) {
		return "", fmt.Errorf("logical path must be absolute: %q", logical)
	}
	clean := filepath.Clean(logical)
	path := rooted(root, clean)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes RootDir: %q", logical)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	limit := len(parts)
	if !includeLeaf && limit > 0 {
		limit--
	}
	current := root
	for index := 0; index < limit; index++ {
		if parts[index] == "" || parts[index] == "." {
			continue
		}
		current = filepath.Join(current, parts[index])
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlinked path component is forbidden: %s", logical)
		}
		if index < limit-1 && !info.IsDir() {
			return "", fmt.Errorf("non-directory path component: %s", logical)
		}
	}
	return path, nil
}

func ensureSafeParent(root, logical string) error {
	_, err := safePath(root, logical, false)
	return err
}

func removeLogicalFile(root, logical string) error {
	return removeLogicalFileWithHook(root, logical, nil)
}

func removeLogicalSymlinkTarget(root, logical, target string) (bool, error) {
	return removeLogicalSymlinkTargetWithHook(root, logical, target, nil)
}

func removeLogicalSymlinkTargetWithHook(root, logical, target string, beforeClaim func() error) (bool, error) {
	return removeLogicalSymlinkTargetWithSync(root, logical, target, beforeClaim, syncLogicalRemovalParent)
}

func removeLogicalSymlinkTargetWithSync(root, logical, target string, beforeClaim func() error, syncParent func(*os.File) error) (bool, error) {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer parent.Close()
	if err := cleanupUninstallRemovalArtifacts(parent, trustedParentRemovalRecovery); err != nil {
		return false, fmt.Errorf("recover interrupted file removal: %w", err)
	}
	expected, linkTarget, err := inspectLogicalSymlinkAt(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		// The missing leaf may be the result of an earlier successful removal
		// whose directory sync failed. A retry must cross that durability
		// boundary before it can report success.
		return false, syncParent(parent)
	}
	if err != nil {
		return false, err
	}
	if expected == nil || linkTarget != target {
		return false, syncParent(parent)
	}
	if beforeClaim != nil {
		if err := beforeClaim(); err != nil {
			return false, err
		}
	}
	removeErr := removeValidatedEntryAt(parent, name, expected, removalLeaf)
	syncErr := syncParent(parent)
	if removeErr != nil {
		return false, errors.Join(removeErr, syncErr)
	}
	return true, syncErr
}

func syncLogicalRemovalParent(parent *os.File) error {
	directory, err := openRemovalDirectory(parent, ".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func inspectLogicalSymlinkAt(parent *os.File, name string) (os.FileInfo, string, error) {
	fd, err := syscall.Openat(
		int(parent.Fd()), name,
		oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, "", err
	}
	entry := os.NewFile(uintptr(fd), name)
	if entry == nil {
		_ = syscall.Close(fd)
		return nil, "", errors.New("could not create symbolic link handle")
	}
	defer entry.Close()
	info, err := entry.Stat()
	if err != nil {
		return nil, "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return nil, "", nil
	}
	for size := 256; size <= 1<<20; size *= 2 {
		buffer := make([]byte, size)
		n, err := readlinkOpenedEntry(entry, buffer)
		if err != nil {
			return nil, "", err
		}
		if n < len(buffer) {
			return info, string(buffer[:n]), nil
		}
	}
	return nil, "", errors.New("symbolic link target exceeds 1 MiB")
}

func readlinkOpenedEntry(entry *os.File, buffer []byte) (int, error) {
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return 0, err
	}
	result, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT, entry.Fd(), uintptr(unsafe.Pointer(empty)),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(result), nil
}

func removeLogicalFileWithHook(root, logical string, beforeClaim func() error) error {
	return removeLogicalFileWithSync(root, logical, beforeClaim, syncLogicalRemovalParent)
}

func removeLogicalFileWithRecovery(root, logical string, policy removalRecoveryPolicy) error {
	return removeLogicalFileWithSyncAndRecovery(root, logical, nil, syncLogicalRemovalParent, policy)
}

func removeLogicalFileWithSync(root, logical string, beforeClaim func() error, syncParent func(*os.File) error) (returnErr error) {
	return removeLogicalFileWithSyncAndRecovery(root, logical, beforeClaim, syncParent, trustedParentRemovalRecovery)
}

func removeLogicalFileWithSyncAndRecovery(root, logical string, beforeClaim func() error, syncParent func(*os.File) error, policy removalRecoveryPolicy) (returnErr error) {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, syncParent(parent), parent.Close())
	}()
	if err := cleanupUninstallRemovalArtifacts(parent, policy); err != nil {
		return fmt.Errorf("recover interrupted file removal: %w", err)
	}
	expected, err := readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if expected.IsDir() {
		return fmt.Errorf("refusing to remove directory as a file: %s", logical)
	}
	if beforeClaim != nil {
		if err := beforeClaim(); err != nil {
			return err
		}
	}
	return removeValidatedEntryAtWithHooks(parent, name, expected, removalLeaf, removalHooks{syncOwned: syncParent})
}

func removeLogicalEmptyDirectory(root, logical string) error {
	return removeLogicalEmptyDirectoryWithHook(root, logical, nil)
}

func removeLogicalEmptyDirectoryWithHook(root, logical string, beforeClaim func() error) error {
	return removeLogicalEmptyDirectoryWithSync(root, logical, beforeClaim, syncLogicalRemovalParent)
}

func removeLogicalEmptyDirectoryWithSync(root, logical string, beforeClaim func() error, syncParent func(*os.File) error) (returnErr error) {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, syncParent(parent), parent.Close())
	}()
	if err := cleanupUninstallRemovalArtifacts(parent, trustedParentRemovalRecovery); err != nil {
		return fmt.Errorf("recover interrupted directory removal: %w", err)
	}
	expected, err := readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !expected.IsDir() {
		return nil
	}
	empty, err := removalDirectoryEmpty(parent, name)
	if err != nil || !empty {
		return err
	}
	if beforeClaim != nil {
		if err := beforeClaim(); err != nil {
			return err
		}
	}
	return removeValidatedEntryAtWithHooks(parent, name, expected, removalEmptyDirectory, removalHooks{syncOwned: syncParent})
}

// removeLogicalTree resolves the parent beneath an opened RootDir descriptor
// and recursively removes entries relative to directory descriptors. Unlike a
// safePath check followed by os.RemoveAll, there is no pathname gap in which a
// checked ancestor can be replaced by a symlink to another tree.
func removeLogicalTree(root, logical string) error {
	return removeLogicalTreeWithHook(root, logical, nil)
}

func removeLogicalTreeWithHook(root, logical string, beforeClaim func() error) error {
	return removeLogicalTreeWithSync(root, logical, beforeClaim, syncLogicalRemovalParent)
}

func removeLogicalTreeWithSync(root, logical string, beforeClaim func() error, syncParent func(*os.File) error) (returnErr error) {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, syncParent(parent), parent.Close())
	}()
	if err := cleanupUninstallRemovalArtifacts(parent, trustedParentRemovalRecovery); err != nil {
		return fmt.Errorf("recover interrupted tree removal: %w", err)
	}
	return removeAllAtWithHooks(parent, name, beforeClaim, removalHooks{syncOwned: syncParent})
}

func openLogicalParent(root, logical string) (*os.File, string, error) {
	if !filepath.IsAbs(logical) {
		return nil, "", fmt.Errorf("logical path must be absolute: %q", logical)
	}
	clean := filepath.Clean(logical)
	if clean == string(filepath.Separator) {
		return nil, "", errors.New("refusing to remove uninstaller RootDir")
	}
	current, err := openRootHandle(root)
	if err != nil {
		return nil, "", err
	}
	walked := ""
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Dir(clean), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		walked += string(filepath.Separator) + component
		physical := component
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if openErr != nil && walked == "/usr/local/sbin" && validLocalSbinAliasAt(current, component) {
			physical = "bin"
			nextFD, openErr = syscall.Openat(
				int(current.Fd()), "bin",
				oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
				0,
			)
		}
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return nil, "", fmt.Errorf("symlinked path component or non-directory component is forbidden: %s", logical)
			}
			return nil, "", openErr
		}
		next := os.NewFile(uintptr(nextFD), filepath.Join(current.Name(), physical))
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return nil, "", errors.New("could not create uninstall directory handle")
		}
		_ = current.Close()
		current = next
	}
	return current, filepath.Base(clean), nil
}

func validLocalSbinAliasAt(parent *os.File, component string) bool {
	componentPointer, err := syscall.BytePtrFromString(component)
	if err != nil {
		return false
	}
	var target [4]byte
	result, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT,
		parent.Fd(), uintptr(unsafe.Pointer(componentPointer)), uintptr(unsafe.Pointer(&target[0])), uintptr(len(target)), 0, 0,
	)
	return errno == 0 && int(result) == len("bin") && string(target[:result]) == "bin"
}

func openRootHandle(root string) (*os.File, error) {
	fd, err := syscall.Open(
		string(filepath.Separator),
		oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), string(filepath.Separator))
	if current == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create uninstaller root handle")
	}
	if root == string(filepath.Separator) {
		return current, nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return nil, fmt.Errorf("uninstaller RootDir contains a symlinked or non-directory component: %s", root)
			}
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), filepath.Join(current.Name(), component))
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return nil, errors.New("could not create uninstaller root component handle")
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}
