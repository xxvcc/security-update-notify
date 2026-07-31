package filetrust

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureDirectoryCreatesAndPreservesProtectedModes(t *testing.T) {
	root := t.TempDir()
	created := filepath.Join(root, "created")
	if err := EnsureDirectory(created, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(created)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("created mode=%#o want 0750", info.Mode().Perm())
	}

	strict := filepath.Join(root, "strict")
	if err := os.Mkdir(strict, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDirectory(strict, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(strict)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("existing strict mode was widened to %#o", info.Mode().Perm())
	}
}

func TestExistingDirectoryFailsClosedWithoutChangingUnsafePaths(t *testing.T) {
	root := t.TempDir()
	wide := filepath.Join(root, "wide")
	if err := os.Mkdir(wide, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDirectory(wide, os.Geteuid()); err == nil {
		t.Fatal("group/other-writable directory was accepted")
	}
	info, err := os.Lstat(wide)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("unsafe directory was chmodded before validation: %#o", info.Mode().Perm())
	}

	link := filepath.Join(root, "link")
	if err := os.Symlink(wide, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ExistingDirectory(link, os.Geteuid()); err == nil {
		t.Fatal("symlinked directory was accepted")
	}
	if _, err := ExistingDirectory(wide, os.Geteuid()+1); err == nil {
		t.Fatal("wrong-owner directory was accepted")
	}
}

func TestValidateRegularMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRegular(info, os.Geteuid(), 0o022, true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRegular(info, os.Geteuid()+1, 0o022, true); err == nil {
		t.Fatal("wrong-owner file was accepted")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRegular(info, os.Geteuid(), 0o022, true); err == nil {
		t.Fatal("group/other-writable file was accepted")
	}
}

func TestMetadataWithoutStatFailsClosed(t *testing.T) {
	if err := ValidateDirectory(fakeInfo{mode: os.ModeDir | 0o700}, os.Geteuid(), 0o022); err == nil {
		t.Fatal("directory without syscall metadata was accepted")
	}
	if err := ValidateRegular(fakeInfo{mode: 0o600}, os.Geteuid(), 0o022, true); err == nil {
		t.Fatal("file without syscall metadata was accepted")
	}
}

type fakeInfo struct{ mode fs.FileMode }

func (fakeInfo) Name() string        { return "fake" }
func (fakeInfo) Size() int64         { return 0 }
func (f fakeInfo) Mode() fs.FileMode { return f.mode }
func (fakeInfo) ModTime() time.Time  { return time.Time{} }
func (f fakeInfo) IsDir() bool       { return f.mode.IsDir() }
func (fakeInfo) Sys() any            { return nil }
