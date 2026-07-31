package dist

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTarGz(t *testing.T, path string, entries []*tar.Header, bodies map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		if body, ok := bodies[h.Name]; ok {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if body, ok := bodies[h.Name]; ok {
			io.WriteString(tw, body)
		}
	}
	tw.Close()
	gz.Close()
}

func TestExtractGood(t *testing.T) {
	dir := t.TempDir()
	tgz := filepath.Join(dir, "a.tar.gz")
	writeTarGz(t, tgz, []*tar.Header{
		{Name: "top/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "top/files/runtime", Typeflag: tar.TypeReg, Mode: 0o6755}, // setuid 位应被剥离
		{Name: "top/files/x", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"top/files/runtime": "runtime", "top/files/x": "hi"})

	dest := filepath.Join(dir, "out")
	os.MkdirAll(dest, 0o755)
	if err := Extract(tgz, dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "top/files/runtime"))
	if err != nil || string(b) != "runtime" {
		t.Errorf("runtime content=%q err=%v", b, err)
	}
	fi, _ := os.Stat(filepath.Join(dest, "top/files/runtime"))
	if fi.Mode()&os.ModeSetuid != 0 {
		t.Error("setuid bit was not stripped")
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("perm=%o want 0755", fi.Mode().Perm())
	}
}

func TestExtractRejectsSpecialAndTraversal(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]*tar.Header{
		"symlink":   {{Name: "top/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}},
		"absolute":  {{Name: "/etc/evil", Typeflag: tar.TypeReg, Mode: 0o644}},
		"traversal": {{Name: "top/../evil", Typeflag: tar.TypeReg, Mode: 0o644}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			tgz := filepath.Join(dir, name+".tar.gz")
			writeTarGz(t, tgz, entries, nil)
			dest := filepath.Join(dir, name+"-out")
			os.MkdirAll(dest, 0o755)
			if err := Extract(tgz, dest); err == nil {
				t.Errorf("Extract(%s) should have rejected", name)
			}
		})
	}
}

func TestExtractRejectsPreexistingSymlinkedDestinationPaths(t *testing.T) {
	dir := t.TempDir()
	tgz := filepath.Join(dir, "symlink-parent.tar.gz")
	writeTarGz(t, tgz, []*tar.Header{
		{Name: "top/files/payload", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"top/files/payload": "must stay inside destination"})

	dest := filepath.Join(dir, "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(dest, "top")); err != nil {
		t.Fatal(err)
	}
	if err := Extract(tgz, dest); err == nil {
		t.Fatal("pre-existing symlinked archive parent was followed")
	}
	if _, err := os.Lstat(filepath.Join(external, "files")); !os.IsNotExist(err) {
		t.Fatalf("extraction changed a path outside the destination: %v", err)
	}

	destLink := filepath.Join(dir, "out-link")
	if err := os.Symlink(dest, destLink); err != nil {
		t.Fatal(err)
	}
	if err := Extract(tgz, destLink); err == nil {
		t.Fatal("symlinked extraction destination was accepted")
	}
}

func TestExtractRemainsBoundToOpenedDestinationDirectory(t *testing.T) {
	root := t.TempDir()
	tgz := filepath.Join(root, "bound.tar.gz")
	writeTarGz(t, tgz, []*tar.Header{
		{Name: "top/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "top/payload", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"top/payload": "bound to opened directory"})
	destination := filepath.Join(root, "destination")
	moved := filepath.Join(root, "opened-destination")
	external := filepath.Join(root, "external")
	for _, path := range []string{destination, external} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := openRealDirectory(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := os.Rename(destination, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, destination); err != nil {
		t.Fatal(err)
	}
	if err := extractIntoDirectory(tgz, directory); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(moved, "top", "payload"))
	if err != nil || string(got) != "bound to opened directory" {
		t.Fatalf("opened destination contains %q err=%v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(external, "top")); !os.IsNotExist(err) {
		t.Fatalf("replacement destination received extracted data: %v", err)
	}
}

func TestExtractRejectsOutOfRangeModes(t *testing.T) {
	dir := t.TempDir()
	for name, mode := range map[string]int64{
		"negative":  -1,
		"oversized": 0o10000,
	} {
		t.Run(name, func(t *testing.T) {
			tgz := filepath.Join(dir, name+".tar.gz")
			writeTarGz(t, tgz, []*tar.Header{{Name: "top/file", Typeflag: tar.TypeReg, Mode: mode}}, nil)
			dest := filepath.Join(dir, name+"-out")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := Extract(tgz, dest); err == nil {
				t.Fatalf("Extract accepted archive mode %#o", mode)
			}
		})
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "pkg.tar.gz")
	os.WriteFile(data, []byte("hello release"), 0o644)
	sum := sha256.Sum256([]byte("hello release"))
	shaFile := data + ".sha256"
	os.WriteFile(shaFile, []byte(hex.EncodeToString(sum[:])+"  pkg.tar.gz\n"), 0o644)
	if err := VerifySHA256(data, shaFile); err != nil {
		t.Errorf("VerifySHA256 good: %v", err)
	}
	malformed := map[string]string{
		"short digest":   "deadbeef\n",
		"wrong filename": hex.EncodeToString(sum[:]) + "  other.tar.gz\n",
		"multiple lines": hex.EncodeToString(sum[:]) + "  pkg.tar.gz\n" + hex.EncodeToString(sum[:]) + "  other.tar.gz\n",
		"one space":      hex.EncodeToString(sum[:]) + " pkg.tar.gz\n",
		"binary marker":  hex.EncodeToString(sum[:]) + " *pkg.tar.gz\n",
		"no newline":     hex.EncodeToString(sum[:]) + "  pkg.tar.gz",
		"trailing space": hex.EncodeToString(sum[:]) + "  pkg.tar.gz \n",
	}
	for name, contents := range malformed {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(shaFile, []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := VerifySHA256(data, shaFile); err == nil {
				t.Fatal("malformed checksum file was accepted")
			}
		})
	}
	if err := os.WriteFile(shaFile, []byte(strings.Repeat("x", maxReleaseMetadataBytes+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifySHA256(data, shaFile); err == nil {
		t.Error("oversized checksum file was accepted")
	}
}

func TestVerifySHA256RejectsSymlinkedInputs(t *testing.T) {
	dir := t.TempDir()
	realArchive := filepath.Join(dir, "real.tar.gz")
	if err := os.WriteFile(realArchive, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "pkg.tar.gz")
	if err := os.Symlink(realArchive, archive); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("archive"))
	checksum := filepath.Join(dir, "pkg.tar.gz.sha256")
	if err := os.WriteFile(checksum, []byte(hex.EncodeToString(sum[:])+"  pkg.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySHA256(archive, checksum); err == nil {
		t.Fatal("symlinked archive was accepted for checksum verification")
	}
}

func TestDownload(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "payload-bytes")
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "f")
	if err := Download(srv.Client(), srv.URL+"/x", dest); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dest)
	if string(b) != "payload-bytes" {
		t.Errorf("downloaded %q", b)
	}
	// 非 https 必须被拒。
	if err := Download(srv.Client(), "http://example.com/x", dest); err == nil {
		t.Error("Download should reject non-https")
	}
}
