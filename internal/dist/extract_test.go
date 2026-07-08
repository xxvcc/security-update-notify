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
		{Name: "top/install.sh", Typeflag: tar.TypeReg, Mode: 0o6755}, // setuid 位应被剥离
		{Name: "top/files/x", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"top/install.sh": "#!/bin/sh\n", "top/files/x": "hi"})

	dest := filepath.Join(dir, "out")
	os.MkdirAll(dest, 0o755)
	if err := Extract(tgz, dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "top/install.sh"))
	if err != nil || string(b) != "#!/bin/sh\n" {
		t.Errorf("install.sh content=%q err=%v", b, err)
	}
	fi, _ := os.Stat(filepath.Join(dest, "top/install.sh"))
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
	os.WriteFile(shaFile, []byte("deadbeef\n"), 0o644)
	if err := VerifySHA256(data, shaFile); err == nil {
		t.Error("VerifySHA256 should reject non-64-hex")
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
