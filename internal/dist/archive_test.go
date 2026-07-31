package dist

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTarGz 把给定 header（Size=0 的普通文件写空内容）打进一个 .tar.gz 临时文件，返回路径。
func buildTarGz(t *testing.T, hdrs []*tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "a.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func reg(name string) *tar.Header { return &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644} }
func dir(name string) *tar.Header { return &tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755} }
func link(name string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}
}

func TestCheckArchive(t *testing.T) {
	const top = "security-update-notify-9.9.9"
	cases := []struct {
		name    string
		hdrs    []*tar.Header
		wantErr bool
	}{
		{"good", []*tar.Header{dir(top + "/"), reg(top + "/VERSION"), reg(top + "/files/x")}, false},
		{"symlink-rejected", []*tar.Header{dir(top + "/"), link(top + "/bad-link")}, true},
		{"absolute-rejected", []*tar.Header{reg("/etc/passwd")}, true},
		{"traversal-rejected", []*tar.Header{reg(top + "/../evil")}, true},
		{"outside-top-rejected", []*tar.Header{reg("other-dir/x")}, true},
		// path.Clean 泄漏点：`./top/...` 必须被拒（与 Bash glob 等价），不得被规范化后放行。
		{"dot-slash-top-rejected", []*tar.Header{reg("./" + top + "/x")}, true},
		{"empty-archive-rejected", []*tar.Header{}, true},
		{"wrong-top-rejected", []*tar.Header{reg("security-update-notify-1.0.0/x")}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := buildTarGz(t, c.hdrs)
			err := CheckArchive(path, top)
			if (err != nil) != c.wantErr {
				t.Errorf("CheckArchive() err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestArchiveEntryLimit(t *testing.T) {
	const top = "security-update-notify-9.9.9"
	headers := make([]*tar.Header, 0, maxArchiveEntries+1)
	for i := 0; i <= maxArchiveEntries; i++ {
		headers = append(headers, reg(filepath.Join(top, fmt.Sprintf("file-%05d", i))))
	}
	path := buildTarGz(t, headers)
	if err := CheckArchive(path, top); err == nil {
		t.Fatal("archive entry bomb passed safety check")
	}
	if err := Extract(path, t.TempDir()); err == nil {
		t.Fatal("archive entry bomb was extracted")
	}
}

func TestArchiveReadersRejectCorruptedGzipFooter(t *testing.T) {
	const top = "security-update-notify-9.9.9"
	path := buildTarGz(t, []*tar.Header{dir(top + "/"), reg(top + "/VERSION")})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 8 {
		t.Fatal("test gzip stream is unexpectedly short")
	}
	b[len(b)-1] ^= 0xff // corrupt the gzip ISIZE footer without changing tar bytes
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckArchive(path, top); err == nil {
		t.Fatal("archive check accepted a corrupt gzip footer")
	}
	if err := Extract(path, t.TempDir()); err == nil {
		t.Fatal("archive extraction accepted a corrupt gzip footer")
	}
}

func TestArchiveReadersRejectConcatenatedGzipStreams(t *testing.T) {
	const top = "security-update-notify-9.9.9"
	path := buildTarGz(t, []*tar.Header{dir(top + "/"), reg(top + "/VERSION")})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte("unchecked second gzip member")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckArchive(path, top); err == nil {
		t.Fatal("archive check accepted concatenated gzip members")
	}
	if err := Extract(path, t.TempDir()); err == nil {
		t.Fatal("archive extraction accepted concatenated gzip members")
	}
}

func TestArchiveReadersRejectNonZeroDataAfterTarEnd(t *testing.T) {
	const top = "security-update-notify-9.9.9"
	path := buildTarGz(t, []*tar.Header{dir(top + "/"), reg(top + "/VERSION")})
	compressed, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		_ = compressed.Close()
		t.Fatal(err)
	}
	tarBytes, err := io.ReadAll(gz)
	if err != nil {
		_ = gz.Close()
		_ = compressed.Close()
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		_ = compressed.Close()
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}

	output, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzWriter := gzip.NewWriter(output)
	if _, err := gzWriter.Write(append(tarBytes, []byte("hidden trailing payload")...)); err != nil {
		_ = gzWriter.Close()
		_ = output.Close()
		t.Fatal(err)
	}
	if err := gzWriter.Close(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckArchive(path, top); err == nil {
		t.Fatal("archive check accepted a non-zero payload after the tar end marker")
	}
	if err := Extract(path, t.TempDir()); err == nil {
		t.Fatal("archive extraction accepted a non-zero payload after the tar end marker")
	}
}

func TestArchivePathResourceLimits(t *testing.T) {
	const top = "security-update-notify-9.9.9"
	cases := map[string]string{
		"bytes":     top + "/" + strings.Repeat(strings.Repeat("p", 240)+"/", 17) + "payload",
		"depth":     top + "/" + strings.Repeat("d/", maxArchivePathDepth) + "payload",
		"component": top + "/" + strings.Repeat("x", maxArchiveComponentBytes+1),
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			path := buildTarGz(t, []*tar.Header{reg(entry)})
			if err := CheckArchive(path, top); err == nil {
				t.Fatal("archive check accepted an over-limit path")
			}
			if err := Extract(path, t.TempDir()); err == nil {
				t.Fatal("archive extraction accepted an over-limit path")
			}
		})
	}
}

func TestArchiveTotalPathComponentLimit(t *testing.T) {
	const top = "security-update-notify-9.9.9"
	const componentsPerEntry = 16
	prefix := top + "/" + strings.Repeat("d/", componentsPerEntry-2)
	entryCount := maxArchivePathComponents/componentsPerEntry + 1
	headers := make([]*tar.Header, 0, entryCount)
	for index := 0; index < entryCount; index++ {
		headers = append(headers, reg(prefix+fmt.Sprintf("file-%05d", index)))
	}
	if err := CheckArchive(buildTarGz(t, headers), top); err == nil {
		t.Fatal("archive check accepted an excessive total path-component workload")
	}
}
