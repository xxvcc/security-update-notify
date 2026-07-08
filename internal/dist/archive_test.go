package dist

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
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
		{"good", []*tar.Header{dir(top + "/"), reg(top + "/install.sh"), reg(top + "/files/x")}, false},
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
