package dist

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadReleaseSetFallsBackAsACompleteSet(t *testing.T) {
	const filename = "security-update-notify-2.3.0.tar.gz"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mirror/"+filename+".sha256" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/mirror/"+filename || r.URL.Path == "/github/"+filename ||
			r.URL.Path == "/github/"+filename+".sha256" || r.URL.Path == "/github/"+filename+".asc" {
			io.WriteString(w, r.URL.Path)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	selected, err := DownloadReleaseSet(srv.Client(), []string{srv.URL + "/mirror", srv.URL + "/github"}, filename, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if selected != srv.URL+"/github" {
		t.Fatalf("selected = %q", selected)
	}
	for _, suffix := range []string{"", ".sha256", ".asc"} {
		b, err := os.ReadFile(filepath.Join(dir, filename+suffix))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "/github/"+filename+suffix {
			t.Errorf("%s contains %q", suffix, b)
		}
	}
}

func TestDownloadFailurePreservesDestinationAndRemovesTemporaryFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "response-too-large")
	}))
	defer srv.Close()
	dir := t.TempDir()
	dest := filepath.Join(dir, "asset")
	if err := os.WriteFile(dest, []byte("previous-complete-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := downloadWithLimit(srv.Client(), srv.URL+"/asset", dest, 4); err == nil {
		t.Fatal("oversized download was accepted")
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "previous-complete-file" {
		t.Fatalf("destination changed after failed download: %q err=%v", got, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".download-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary downloads left behind: %v err=%v", matches, err)
	}
}

func TestDownloadReleaseSetLimitsMetadata(t *testing.T) {
	const filename = "security-update-notify-2.3.0.tar.gz"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			_, _ = io.CopyN(w, zeroReader{}, maxReleaseMetadataBytes+1)
			return
		}
		_, _ = io.WriteString(w, "asset")
	}))
	defer srv.Close()
	if _, err := DownloadReleaseSet(srv.Client(), []string{srv.URL}, filename, t.TempDir(), false); err == nil {
		t.Fatal("oversized release metadata was accepted")
	}
}

func TestDownloadReleaseSetRejectsUnsafeFilenameAndDestination(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(filepath.Dir(dir), "escaped-release-asset")
	if _, err := DownloadReleaseSet(http.DefaultClient, []string{"https://example.invalid"}, "../escaped-release-asset", dir, false); err == nil {
		t.Fatal("path-traversing release filename was accepted")
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Fatalf("unsafe filename touched path outside destination: %v", err)
	}
	link := filepath.Join(t.TempDir(), "destination-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := DownloadReleaseSet(http.DefaultClient, []string{"https://example.invalid"}, "asset", link, false); err == nil {
		t.Fatal("symlink release destination was accepted")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
