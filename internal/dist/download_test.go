package dist

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingRoundTripper struct{ err error }

func (t failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

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

func TestDownloadCommitsPrivateRegularFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "complete")
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "asset")
	if err := downloadWithLimit(srv.Client(), srv.URL+"/asset", dest, 32); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("downloaded mode=%v, want regular 0600", info.Mode())
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

func TestDownloadReleaseSetFailurePreservesExistingCompleteSet(t *testing.T) {
	const filename = "security-update-notify-2.3.0.tar.gz"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "uncommitted replacement")
	}))
	defer srv.Close()
	dir := t.TempDir()
	for _, suffix := range []string{"", ".sha256", ".asc"} {
		if err := os.WriteFile(filepath.Join(dir, filename+suffix), []byte("previous"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := DownloadReleaseSet(srv.Client(), []string{srv.URL}, filename, dir, true); err == nil {
		t.Fatal("incomplete replacement set was accepted")
	}
	for _, suffix := range []string{"", ".sha256", ".asc"} {
		got, err := os.ReadFile(filepath.Join(dir, filename+suffix))
		if err != nil || string(got) != "previous"+suffix {
			t.Fatalf("existing %s asset changed after fallback failure: %q err=%v", suffix, got, err)
		}
	}
	for _, pattern := range []string{".download-*", ".download-backup-*"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil || len(matches) != 0 {
			t.Fatalf("download transaction left %s residue: %v err=%v", pattern, matches, err)
		}
	}
}

func TestCommitDownloadedSetRollsBackEveryPreviousAsset(t *testing.T) {
	dir := t.TempDir()
	directory, err := openRealDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	for name, contents := range map[string]string{
		"asset":        "previous archive",
		"asset.sha256": "previous checksum",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	staged, err := os.CreateTemp(dir, ".download-test-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.WriteString("replacement archive"); err != nil {
		_ = staged.Close()
		t.Fatal(err)
	}
	stagedName := filepath.Base(staged.Name())
	if err := staged.Close(); err != nil {
		t.Fatal(err)
	}

	err = commitDownloadedSet(directory, [][2]string{
		{stagedName, "asset"},
		{"missing-staged-checksum", "asset.sha256"},
	})
	if err == nil {
		t.Fatal("commit with a missing staged asset unexpectedly succeeded")
	}
	for name, want := range map[string]string{
		"asset":        "previous archive",
		"asset.sha256": "previous checksum",
	} {
		got, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil || string(got) != want {
			t.Fatalf("%s after rollback = %q err=%v, want %q", name, got, readErr, want)
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".download-backup-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("rollback left backup residue: %v err=%v", matches, err)
	}
}

func TestCommitDownloadedSetRejectsAndRestoresDirectoryTarget(t *testing.T) {
	dir := t.TempDir()
	directory, err := openRealDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := os.Mkdir(filepath.Join(dir, "asset"), 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := os.CreateTemp(dir, ".download-test-")
	if err != nil {
		t.Fatal(err)
	}
	stagedName := filepath.Base(staged.Name())
	if err := staged.Close(); err != nil {
		t.Fatal(err)
	}
	if err := commitDownloadedSet(directory, [][2]string{{stagedName, "asset"}}); err == nil {
		t.Fatal("directory target was accepted as a previous download")
	}
	info, err := os.Lstat(filepath.Join(dir, "asset"))
	if err != nil || !info.IsDir() {
		t.Fatalf("directory target was not restored: mode=%v err=%v", info, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".download-backup-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("directory-target rollback left backup residue: %v err=%v", matches, err)
	}
}

func TestDownloadRemainsBoundToOpenedDestinationDirectory(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	moved := filepath.Join(root, "opened-destination")
	external := filepath.Join(root, "external")
	for _, path := range []string{destination, external} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	reader := &callbackReader{
		Reader: bytes.NewReader([]byte("verified destination bytes")),
		callback: func() error {
			if err := os.Rename(destination, moved); err != nil {
				return err
			}
			return os.Symlink(external, destination)
		},
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(reader),
			Request:    req,
			Header:     make(http.Header),
		}, nil
	})}
	if err := Download(client, "https://downloads.example.test/asset", filepath.Join(destination, "asset")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(moved, "asset"))
	if err != nil || string(got) != "verified destination bytes" {
		t.Fatalf("opened destination contains %q err=%v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(external, "asset")); !os.IsNotExist(err) {
		t.Fatalf("replacement destination received download: %v", err)
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

func TestDownloadErrorsDoNotExposeSourceURL(t *testing.T) {
	const secret = "private-query-token"
	client := &http.Client{Transport: failingRoundTripper{err: errors.New("forced transport failure")}}
	_, err := DownloadReleaseSet(client, []string{"https://downloads.example.test/releases?token=" + secret}, "asset", t.TempDir(), false)
	if err == nil {
		t.Fatal("forced request failure unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "downloads.example.test") {
		t.Fatalf("download error exposed source URL: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type callbackReader struct {
	io.Reader
	callback func() error
	done     bool
}

func (r *callbackReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		if err := r.callback(); err != nil {
			return 0, err
		}
	}
	return r.Reader.Read(p)
}
