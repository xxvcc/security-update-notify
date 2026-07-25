package dist

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLatestRelease(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/xxvcc/security-update-notify/releases/latest" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"tag_name":"v2.1.0","name":"2.1.0"}`)
	}))
	defer srv.Close()
	oldMirror, oldGitHub := releaseMirrorBase, githubAPIBase
	releaseMirrorBase = ""
	githubAPIBase = srv.URL
	defer func() { releaseMirrorBase, githubAPIBase = oldMirror, oldGitHub }()

	got, err := LatestRelease(srv.Client(), "xxvcc/security-update-notify")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2.1.0" { // 去掉一个前导 v
		t.Errorf("LatestRelease = %q want 2.1.0", got)
	}
}

func TestLatestReleaseNon200(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403) // rate limited
	}))
	defer srv.Close()
	oldMirror, oldGitHub := releaseMirrorBase, githubAPIBase
	releaseMirrorBase = ""
	githubAPIBase = srv.URL
	defer func() { releaseMirrorBase, githubAPIBase = oldMirror, oldGitHub }()

	if _, err := LatestRelease(srv.Client(), "x/y"); err == nil {
		t.Error("expected error on non-200")
	}
}

func TestLatestReleaseUsesMirror(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/latest.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, `{"version":"2.3.0","tag":"v2.3.0","base_url":"`+srv.URL+`/v2.3.0"}`)
	}))
	defer srv.Close()
	oldMirror, oldGitHub := releaseMirrorBase, githubAPIBase
	releaseMirrorBase = srv.URL
	githubAPIBase = "https://github.invalid"
	defer func() { releaseMirrorBase, githubAPIBase = oldMirror, oldGitHub }()

	got, err := LatestRelease(srv.Client(), "xxvcc/security-update-notify")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2.3.0" {
		t.Fatalf("LatestRelease = %q want 2.3.0", got)
	}
}

func TestLatestReleaseFallsBackToGitHub(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mirror/latest.json":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/repos/xxvcc/security-update-notify/releases/latest":
			io.WriteString(w, `{"tag_name":"v2.3.1"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	oldMirror, oldGitHub := releaseMirrorBase, githubAPIBase
	releaseMirrorBase = srv.URL + "/mirror"
	githubAPIBase = srv.URL
	defer func() { releaseMirrorBase, githubAPIBase = oldMirror, oldGitHub }()

	got, err := LatestRelease(srv.Client(), "xxvcc/security-update-notify")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2.3.1" {
		t.Fatalf("LatestRelease = %q want 2.3.1", got)
	}
}

func TestReleaseBasesMirrorThenGitHub(t *testing.T) {
	oldMirror, oldDownload := releaseMirrorBase, githubDownloadBase
	releaseMirrorBase = "https://mirror.example/releases/"
	githubDownloadBase = "https://github.example/"
	defer func() { releaseMirrorBase, githubDownloadBase = oldMirror, oldDownload }()

	got := ReleaseBases("owner/repo", "2.3.0")
	want := []string{
		"https://mirror.example/releases/v2.3.0",
		"https://github.example/owner/repo/releases/download/v2.3.0",
	}
	if len(got) != len(want) {
		t.Fatalf("ReleaseBases = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ReleaseBases[%d] = %q want %q", i, got[i], want[i])
		}
	}
}
