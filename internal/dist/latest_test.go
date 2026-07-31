package dist

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestReleaseMetadataErrorsDoNotExposeURLQuery(t *testing.T) {
	const secret = "private-query-token"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	errURL := server.URL + "/latest.json?token=" + secret
	if _, err := getReleaseJSON(server.Client(), errURL, "application/json"); err == nil {
		t.Fatal("non-200 metadata response was accepted")
	} else if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("metadata error exposed request URL: %v", err)
	}
}

func TestLatestReleaseRejectsOversizedOrTrailingJSON(t *testing.T) {
	for name, body := range map[string]string{
		"oversized": strings.Repeat("x", maxReleaseJSONBytes+1),
		"trailing":  `{"tag_name":"v2.3.1"}{"tag_name":"v9.9.9"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, body)
			}))
			defer srv.Close()
			oldMirror, oldGitHub := releaseMirrorBase, githubAPIBase
			releaseMirrorBase = ""
			githubAPIBase = srv.URL
			defer func() { releaseMirrorBase, githubAPIBase = oldMirror, oldGitHub }()
			if _, err := LatestRelease(srv.Client(), "x/y"); err == nil {
				t.Fatal("invalid release JSON was accepted")
			}
		})
	}
}

func TestLatestReleaseRejectsUnsafeVersion(t *testing.T) {
	for name, version := range map[string]string{
		"newline":                         "2.3.1\nforged",
		"slash":                           "2.3.1/asset",
		"long":                            strings.Repeat("1", 129),
		"text":                            "abc",
		"double-v":                        "v2.3.1",
		"underscore":                      "1_2",
		"empty-segment":                   "1..2",
		"numeric-prerelease-leading-zero": "1.2.3-01",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				body, _ := json.Marshal(map[string]string{"tag_name": "v" + version})
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			oldMirror, oldGitHub := releaseMirrorBase, githubAPIBase
			releaseMirrorBase = ""
			githubAPIBase = srv.URL
			defer func() { releaseMirrorBase, githubAPIBase = oldMirror, oldGitHub }()
			if _, err := LatestRelease(srv.Client(), "x/y"); err == nil {
				t.Fatal("unsafe release version was accepted")
			}
		})
	}
}

func TestLatestReleaseRequiresCanonicalGitHubTagPrefix(t *testing.T) {
	for _, tag := range []string{"2.3.1", "vv2.3.1"} {
		t.Run(tag, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				body, _ := json.Marshal(map[string]string{"tag_name": tag})
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			oldMirror, oldGitHub := releaseMirrorBase, githubAPIBase
			releaseMirrorBase = ""
			githubAPIBase = srv.URL
			defer func() { releaseMirrorBase, githubAPIBase = oldMirror, oldGitHub }()
			if _, err := LatestRelease(srv.Client(), "x/y"); err == nil {
				t.Fatalf("non-canonical GitHub tag %q was accepted", tag)
			}
		})
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
