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
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

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
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	if _, err := LatestRelease(srv.Client(), "x/y"); err == nil {
		t.Error("expected error on non-200")
	}
}
