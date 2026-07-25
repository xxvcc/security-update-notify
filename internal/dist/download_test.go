package dist

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
