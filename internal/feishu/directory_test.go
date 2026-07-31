package feishu

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanDirectoryPaginatesAndAcceptsStaleFinalToken(t *testing.T) {
	var directoryCalls int32
	c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			io.WriteString(w, `{"code":0,"tenant_access_token":"tenant-token"}`)
		case "/open-apis/directory/v1/employees/filter":
			if r.Header.Get("Authorization") != "Bearer tenant-token" || r.URL.Query().Get("employee_id_type") != "open_id" {
				t.Errorf("unexpected auth or query: %q %q", r.Header.Get("Authorization"), r.URL.RawQuery)
			}
			var body struct {
				Required []string `json:"required_fields"`
				Page     struct {
					Token string `json:"page_token"`
				} `json:"page_request"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if strings.Join(body.Required, ",") != "base_info.employee_id,base_info.name,base_info.mobile" {
				t.Errorf("required_fields=%v", body.Required)
			}
			call := atomic.AddInt32(&directoryCalls, 1)
			if call == 1 && body.Page.Token == "" {
				io.WriteString(w, directoryPageJSON(true, "next", `
                  {"base_info":{"employee_id":"ou_first","mobile":"+8613812341234","name":{"name":{"i18n_value":{"zh_cn":"王小明"},"default_value":"First"}}}},
                  {"base_info":{"employee_id":"bad-id","mobile":"1234"}}`))
				return
			}
			if call == 2 && body.Page.Token == "next" {
				// Feishu can retain the request token on the final page. This is complete, not a loop.
				io.WriteString(w, directoryPageJSON(false, "next", `
                  {"base_info":{"employee_id":"ou_first","mobile":"0000"}},
                  {"base_info":{"employee_id":"ou_second","mobile":"","name":{"name":{"default_value":"Fallback Name"}}}}`))
				return
			}
			http.Error(w, "unexpected page", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	users, err := c.ScanDirectory(context.Background(), "cli_test", "secret")
	if err != nil {
		t.Fatal(err)
	}
	want := []DirectoryUser{
		{Name: "王小明", MobileTail: "1234", OpenID: "ou_first"},
		{Name: "Fallback Name", MobileTail: "", OpenID: "ou_second"},
	}
	if fmt.Sprint(users) != fmt.Sprint(want) {
		t.Fatalf("users=%v want %v", users, want)
	}
}

func TestSanitizeDisplayHintRemovesTerminalAndBidiControls(t *testing.T) {
	input := "Alice\x1b]0;spoof\a\n\u202eAdmin\u2028Fake\u2029Entry"
	if got, want := sanitizeDisplayHint(input), "Alice]0;spoofAdminFakeEntry"; got != want {
		t.Fatalf("sanitizeDisplayHint(%q)=%q want %q", input, got, want)
	}
	if got := sanitizeDisplayHint("王小明"); got != "王小明" {
		t.Fatalf("ordinary international name changed: %q", got)
	}
}

func TestScanDirectoryRejectsBrokenPaginationAndPartialResults(t *testing.T) {
	tests := map[string]func(call int32) string{
		"repeated token": func(call int32) string {
			return directoryPageJSON(true, "same", "")
		},
		"missing token": func(call int32) string {
			return directoryPageJSON(true, "", "")
		},
		"abnormals": func(call int32) string {
			return `{"code":0,"data":{"employees":[],"abnormals":[{"field":"name"}],"page_response":{"has_more":false}}}`
		},
		"missing has_more": func(call int32) string {
			return `{"code":0,"data":{"employees":[],"abnormals":[],"page_response":{}}}`
		},
		"null has_more": func(call int32) string {
			return `{"code":0,"data":{"employees":[],"abnormals":[],"page_response":{"has_more":null}}}`
		},
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			var calls int32
			c, srv, _ := newTestClient(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "tenant_access_token") {
					io.WriteString(w, `{"code":0,"tenant_access_token":"token"}`)
					return
				}
				io.WriteString(w, response(atomic.AddInt32(&calls, 1)))
			})
			defer srv.Close()
			_, err := c.ScanDirectory(context.Background(), "cli_test", "secret")
			if err == nil {
				t.Fatal("expected error")
			}
			want := map[string]string{
				"repeated token":   "repeated a page token",
				"missing token":    "without a page token",
				"abnormals":        "abnormals returned",
				"missing has_more": "page_response.has_more missing",
				"null has_more":    "page_response.has_more missing",
			}[name]
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v want %q", err, want)
			}
		})
	}
}

func TestScanDirectoryRetriesFeishuRateLimitCode(t *testing.T) {
	var calls int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "tenant_access_token") {
			io.WriteString(w, `{"code":0,"tenant_access_token":"token"}`)
			return
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			io.WriteString(w, `{"code":99991400}`)
			return
		}
		io.WriteString(w, directoryPageJSON(false, "", ""))
	})
	defer srv.Close()
	c.Sleep = func(time.Duration) { atomic.AddInt32(slept, 1) }
	if _, err := c.ScanDirectory(context.Background(), "cli_test", "secret"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || *slept != 1 {
		t.Fatalf("calls=%d sleeps=%d want 2,1", calls, *slept)
	}
}

func TestScanDirectoryRetriesNonJSONServerFailure(t *testing.T) {
	var calls int32
	c, srv, slept := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "tenant_access_token") {
			io.WriteString(w, `{"code":0,"tenant_access_token":"token"}`)
			return
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "<html>temporary gateway failure</html>")
			return
		}
		io.WriteString(w, directoryPageJSON(false, "", ""))
	})
	defer srv.Close()
	if _, err := c.ScanDirectory(context.Background(), "cli_test", "secret"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || *slept != 1 {
		t.Fatalf("calls=%d sleeps=%d want 2,1", calls, *slept)
	}
}

func TestScanDirectoryRetriesInterruptedResponseBody(t *testing.T) {
	var directoryRequests int32
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body io.Reader
		if strings.Contains(req.URL.Path, "tenant_access_token") {
			body = strings.NewReader(`{"code":0,"tenant_access_token":"token"}`)
		} else if atomic.AddInt32(&directoryRequests, 1) == 1 {
			body = io.MultiReader(strings.NewReader(`{"code":0,`), interruptedReader{})
		} else {
			body = strings.NewReader(directoryPageJSON(false, "", ""))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(body)}, nil
	})}
	c := &Client{HTTP: client, BaseURL: "https://open.feishu.test", Sleep: func(time.Duration) {}}
	users, err := c.ScanDirectory(context.Background(), "cli_app", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 || directoryRequests != 2 {
		t.Fatalf("users=%v directory requests=%d, want empty,2", users, directoryRequests)
	}
}

func TestScanDirectoryDoesNotFollowRedirect(t *testing.T) {
	var targetCalls int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&targetCalls, 1)
		io.WriteString(w, directoryPageJSON(false, "", ""))
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "tenant_access_token") {
			io.WriteString(w, `{"code":0,"tenant_access_token":"token"}`)
			return
		}
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := &Client{HTTP: source.Client(), BaseURL: source.URL, Sleep: func(time.Duration) {}}
	if _, err := c.ScanDirectory(context.Background(), "cli_test", "secret"); err == nil {
		t.Fatal("redirect was accepted")
	}
	if targetCalls != 0 {
		t.Fatalf("credential-bearing redirect reached target %d times", targetCalls)
	}
}

func directoryPageJSON(hasMore bool, token, employees string) string {
	if employees != "" {
		employees = "[" + employees + "]"
	} else {
		employees = "[]"
	}
	return fmt.Sprintf(`{"code":0,"data":{"employees":%s,"abnormals":[],"page_response":{"has_more":%t,"page_token":%q}}}`, employees, hasMore, token)
}
