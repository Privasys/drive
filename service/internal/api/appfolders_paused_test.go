package api

import (
	"net/http"
	"testing"
)

// TestAppFoldersArePaused proves no app-folder route reads or forwards a
// holder token while app folders are paused: every route answers 503 before
// anything is resolved or fetched.
func TestAppFoldersArePaused(t *testing.T) {
	ts := newFullServer(t, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/app-folders"},
		{"GET", "/v1/app-folders/0123456789abcdef0123456789abcdef/files"},
		{"DELETE", "/v1/app-folders/0123456789abcdef0123456789abcdef/files?path=x"},
	} {
		req, _ := http.NewRequest(c.method, ts.URL+c.path, nil)
		req.Header.Set("Authorization", devAuth)
		req.Header.Set(holderTokenHeader, "a-holder-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: want 503, got %d", c.method, c.path, resp.StatusCode)
		}
	}
}
