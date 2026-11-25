package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// operatorReq is a request from the instance operator, as the runtime
// states it on a route the manifest declares "owner".
func operatorReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	t.Setenv(configureGrantEnv, "1")
	req := authedReq(t, method, url, body)
	req.Header.Del("Authorization")
	req.Header.Set(configureGrantHeader, "role=owner; sub=user-1")
	return req
}

func doOperatorGet(t *testing.T, ts *httptest.Server, path string) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(operatorReq(t, "GET", ts.URL+path, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, raw)
	}
	return string(raw)
}

// TestTenantKeyRoutesAreOperatorOnly: every tenant-key admin route refuses an
// ordinary signed-in user (403), with or without the runtime marker, and a
// claimed operator header without the runtime marker is not trusted.
func TestTenantKeyRoutesAreOperatorOnly(t *testing.T) {
	ts, _ := newTestServer(t)
	routes := []struct{ method, path string }{
		{"GET", "/v1/admin/tenant-keys/pending"},
		{"POST", "/v1/admin/tenant-keys/pending"},
		{"POST", "/v1/admin/tenant-keys/resweep"},
		{"GET", "/v1/admin/tenant-keys/records"},
		{"POST", "/v1/admin/tenant-keys/records"},
	}
	for _, grant := range []string{"", "1"} {
		t.Setenv(configureGrantEnv, grant)
		for _, rt := range routes {
			resp, err := http.DefaultClient.Do(authedReq(t, rt.method, ts.URL+rt.path, ""))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("grant=%q user %s %s: want 403, got %d", grant, rt.method, rt.path, resp.StatusCode)
			}
		}
	}
	// Without the runtime marker a claimed operator header is deleted, and
	// the call is just a user's.
	t.Setenv(configureGrantEnv, "")
	req := authedReq(t, "GET", ts.URL+"/v1/admin/tenant-keys/records", "")
	req.Header.Set(configureGrantHeader, "role=owner; sub=user-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("claimed operator header: want 403, got %d", resp.StatusCode)
	}
}
