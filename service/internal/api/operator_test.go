package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// opHdr is the runtime's operator statement as request headers.
func opHdr(t *testing.T) map[string]string {
	t.Helper()
	t.Setenv(configureGrantEnv, "1")
	return map[string]string{configureGrantHeader: "role=owner; sub=user-1"}
}

// TestOperatorRoutesRefuseUsers: every operator route (purge, subjects,
// drain) refuses an ordinary user's bearer, a tool token's user and a
// claimed operator header without the runtime marker, before doing anything.
func TestOperatorRoutesRefuseUsers(t *testing.T) {
	ts := newFullServer(t, nil)
	routes := []struct{ method, path, body string }{
		{"POST", "/tools/purge_tenant", `{"tenant_id":"x","reason":"r"}`},
		{"POST", "/tools/list_subjects", `{}`},
		{"POST", "/tools/rekey_subjects", `{"mapping":{"a":"b"},"reason":"r"}`},
		{"POST", "/actions/drain_local_objects", `{}`},
		{"GET", "/actions/drain_local_objects/status", ``},
	}
	for _, grant := range []string{"", "1"} {
		t.Setenv(configureGrantEnv, grant)
		for _, rt := range routes {
			st, b, _ := rawReq(t, rt.method, ts.URL+rt.path, devAuth, rt.body, nil)
			if st != http.StatusForbidden {
				t.Fatalf("grant=%q user %s %s: want 403, got %d %s", grant, rt.method, rt.path, st, b)
			}
		}
	}
	t.Setenv(configureGrantEnv, "")
	for _, rt := range routes {
		st, b, _ := rawReq(t, rt.method, ts.URL+rt.path, devAuth, rt.body,
			map[string]string{configureGrantHeader: "role=owner; sub=user-1"})
		if st != http.StatusForbidden {
			t.Fatalf("claimed header %s %s: want 403, got %d %s", rt.method, rt.path, st, b)
		}
	}
}

// TestEveryOperatorToolIsOwnerInManifest: every manifest tool whose route
// takes the operator gate is declared x-privasys.auth "owner", so the
// runtime checks the role and states it; none is missed.
func TestEveryOperatorToolIsOwnerInManifest(t *testing.T) {
	raw, err := os.ReadFile("../../privasys.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Tools []struct {
			Name     string `json:"name"`
			Endpoint string `json:"endpoint"`
			Role     string `json:"role"`
			X        struct {
				Auth string `json:"auth"`
			} `json:"x-privasys"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	operator := map[string]bool{
		"/tools/purge_tenant": true, "/tools/list_subjects": true, "/tools/rekey_subjects": true,
		"/actions/drain_local_objects": true, "/actions/drain_local_objects/status": true,
		"/v1/admin/tenant-keys/records": true, "/v1/admin/tenant-keys/pending": true,
		"/v1/admin/tenant-keys/resweep": true, "/v1/admin/audit/summary": true,
	}
	seen := map[string]bool{}
	for _, tool := range m.Tools {
		if operator[tool.Endpoint] {
			seen[tool.Endpoint] = true
			if tool.X.Auth != "owner" {
				t.Errorf("%s (%s) is an operator route but not declared auth owner", tool.Name, tool.Endpoint)
			}
		}
		if tool.Role == "config" && tool.Endpoint != "/configure" && tool.X.Auth != "owner" {
			t.Errorf("%s has role config but no auth owner", tool.Name)
		}
	}
	for ep := range operator {
		if !seen[ep] {
			t.Errorf("operator route %s is not in the manifest", ep)
		}
	}
}

// TestAuditSummaryOperatorOnly: the summary lists a purge with the tenant's
// first characters and no actor, and refuses an ordinary user.
func TestAuditSummaryOperatorOnly(t *testing.T) {
	ts, srv := newTestServer(t)
	if err := srv.Store.AppendAudit(context.Background(), "0123456789abcdef", "tenant_purged", "someone", "reason"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(authedReq(t, "GET", ts.URL+"/v1/admin/audit/summary", ""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("user: want 403, got %d", resp.StatusCode)
	}
	raw := doOperatorGet(t, ts, "/v1/admin/audit/summary")
	var got struct {
		Counts map[string]int `json:"counts"`
		Events []struct {
			Tenant string `json:"tenant"`
		} `json:"events"`
		Actors int    `json:"distinct_actors"`
		Since  string `json:"log_reaches_back_to"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.Counts["tenant_purged"] != 1 || len(got.Events) != 1 || got.Events[0].Tenant != "01234567" || got.Actors != 1 || got.Since == "" {
		t.Fatalf("summary: %s", raw)
	}
	if strings.Contains(raw, "someone") || strings.Contains(raw, "reason") {
		t.Fatalf("the summary leaks the actor or detail: %s", raw)
	}
}
