package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPurgeTenant: the operator purge removes the tenant, its nodes and
// grants; the audit trail survives. (Operator-role enforcement lives in
// the enclave-os manager, mirroring /configure.)
func TestPurgeTenant(t *testing.T) {
	_, srv := newTestServer(t)
	// The default harness serves only /v1; mount the manifest-tool
	// surface alongside it, as Handler() does in production.
	mux := http.NewServeMux()
	mux.Handle("/v1/", srv.Routes())
	mux.Handle("/tools/", srv.Tools())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	// Purge without a reason is rejected.
	code, _ := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/purge_tenant", owner,
		`{"tenant_id":"`+tenantID+`"}`))
	if code != http.StatusBadRequest {
		t.Fatalf("purge without reason: want 400, got %d", code)
	}

	code, b := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/purge_tenant", owner,
		`{"tenant_id":"`+tenantID+`","reason":"identity rotated; tenant unreachable"}`))
	if code != 200 {
		t.Fatalf("purge: %d %s", code, b)
	}
	var res struct {
		Status string `json:"status"`
		Files  int    `json:"files"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "purged" || res.Files != 1 {
		t.Fatalf("purge result: %s", b)
	}

	// The tenant and its file are gone.
	if code, _ := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, fileID), owner, "")); code == 200 {
		t.Fatalf("file still readable after purge")
	}
	if _, err := srv.Store.GetTenant(t.Context(), tenantID); err == nil {
		t.Fatalf("tenant row survived purge")
	}

	// Purging again reports not found.
	if code, _ := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/purge_tenant", owner,
		`{"tenant_id":"`+tenantID+`","reason":"again"}`)); code != http.StatusNotFound {
		t.Fatalf("double purge: want 404, got %d", code)
	}
}
