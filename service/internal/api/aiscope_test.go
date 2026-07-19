package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Privasys/drive/service/internal/grants"
)

// TestAIScope: enable/disable/list the assistant's directory grants, and
// verify the AI-scoped node set expands folder grants to descendants and
// always includes Memory/ (Chat conversations/ is opt-in as of 2026-07-19).
func TestAIScope(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner = "user-1"
	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)

	// A Projects/ folder with a file inside.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/folders", base.URL, tenant.ID), owner, `{"name":"Projects"}`))
	if code != 201 {
		t.Fatalf("folder: %d %s", code, b)
	}
	var folder nodeJSON
	_ = json.Unmarshal(b, &folder)
	// A file inside Projects/, via the REST upload.
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=spec.md&mime=text/markdown&parent_id=%s", base.URL, tenant.ID, folder.ID),
		bytes.NewReader([]byte("# Spec\nbody")))
	req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
	code, b = doReq(t, req)
	if code != 201 {
		t.Fatalf("upload child: %d %s", code, b)
	}
	var child nodeJSON
	_ = json.Unmarshal(b, &child)
	// A Memory file so the default scope has content.
	mpayload, _ := json.Marshal(map[string]any{
		"tenant_id": tenant.ID, "name": "pref", "summary": "a pref", "body": "the preference",
	})
	doReq(t, bearerReq(t, "POST", ts.URL+"/tools/write_memory", owner, string(mpayload)))

	// Enable Projects/ for AI.
	epayload, _ := json.Marshal(map[string]any{"tenant_id": tenant.ID, "node_id": folder.ID})
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/enable_ai", owner, string(epayload)))
	if code != 201 {
		t.Fatalf("enable_ai: %d %s", code, b)
	}
	// Idempotent.
	if code, _ := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/enable_ai", owner, string(epayload))); code != 200 {
		t.Fatalf("enable_ai idempotent: got %d", code)
	}

	// List: Projects present; Memory/ as the always-scoped default.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/list_ai_scope", owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID)))
	if code != 200 {
		t.Fatalf("list_ai_scope: %d %s", code, b)
	}
	var scope struct {
		Scoped []struct {
			NodeID string `json:"node_id"`
			Name   string `json:"name"`
		} `json:"scoped"`
		AlwaysScoped []string `json:"always_scoped"`
	}
	_ = json.Unmarshal(b, &scope)
	if len(scope.Scoped) != 1 || scope.Scoped[0].NodeID != folder.ID {
		t.Fatalf("scoped list unexpected: %s", b)
	}
	if len(scope.AlwaysScoped) < 1 {
		t.Fatalf("Memory default not reported: %s", b)
	}

	// The AI-scoped node set expands the folder grant to its child.
	nodes, err := srv.aiScopeNodeSet(t.Context(), tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, id := range nodes {
		set[id] = true
	}
	if !set[folder.ID] || !set[child.ID] {
		t.Fatalf("scope set missing folder/child: %v", nodes)
	}

	// Disable and confirm it drops out.
	code, _ = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/disable_ai", owner, string(epayload)))
	if code != 200 {
		t.Fatalf("disable_ai: %d", code)
	}
	if g, _ := srv.Grants.ActiveRawSubjectOnNode(t.Context(), tenant.ID, folder.ID, grants.SubjectAssistant); g != nil {
		t.Fatal("assistant grant should be revoked")
	}
}
