package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestChatDriveIntegrationE2E exercises the server contract the chat UI's
// §8.7 Drive integration depends on, end to end: a conversation with turns
// and both attachment intents, then the REVISED AI-scope defaults (Memory/
// always in scope, Chat conversations/ OPT-IN as of 2026-07-19) and the
// whole-Drive sentinel grant. Deterministic; no live enclave.
func TestChatDriveIntegrationE2E(t *testing.T) {
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

	// A Memory note (creates Memory/, the always-scoped default).
	mpayload, _ := json.Marshal(map[string]any{
		"tenant_id": tenant.ID, "name": "pref", "summary": "a pref", "body": "the preference",
	})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/write_memory", owner, string(mpayload))); code != 200 && code != 201 {
		t.Fatalf("write_memory: %d %s", code, b)
	}

	// A conversation with a turn and a knowledge attachment.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/create_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"title":"Weekend plans","date":"2026-07-19"}`, tenant.ID)))
	if code != 201 {
		t.Fatalf("create_conversation: %d %s", code, b)
	}
	var conv struct {
		ConversationID string `json:"conversation_id"`
		FilesFolderID  string `json:"files_folder_id"`
	}
	_ = json.Unmarshal(b, &conv)

	kb := base64.StdEncoding.EncodeToString([]byte("# Notes\nBrighton on Saturday."))
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/attach_to_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"conversation_id":%q,"name":"notes.md","mime":"text/markdown","content_base64":%q,"intent":"knowledge"}`,
			tenant.ID, conv.ConversationID, kb))); code != 200 {
		t.Fatalf("attach knowledge: %d %s", code, b)
	}

	// The conversations root folder id (parent of the conversation folder).
	convRoot, err := srv.Store.ChildByName(t.Context(), tenant.ID, "", "Chat conversations")
	if err != nil {
		t.Fatalf("Chat conversations folder should exist: %v", err)
	}

	// --- Default AI scope: Memory/ in, Chat conversations/ OUT. ---
	code, b = doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/ai-scope", base.URL, tenant.ID), owner, ""))
	if code != 200 {
		t.Fatalf("list ai-scope: %d %s", code, b)
	}
	var scope struct {
		Scoped []struct {
			NodeID string `json:"node_id"`
		} `json:"scoped"`
		AlwaysScoped []string `json:"always_scoped"`
		AllScoped    bool     `json:"all_scoped"`
	}
	_ = json.Unmarshal(b, &scope)
	if len(scope.AlwaysScoped) < 1 {
		t.Fatalf("Memory should be an always-scoped default: %s", b)
	}
	if len(scope.Scoped) != 0 || scope.AllScoped {
		t.Fatalf("fresh tenant should have no explicit/whole-drive scope: %s", b)
	}

	inScope := func() map[string]bool {
		ids, serr := srv.aiScopeNodeSet(t.Context(), tenant.ID)
		if serr != nil {
			t.Fatalf("aiScopeNodeSet: %v", serr)
		}
		set := map[string]bool{}
		for _, id := range ids {
			set[id] = true
		}
		return set
	}
	if inScope()[convRoot.ID] {
		t.Fatal("Chat conversations/ must NOT be in AI scope by default (opt-in)")
	}

	// --- Opt in to past conversations. ---
	epayload, _ := json.Marshal(map[string]any{"tenant_id": tenant.ID, "node_id": convRoot.ID})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/enable_ai", owner, string(epayload))); code != 201 {
		t.Fatalf("enable_ai conversations: %d %s", code, b)
	}
	if !inScope()[convRoot.ID] {
		t.Fatal("Chat conversations/ should be in scope after opt-in")
	}

	// --- Whole-Drive sentinel: a Docs/ folder + file becomes reachable. ---
	code, b = doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/tenants/%s/folders", base.URL, tenant.ID), owner, `{"name":"Docs"}`))
	if code != 201 {
		t.Fatalf("Docs folder: %d %s", code, b)
	}
	var docs nodeJSON
	_ = json.Unmarshal(b, &docs)
	before := inScope()
	if before[docs.ID] {
		t.Fatal("Docs/ should not be in scope before whole-Drive is enabled")
	}

	if code, b = doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/tenants/%s/ai-scope/all", base.URL, tenant.ID), owner, "")); code != 201 {
		t.Fatalf("enable whole-Drive: %d %s", code, b)
	}
	code, b = doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/ai-scope", base.URL, tenant.ID), owner, ""))
	_ = json.Unmarshal(b, &scope)
	if code != 200 || !scope.AllScoped {
		t.Fatalf("whole-Drive should be reported as all_scoped: %d %s", code, b)
	}
	if !inScope()[docs.ID] {
		t.Fatal("Docs/ should be in scope once whole-Drive is enabled")
	}

	// --- Disable whole-Drive; explicit conversations grant survives. ---
	if code, b = doReq(t, bearerReq(t, "DELETE", fmt.Sprintf("%s/v1/tenants/%s/ai-scope/all", base.URL, tenant.ID), owner, "")); code != 200 {
		t.Fatalf("disable whole-Drive: %d %s", code, b)
	}
	after := inScope()
	if after[docs.ID] {
		t.Fatal("Docs/ should drop out after whole-Drive is disabled")
	}
	if !after[convRoot.ID] {
		t.Fatal("the explicit conversations grant must survive disabling whole-Drive")
	}

	// A stranger cannot read or change this tenant's AI scope.
	if code, _ := doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/ai-scope", base.URL, tenant.ID), "user-9", "")); code != http.StatusForbidden {
		t.Fatalf("stranger ai-scope read: want 403, got %d", code)
	}
	if code, _ := doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/tenants/%s/ai-scope/all", base.URL, tenant.ID), "user-9", "")); code != http.StatusForbidden {
		t.Fatalf("stranger whole-Drive enable: want 403, got %d", code)
	}
}
