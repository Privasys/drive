package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/config"
)

// TestMCPSettingsAndCatalogue covers the two halves of the generic tool
// integration contract:
//
//  1. The tool CATALOGUE is served to the attested assistant enclave
//     WITHOUT an acting user — the enclave pulls it on a cache-refresh
//     timer outside any request — while every tool CALL still demands
//     X-Privasys-On-Behalf-Of. (The 401 that motivated this: the enclave
//     could never load Drive's tools at all.)
//  2. The per-user settings surface: schema+values read, partial writes,
//     and REAL enforcement — memory off must empty the assistant's scope
//     where the reads happen, not just hide a UI row.
func TestMCPSettingsAndCatalogue(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner = "user-1"
	const caiAppID = "3a545cb7740e4d31839b7341359631a2"

	srv.InstallConfig(&config.Config{
		Mode:                        config.ModeSovereign,
		AssistantEnclaveMeasurement: caiAppID,
	})

	// A personal tenant with a memory note (creates Memory/).
	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)
	mpayload, _ := json.Marshal(map[string]any{
		"tenant_id": tenant.ID, "name": "pref", "summary": "a pref", "body": "the preference",
	})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/write_memory", owner, string(mpayload))); code != 200 && code != 201 {
		t.Fatalf("write_memory: %d %s", code, b)
	}

	attested := func(method, path, sub, body string) (*http.Request, error) {
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req, err := http.NewRequest(method, ts.URL+path, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(peerVerifiedHeader, "true")
		req.Header.Set(peerAppIDHeader, caiAppID)
		if sub != "" {
			req.Header.Set(onBehalfOfHeader, sub)
		}
		return req, nil
	}

	// --- 1. Catalogue: no acting user needed; calls still need one. ---
	req, _ := attested("GET", "/api/v1/mcp/tools", "", "")
	code, b = doReq(t, req)
	if code != 200 {
		t.Fatalf("catalogue without on-behalf-of must be served, got %d %s", code, b)
	}
	var catalogue struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
		Settings map[string]any `json:"settings"`
	}
	_ = json.Unmarshal(b, &catalogue)
	if len(catalogue.Tools) == 0 {
		t.Fatalf("catalogue should list tools: %s", b)
	}
	if catalogue.Settings["title"] != "Memory" || catalogue.Settings["icon"] != "brain" {
		t.Fatalf("catalogue should advertise the settings descriptor: %s", b)
	}

	req, _ = attested("POST", "/api/v1/mcp/tools/get_memory", "", "{}")
	if code, b = doReq(t, req); code != http.StatusUnauthorized {
		t.Fatalf("tool call without on-behalf-of must be refused, got %d %s", code, b)
	}
	req, _ = attested("GET", "/api/v1/mcp/settings", "", "")
	if code, _ = doReq(t, req); code != http.StatusUnauthorized {
		t.Fatalf("settings without on-behalf-of must be refused, got %d", code)
	}

	// --- 2. Settings read: defaults. ---
	type doc struct {
		Version int `json:"version"`
		Display struct {
			Title string `json:"title"`
			Icon  string `json:"icon"`
		} `json:"display"`
		Schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Order      []string                   `json:"x-order"`
		} `json:"schema"`
		Values struct {
			Memory            bool     `json:"memory"`
			PastConversations bool     `json:"past_conversations"`
			EntireDrive       bool     `json:"entire_drive"`
			Folders           []string `json:"folders"`
		} `json:"values"`
	}
	getSettings := func() doc {
		req, _ := attested("GET", "/api/v1/mcp/settings", owner, "")
		code, b := doReq(t, req)
		if code != 200 {
			t.Fatalf("settings get: %d %s", code, b)
		}
		var d doc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("settings decode: %v %s", err, b)
		}
		return d
	}
	d := getSettings()
	if d.Version != 1 || d.Display.Icon != "brain" || len(d.Schema.Order) != 4 {
		t.Fatalf("unexpected settings doc shape: %+v", d)
	}
	if !d.Values.Memory || d.Values.PastConversations || d.Values.EntireDrive || len(d.Values.Folders) != 0 {
		t.Fatalf("fresh defaults should be memory-only: %+v", d.Values)
	}

	putSettings := func(values string) doc {
		req, _ := attested("PUT", "/api/v1/mcp/settings", owner, `{"values":`+values+`}`)
		code, b := doReq(t, req)
		if code != 200 {
			t.Fatalf("settings put %s: %d %s", values, code, b)
		}
		var d doc
		_ = json.Unmarshal(b, &d)
		return d
	}

	inScope := func() map[string]bool {
		ids, err := srv.aiScopeNodeSet(t.Context(), tenant.ID)
		if err != nil {
			t.Fatalf("aiScopeNodeSet: %v", err)
		}
		set := map[string]bool{}
		for _, id := range ids {
			set[id] = true
		}
		return set
	}
	memNode, err := srv.Store.ChildByName(t.Context(), tenant.ID, "", memoryRoot)
	if err != nil {
		t.Fatalf("Memory/ should exist: %v", err)
	}

	// --- 3. Memory OFF is enforced where the reads happen. ---
	if !inScope()[memNode.ID] {
		t.Fatal("Memory/ should be in scope by default")
	}
	if d := putSettings(`{"memory":false}`); d.Values.Memory {
		t.Fatal("memory should report off after PUT")
	}
	if inScope()[memNode.ID] {
		t.Fatal("Memory/ must leave the AI scope when memory is off")
	}
	req, _ = attested("POST", "/api/v1/mcp/tools/get_memory", owner, "{}")
	code, b = doReq(t, req)
	if code != 200 || !strings.Contains(string(b), `"disabled"`) {
		t.Fatalf("assistant get_memory should report disabled: %d %s", code, b)
	}
	// The user's own read (Drive UI) is unaffected.
	code, b = doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/memory", base.URL, tenant.ID), owner, ""))
	if code != 200 || strings.Contains(string(b), `"disabled"`) {
		t.Fatalf("user memory read should be unaffected: %d %s", code, b)
	}
	if d := putSettings(`{"memory":true}`); !d.Values.Memory {
		t.Fatal("memory should report on again")
	}
	if !inScope()[memNode.ID] {
		t.Fatal("Memory/ should return to scope when memory is back on")
	}

	// --- 4. Folders + entire drive reconcile through the same surface. ---
	code, b = doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/tenants/%s/folders", base.URL, tenant.ID), owner, `{"name":"Docs"}`))
	if code != 201 {
		t.Fatalf("Docs folder: %d %s", code, b)
	}
	var docs struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &docs)

	d = putSettings(fmt.Sprintf(`{"folders":[%q]}`, docs.ID))
	if len(d.Values.Folders) != 1 || d.Values.Folders[0] != docs.ID {
		t.Fatalf("folders should reconcile to Docs/: %+v", d.Values)
	}
	if !inScope()[docs.ID] {
		t.Fatal("Docs/ should be in scope after folders PUT")
	}
	d = putSettings(`{"folders":[],"entire_drive":true}`)
	if len(d.Values.Folders) != 0 || !d.Values.EntireDrive {
		t.Fatalf("entire drive on, folders cleared: %+v", d.Values)
	}
	if !inScope()[docs.ID] {
		t.Fatal("Docs/ should be in scope via entire drive")
	}
	d = putSettings(`{"entire_drive":false}`)
	if inScope()[docs.ID] {
		t.Fatal("Docs/ should leave scope when entire drive is off and no folder grant remains")
	}
	if d.Values.EntireDrive {
		t.Fatalf("entire drive should report off: %+v", d.Values)
	}
}
