package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/grants"
)

// A files.ai capability lets an app read and search what the holder put in
// their AI scope, acting for the holder who minted it: Drive takes the holder
// from the grant, not from any header the app sends. It reads only the AI
// scope, cannot redeem links or change settings, and stops when revoked.
func TestFilesAICapability(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	srv.InstallConfig(&config.Config{Mode: config.ModeSovereign})
	const owner = "user-1"

	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/me/tenant", owner, ""))
	if code != 200 && code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)

	mkFolderWithFile := func(folderName, fileName, contents string) (folderID, fileID string) {
		code, b := doReq(t, bearerReq(t, "POST",
			fmt.Sprintf("%s/v1/tenants/%s/folders", base.URL, tenant.ID), owner, fmt.Sprintf(`{"name":%q}`, folderName)))
		if code != 201 {
			t.Fatalf("folder %s: %d %s", folderName, code, b)
		}
		var folder nodeJSON
		_ = json.Unmarshal(b, &folder)
		req, _ := http.NewRequest("POST",
			fmt.Sprintf("%s/v1/tenants/%s/files?name=%s&mime=text/markdown&parent_id=%s", base.URL, tenant.ID, fileName, folder.ID),
			bytes.NewReader([]byte(contents)))
		req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
		code, b = doReq(t, req)
		if code != 201 {
			t.Fatalf("file %s: %d %s", fileName, code, b)
		}
		var file nodeJSON
		_ = json.Unmarshal(b, &file)
		return folder.ID, file.ID
	}
	docsID, docFileID := mkFolderWithFile("Docs", "spec.md", "# Spec\nthe answer is 42")
	_, privFileID := mkFolderWithFile("Private", "secret.md", "# Secret\ndo not read")
	ep, _ := json.Marshal(map[string]any{"tenant_id": tenant.ID, "node_id": docsID})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/enable_ai", owner, string(ep))); code != 201 {
		t.Fatalf("enable_ai: %d %s", code, b)
	}

	// The holder approves files.ai for an app (the wallet's call).
	pub, priv, _ := ed25519.GenerateKey(nil)
	pk := base64.RawStdEncoding.EncodeToString(pub)
	const app = "0123456789abcdef0123456789abcdef"
	mint := func(perms string) (int, map[string]string) {
		body := fmt.Sprintf(`{"nonce":"n","subject_app_id":%q,"binding_pubkey":%q,"permissions":%s,"kind":"files.ai"}`, app, pk, perms)
		code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/capabilities", owner, body))
		var out struct {
			ServiceResult map[string]string `json:"service_result"`
		}
		_ = json.Unmarshal(b, &out)
		return code, out.ServiceResult
	}
	if code, _ := mint(`["read","write"]`); code != http.StatusBadRequest {
		t.Fatalf("files.ai with write: %d, want 400", code)
	}
	code, res := mint(`["read"]`)
	if code != 201 || res["tenant_id"] != tenant.ID || res["grant_id"] == "" || res["node_id"] != "" {
		t.Fatalf("mint: %d %v", code, res)
	}
	tok, err := grants.MintToken(priv, grants.Envelope{
		Iss: "drive.privasys.org", Aud: "privasys-drive", Sub: tenant.ID, Node: "",
		Scope: []grants.Scope{grants.ScopeRead}, JTI: res["grant_id"],
		Iat: time.Now().Unix(), Exp: time.Now().Add(5 * time.Minute).Unix(), PK: pk,
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(tool, body string, onBehalf string) (int, []byte) {
		req, _ := http.NewRequest("POST", ts.URL+"/tools/"+tool, bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "AppGrant "+tok)
		req.Header.Set("Content-Type", "application/json")
		if onBehalf != "" {
			req.Header.Set(onBehalfOfHeader, onBehalf)
		}
		return doReq(t, req)
	}

	// Reads in the AI scope, as the holder, with no identity header at all.
	if code, b := call("read_file", fmt.Sprintf(`{"tenant_id":%q,"file_id":%q}`, tenant.ID, docFileID), ""); code != 200 {
		t.Fatalf("read in-scope file: %d %s", code, b)
	}
	// Not outside it.
	if code, _ := call("read_file", fmt.Sprintf(`{"tenant_id":%q,"file_id":%q}`, tenant.ID, privFileID), ""); code != http.StatusForbidden {
		t.Fatalf("read out-of-scope file: %d, want 403", code)
	}
	// A header naming someone else changes nothing: the holder is the grant's.
	if code, _ := call("read_file", fmt.Sprintf(`{"tenant_id":%q,"file_id":%q}`, tenant.ID, docFileID), "someone-else"); code != 200 {
		t.Fatalf("read with a foreign on-behalf-of header: %d, want 200 as the holder", code)
	}

	// No link redemption, no settings change.
	mcp := func(method, path, body string) int {
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "AppGrant "+tok)
		req.Header.Set("Content-Type", "application/json")
		code, _ := doReq(t, req)
		return code
	}
	if code := mcp("POST", "/api/v1/mcp/tools/open_link", `{"link":"https://drive.privasys.org/l?id=x#y"}`); code != http.StatusForbidden {
		t.Fatalf("open_link with a files.ai grant: %d, want 403", code)
	}
	if code := mcp("PUT", "/api/v1/mcp/settings", `{"memory_on":false}`); code != http.StatusForbidden {
		t.Fatalf("settings change with a files.ai grant: %d, want 403", code)
	}

	// Revoked: nothing.
	if code, b := doReq(t, bearerReq(t, "DELETE", fmt.Sprintf("%s/v1/tenants/%s/grants/%s", base.URL, tenant.ID, res["grant_id"]), owner, "")); code != 200 && code != 204 {
		t.Fatalf("revoke: %d %s", code, b)
	}
	if code, _ := call("read_file", fmt.Sprintf(`{"tenant_id":%q,"file_id":%q}`, tenant.ID, docFileID), ""); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatalf("read after revoke: %d, want refused", code)
	}
}
