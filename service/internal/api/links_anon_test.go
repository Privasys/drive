package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// An open, read-only, reusable link that asks for nothing opens with its own
// secret on the direct name, and reads nothing outside what it shares. Every
// other link, every other leg and every other route still needs a sign-in.
func TestLinkOpensWithoutSignIn(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, payload := ownerTenantWithFile(t, ts.URL, owner)

	// A second file in the same drive, outside the shared one.
	up, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=private.txt&mime=text/plain", ts.URL, tenantID),
		bytes.NewReader([]byte("not shared")))
	up.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
	code, b := doReq(t, up)
	if code != 201 {
		t.Fatalf("upload: %d %s", code, b)
	}
	var private nodeJSON
	_ = json.Unmarshal(b, &private)

	link := func(body string) (string, string) {
		l := createLink(t, ts.URL, tenantID, fileID, owner, body)
		return l["id"].(string), l["secret"].(string)
	}
	read := func(method, path, cred, transport, body string) (int, []byte) {
		var rd *bytes.Reader
		if body != "" {
			rd = bytes.NewReader([]byte(body))
		} else {
			rd = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rd)
		if cred != "" {
			req.Header.Set("Authorization", "DriveLink "+cred)
		}
		if transport != "" {
			req.Header.Set("X-Privasys-Transport", transport)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		return doReq(t, req)
	}
	fileURL := fmt.Sprintf("/v1/tenants/%s/files/%s", tenantID, fileID)

	id, secret := link(`{"mode":"open","scope":["read"]}`)
	cred := id + "." + secret

	// The preview tells the page it may skip the sign-in.
	if _, p := previewLink(t, ts.URL, id, secret); p["opens_without_sign_in"] != true {
		t.Fatalf("preview must say the link opens without a sign-in: %v", p)
	}
	if code, b := read("GET", "/v1/links/"+id+"/view", cred, "direct", ""); code != 200 || !bytes.Contains(b, []byte("shared.txt")) {
		t.Fatalf("view: %d %s", code, b)
	}
	if code, b := read("GET", fileURL, cred, "direct", ""); code != 200 || !bytes.Equal(b, payload) {
		t.Fatalf("download: %d %s", code, b)
	}

	// Never off the direct name, never with a wrong secret, never outside
	// the shared node, never a write.
	if code, _ := read("GET", fileURL, cred, "", ""); code != http.StatusForbidden {
		t.Fatalf("terminated leg: want 403, got %d", code)
	}
	if code, _ := read("GET", fileURL, id+".AAAA", "direct", ""); code != http.StatusNotFound {
		t.Fatalf("wrong secret: want 404, got %d", code)
	}
	if code, _ := read("GET", fmt.Sprintf("/v1/tenants/%s/files/%s", tenantID, private.ID), cred, "direct", ""); code != http.StatusForbidden {
		t.Fatalf("outside the link: want 403, got %d", code)
	}
	if code, _ := read("POST", fmt.Sprintf("/v1/tenants/%s/download.zip", tenantID), cred, "direct",
		`{"node_ids":["`+private.ID+`"]}`); code != http.StatusForbidden {
		t.Fatalf("zip outside the link: want 403, got %d", code)
	}
	if code, _ := read("DELETE", fmt.Sprintf("/v1/tenants/%s/nodes/%s", tenantID, fileID), cred, "direct", ""); code != http.StatusUnauthorized {
		t.Fatalf("delete with a link: want 401, got %d", code)
	}
	if code, _ := read("GET", "/v1/me", cred, "direct", ""); code != http.StatusUnauthorized {
		t.Fatalf("/v1/me with a link: want 401, got %d", code)
	}

	// Links that keep the sign-in.
	for _, body := range []string{
		`{"mode":"open","scope":["read"],"uses":"once"}`,
		`{"mode":"open","scope":["read","write"]}`,
		`{"mode":"restricted","scope":["read"],"required_attributes":["email"]}`,
	} {
		id, secret := link(body)
		if _, p := previewLink(t, ts.URL, id, secret); p["opens_without_sign_in"] == true {
			t.Fatalf("%s: preview must not offer it without a sign-in", body)
		}
		if code, _ := read("GET", fileURL, id+"."+secret, "direct", ""); code != http.StatusForbidden {
			t.Fatalf("%s: want 403, got %d", body, code)
		}
	}
}
