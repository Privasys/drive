package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestBucketCredTools exercises the manifest-tool surface for the BYO
// bucket credential: my_drive resolves the personal tenant, then
// set/get/delete round-trip the sealed credential with the same access
// checks as the REST endpoints.
func TestBucketCredTools(t *testing.T) {
	ts := newFullServer(t, func(s *Server) {
		s.MEKs = &fakeMEKs{mek: make([]byte, 32)}
	})

	// my_drive: idempotent personal tenant.
	resp, body := doJSON(t, "POST", ts.URL+"/tools/my_drive", devAuth, "{}")
	if resp.StatusCode != 200 {
		t.Fatalf("my_drive: %d %s", resp.StatusCode, body)
	}
	var me struct {
		TenantID string `json:"tenant_id"`
		Created  bool   `json:"created"`
	}
	if err := json.Unmarshal(body, &me); err != nil || me.TenantID == "" {
		t.Fatalf("my_drive response: %s (%v)", body, err)
	}
	if !me.Created {
		t.Fatalf("first my_drive should create: %s", body)
	}
	resp, body = doJSON(t, "POST", ts.URL+"/tools/my_drive", devAuth, "{}")
	var again struct {
		TenantID string `json:"tenant_id"`
		Created  bool   `json:"created"`
	}
	_ = json.Unmarshal(body, &again)
	if resp.StatusCode != 200 || again.TenantID != me.TenantID || again.Created {
		t.Fatalf("my_drive not idempotent: %d %s", resp.StatusCode, body)
	}

	// get before set: not configured.
	resp, body = doJSON(t, "POST", ts.URL+"/tools/get_bucket_cred", devAuth,
		fmt.Sprintf(`{"tenant_id":%q}`, me.TenantID))
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"configured":false`) {
		t.Fatalf("get_bucket_cred pre-set: %d %s", resp.StatusCode, body)
	}

	// set: sealed credential stored, plaintext never sent.
	ct := base64.RawURLEncoding.EncodeToString([]byte("sealed-bytes"))
	iv := base64.RawURLEncoding.EncodeToString([]byte("iv0"))
	setBody := fmt.Sprintf(`{"tenant_id":%q,"key_ref":{"handle":"apps.privasys.org/x/data/y/bucket/v1","endpoints":["v:1"]},"ciphertext_b64":%q,"iv_b64":%q,"content_type":"gcs-sa-json","bucket":"tenant-bucket"}`,
		me.TenantID, ct, iv)
	resp, body = doJSON(t, "POST", ts.URL+"/tools/set_bucket_cred", devAuth, setBody)
	if resp.StatusCode != 200 {
		t.Fatalf("set_bucket_cred: %d %s", resp.StatusCode, body)
	}

	// A non-member cannot set or read it.
	otherAuth := "Bearer dev:user-2:mallory@privasys.org"
	resp, _ = doJSON(t, "POST", ts.URL+"/tools/set_bucket_cred", otherAuth, setBody)
	if resp.StatusCode != 403 {
		t.Fatalf("set_bucket_cred by non-member: want 403, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "POST", ts.URL+"/tools/get_bucket_cred", otherAuth,
		fmt.Sprintf(`{"tenant_id":%q}`, me.TenantID))
	if resp.StatusCode != 403 {
		t.Fatalf("get_bucket_cred by non-member: want 403, got %d", resp.StatusCode)
	}

	// get: metadata only, never the ciphertext.
	resp, body = doJSON(t, "POST", ts.URL+"/tools/get_bucket_cred", devAuth,
		fmt.Sprintf(`{"tenant_id":%q}`, me.TenantID))
	if resp.StatusCode != 200 ||
		!strings.Contains(string(body), `"configured":true`) ||
		!strings.Contains(string(body), "tenant-bucket") ||
		strings.Contains(string(body), ct) {
		t.Fatalf("get_bucket_cred: %d %s", resp.StatusCode, body)
	}

	// delete: back to unconfigured.
	resp, _ = doJSON(t, "POST", ts.URL+"/tools/delete_bucket_cred", devAuth,
		fmt.Sprintf(`{"tenant_id":%q}`, me.TenantID))
	if resp.StatusCode != 200 {
		t.Fatalf("delete_bucket_cred: %d", resp.StatusCode)
	}
	resp, body = doJSON(t, "POST", ts.URL+"/tools/get_bucket_cred", devAuth,
		fmt.Sprintf(`{"tenant_id":%q}`, me.TenantID))
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"configured":false`) {
		t.Fatalf("get_bucket_cred post-delete: %d %s", resp.StatusCode, body)
	}
}
