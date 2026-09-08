package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Privasys/drive/service/internal/store"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/grants"
)

// rawReq issues a request with arbitrary headers and returns status, body and
// response headers — the tier-B routes hinge on ETag / If-Match / Range /
// Content-Range, which doJSON does not expose.
func rawReq(t *testing.T, method, url, auth, body string, hdr map[string]string) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", auth)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, b, resp.Header
}

// D1: conditional content replace fences two writers.
func TestD1ConditionalWrite(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	st, b, _ := rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/files?name=notes.txt", devAuth, "one", nil)
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	var f struct {
		ID  string `json:"id"`
		Rev int64  `json:"rev"`
	}
	_ = json.Unmarshal(b, &f)

	st, b, _ = rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+f.ID+"/content", devAuth, "two", map[string]string{"If-Match": `"999"`})
	if st != http.StatusPreconditionFailed {
		t.Fatalf("stale write: want 412, got %d %s", st, b)
	}
	var stale struct {
		Error string `json:"error"`
		Rev   int64  `json:"rev"`
	}
	_ = json.Unmarshal(b, &stale)
	if stale.Error != "stale" || stale.Rev != f.Rev {
		t.Fatalf("412 body: %s", b)
	}

	st, b, hdr := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+f.ID+"/content", devAuth, "two", map[string]string{"If-Match": fmt.Sprintf(`"%d"`, f.Rev)})
	if st != 200 {
		t.Fatalf("conditional write: %d %s", st, b)
	}
	var wr struct {
		Rev int64 `json:"rev"`
	}
	_ = json.Unmarshal(b, &wr)
	if wr.Rev <= f.Rev {
		t.Fatalf("rev did not advance: %d -> %d", f.Rev, wr.Rev)
	}
	if hdr.Get("ETag") != fmt.Sprintf(`"%d"`, wr.Rev) {
		t.Fatalf("ETag %q", hdr.Get("ETag"))
	}

	st, _, _ = rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+f.ID+"/content", devAuth, "three", map[string]string{"If-Match": fmt.Sprintf(`"%d"`, f.Rev)})
	if st != http.StatusPreconditionFailed {
		t.Fatalf("replayed rev: want 412, got %d", st)
	}

	_, rb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+f.ID, devAuth, "", nil)
	if string(rb) != "two" {
		t.Fatalf("content %q", rb)
	}
}

// D4: a Range request returns 206 with the covered bytes.
func TestD4RangeRead(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	content := "0123456789abcdefghij"
	st, b, _ := rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/files?name=r.txt", devAuth, content, nil)
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	var f struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &f)

	st, rb, hdr := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+f.ID, devAuth, "", map[string]string{"Range": "bytes=5-9"})
	if st != http.StatusPartialContent {
		t.Fatalf("range: want 206, got %d", st)
	}
	if string(rb) != "56789" {
		t.Fatalf("range body %q", rb)
	}
	if cr := hdr.Get("Content-Range"); cr != fmt.Sprintf("bytes 5-9/%d", len(content)) {
		t.Fatalf("Content-Range %q", cr)
	}
	_, rb, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+f.ID, devAuth, "", map[string]string{"Range": "bytes=-3"})
	if string(rb) != "hij" {
		t.Fatalf("suffix range %q", rb)
	}
	_, rb, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+f.ID, devAuth, "", map[string]string{"Range": "bytes=15-"})
	if string(rb) != "fghij" {
		t.Fatalf("open range %q", rb)
	}
}

// D2: path addressing with mkdir -p, stat, and create-if-absent.
func TestD2PathAddressing(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	st, b, _ := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=a/b/c.txt", devAuth, "hello", map[string]string{"X-Drive-Parents": "create"})
	if st != 201 {
		t.Fatalf("write_path create: %d %s", st, b)
	}
	st, b, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=a/b/c.txt", devAuth, "", nil)
	if st != 200 {
		t.Fatalf("stat_path: %d %s", st, b)
	}
	var node struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Rev  int64  `json:"rev"`
	}
	_ = json.Unmarshal(b, &node)
	if node.Name != "c.txt" {
		t.Fatalf("resolved %q", node.Name)
	}
	_, rb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+node.ID, devAuth, "", nil)
	if string(rb) != "hello" {
		t.Fatalf("content %q", rb)
	}
	st, _, _ = rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=a/b/c.txt", devAuth, "x", map[string]string{"If-None-Match": "*"})
	if st != http.StatusPreconditionFailed {
		t.Fatalf("if-none-match existing: want 412, got %d", st)
	}
	st, _, _ = rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=x/y/z.txt", devAuth, "x", nil)
	if st != http.StatusNotFound {
		t.Fatalf("missing parent without mkdir: want 404, got %d", st)
	}
	st, _, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=a/../b", devAuth, "", nil)
	if st != http.StatusBadRequest {
		t.Fatalf("traversal: want 400, got %d", st)
	}
}

// D7: an app rediscovers its grants by proving its binding key.
func TestD7GrantsMine(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	_, body = doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/folders", devAuth, `{"name":"AppData"}`)
	var folder struct{ ID string }
	_ = json.Unmarshal(body, &folder)

	pub, priv, _ := ed25519.GenerateKey(nil)
	pk := base64.RawStdEncoding.EncodeToString(pub)
	appID := "0123456789abcdef0123456789abcdef"
	resp, b := doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+folder.ID+"/grants", devAuth,
		fmt.Sprintf(`{"subject":"app:%s","scope":["read","write"],"binding_pubkey":"%s"}`, appID, pk))
	if resp.StatusCode != 201 {
		t.Fatalf("create grant: %d %s", resp.StatusCode, b)
	}
	var g struct{ ID string }
	_ = json.Unmarshal(b, &g)

	tok, _ := grants.MintToken(priv, grants.Envelope{
		Aud: "privasys-drive", Sub: appID, PK: pk,
		Iat: time.Now().Unix(), Exp: time.Now().Add(time.Minute).Unix(), JTI: "self",
	})
	code, rb, _ := rawReq(t, "GET", ts.URL+"/v1/grants/mine", "AppGrant "+tok, "", nil)
	if code != 200 {
		t.Fatalf("grants/mine: %d %s", code, rb)
	}
	var out struct {
		Grants []struct {
			ID     string `json:"id"`
			NodeID string `json:"node_id"`
		} `json:"grants"`
	}
	_ = json.Unmarshal(rb, &out)
	if len(out.Grants) != 1 || out.Grants[0].ID != g.ID || out.Grants[0].NodeID != folder.ID {
		t.Fatalf("grants/mine returned %s", rb)
	}

	pub2, priv2, _ := ed25519.GenerateKey(nil)
	otherTok, _ := grants.MintToken(priv2, grants.Envelope{
		Aud: "privasys-drive", Sub: appID, PK: base64.RawStdEncoding.EncodeToString(pub2),
		Iat: time.Now().Unix(), Exp: time.Now().Add(time.Minute).Unix(), JTI: "self2",
	})
	_, rb, _ = rawReq(t, "GET", ts.URL+"/v1/grants/mine", "AppGrant "+otherTok, "", nil)
	out.Grants = nil
	_ = json.Unmarshal(rb, &out)
	if len(out.Grants) != 0 {
		t.Fatalf("other key saw grants: %s", rb)
	}
}

// Replacing or appending to a file under an excluded folder must not queue it
// for indexing: the node ends up skipped, never pending.
func TestReplaceUnderNoIndexFolderStaysExcluded(t *testing.T) {
	var srv *Server
	ts := newFullServer(t, func(s *Server) { srv = s })
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	st, _, _ := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=App/log.txt", devAuth, "one", map[string]string{"X-Drive-Parents": "create"})
	if st != 201 {
		t.Fatalf("put: %d", st)
	}
	_, fb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=App", devAuth, "", nil)
	var folder struct{ ID string }
	_ = json.Unmarshal(fb, &folder)
	if resp, b := doJSON(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+folder.ID+"/indexing", devAuth, `{"enabled":false}`); resp.StatusCode != 200 {
		t.Fatalf("exclude folder: %d %s", resp.StatusCode, b)
	}
	_, nb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=App/log.txt", devAuth, "", nil)
	_ = nb
	kids, _ := srv.Store.ListChildren(context.Background(), tenant.ID, folder.ID)
	fileID := kids[0].ID
	if st, b, _ := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+fileID+"/content", devAuth, "two", nil); st != 200 {
		t.Fatalf("replace: %d %s", st, b)
	}
	if st, b, _ := rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+fileID+"/append", devAuth, "three", nil); st != 200 {
		t.Fatalf("append: %d %s", st, b)
	}
	status, _, err := srv.Store.NodeIndexMeta(context.Background(), tenant.ID, fileID)
	if err != nil || status != string(store.IndexSkipped) {
		t.Fatalf("index status after writes under an excluded folder = %q (err %v), want skipped", status, err)
	}
}
