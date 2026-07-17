package api

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	// File-backed, not :memory:: the pool opens extra connections under
	// concurrency (e.g. the async access-event writer) and every new
	// :memory: connection is a fresh empty database. The busy timeout
	// absorbs writer overlap.
	dbPath := filepath.Join(t.TempDir(), "drive-test.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st, err := store.New(db, store.DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	bk, err := objectstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mek := sha256.Sum256([]byte("test-mek"))
	srv := &Server{
		Store:    st,
		Backend:  bk,
		Grants:   grants.New(db, false),
		Verifier: oidc.DevVerifier{},
		MEK:      mek[:],
	}
	// Drain fire-and-forget metric writes before the store + TempDir go
	// (registered last, so it runs first under LIFO cleanup).
	t.Cleanup(srv.WaitBackground)
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return ts, srv
}

func authedReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dev:user-1:bertrand@privasys.org")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func TestEndToEnd_UploadListDownloadDelete(t *testing.T) {
	ts, _ := newTestServer(t)

	// 1. Create a tenant.
	resp, err := http.DefaultClient.Do(authedReq(t, "POST", ts.URL+"/v1/tenants",
		`{"kind":"user","name":"Bertrand"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create tenant: %d %s", resp.StatusCode, body)
	}
	var tenant store.Tenant
	if err := json.NewDecoder(resp.Body).Decode(&tenant); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 2. Upload a file.
	body := []byte("hello drive — end-to-end test")
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/v1/tenants/%s/files?name=hello.txt&mime=text/plain", ts.URL, tenant.ID), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dev:user-1:bertrand@privasys.org")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload: %d %s", resp.StatusCode, b)
	}
	var n nodeJSON
	_ = json.NewDecoder(resp.Body).Decode(&n)
	resp.Body.Close()
	if n.PlainSize != int64(len(body)) {
		t.Fatalf("size mismatch: %d vs %d", n.PlainSize, len(body))
	}

	// 3. List root and find the file.
	resp, _ = http.DefaultClient.Do(authedReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/root", ts.URL, tenant.ID), ""))
	var listed []nodeJSON
	_ = json.NewDecoder(resp.Body).Decode(&listed)
	resp.Body.Close()
	if len(listed) != 1 || listed[0].Name != "hello.txt" {
		t.Fatalf("listing: %+v", listed)
	}

	// 4. Download and verify bytes + Merkle header.
	resp, _ = http.DefaultClient.Do(authedReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenant.ID, n.ID), ""))
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("download mismatch: %q", got)
	}
	if h := resp.Header.Get("X-Drive-Merkle-Root"); h == "" {
		t.Fatal("Merkle header missing")
	}

	// 5. Export ZIP.
	resp, _ = http.DefaultClient.Do(authedReq(t, "POST", fmt.Sprintf("%s/v1/tenants/%s/exports", ts.URL, tenant.ID), ""))
	if resp.StatusCode != 200 {
		t.Fatalf("export status %d", resp.StatusCode)
	}
	zipBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.HasPrefix(zipBytes, []byte("PK")) || len(zipBytes) < 100 {
		t.Fatalf("export does not look like a zip: %d bytes", len(zipBytes))
	}

	// 6. Delete the file.
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/v1/tenants/%s/nodes/%s", ts.URL, tenant.ID, n.ID), nil)
	req.Header.Set("Authorization", "Bearer dev:user-1:")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 204 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete: %d %s", resp.StatusCode, b)
	}
	resp.Body.Close()
}

func TestUnauthenticatedReject(t *testing.T) {
	ts, _ := newTestServer(t)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/tenants", strings.NewReader(`{"kind":"user","name":"x"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d", resp.StatusCode)
	}
}
