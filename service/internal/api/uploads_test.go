package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// TestChunkedUpload: a large file arrives as sequential parts and
// finalizes into a node whose content reads back byte-identical;
// out-of-order parts are rejected; abort cleans up.
func TestChunkedUpload(t *testing.T) {
	ts, srv := newTestServer(t)
	srv.StateDir = t.TempDir()
	const owner = "user-1"

	code, b := doReq(t, bearerReq(t, "POST", ts.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("create tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &tenant); err != nil {
		t.Fatal(err)
	}

	// 2.5 parts of distinct bytes.
	part1 := bytes.Repeat([]byte("A"), 1<<20)
	part2 := bytes.Repeat([]byte("B"), 1<<20)
	part3 := []byte("tail-bytes")
	whole := append(append(append([]byte{}, part1...), part2...), part3...)

	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/uploads", ts.URL, tenant.ID), owner,
		fmt.Sprintf(`{"name":"big.bin","mime":"application/octet-stream","size":%d}`, len(whole))))
	if code != 201 {
		t.Fatalf("create upload: %d %s", code, b)
	}
	var up struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &up); err != nil {
		t.Fatal(err)
	}

	putPart := func(i int, data []byte) (int, []byte) {
		req, _ := http.NewRequest("PUT",
			fmt.Sprintf("%s/v1/tenants/%s/uploads/%s/chunks/%d", ts.URL, tenant.ID, up.ID, i),
			bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
		return doReq(t, req)
	}

	// Out-of-order part is rejected.
	if code, _ := putPart(1, part2); code != http.StatusConflict {
		t.Fatalf("out-of-order part: want 409, got %d", code)
	}
	for i, data := range [][]byte{part1, part2, part3} {
		if code, b := putPart(i, data); code != 200 {
			t.Fatalf("part %d: %d %s", i, code, b)
		}
	}

	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/uploads/%s/finalize", ts.URL, tenant.ID, up.ID), owner, ""))
	if code != 201 {
		t.Fatalf("finalize: %d %s", code, b)
	}
	var node nodeJSON
	if err := json.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}
	if node.Name != "big.bin" || node.PlainSize != int64(len(whole)) {
		t.Fatalf("node unexpected: %+v", node)
	}

	// Content round-trips.
	req := bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenant.ID, node.ID), owner, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, whole) {
		t.Fatalf("read back: %d, %d bytes (want %d)", resp.StatusCode, len(got), len(whole))
	}

	// The session is gone after finalize.
	if code, _ := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/uploads/%s/finalize", ts.URL, tenant.ID, up.ID), owner, "")); code != http.StatusNotFound {
		t.Fatalf("re-finalize: want 404, got %d", code)
	}

	// Abort works on a fresh session.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/uploads", ts.URL, tenant.ID), owner,
		`{"name":"aborted.bin"}`))
	if code != 201 {
		t.Fatalf("create upload 2: %d %s", code, b)
	}
	_ = json.Unmarshal(b, &up)
	if code, _ := doReq(t, bearerReq(t, "DELETE",
		fmt.Sprintf("%s/v1/tenants/%s/uploads/%s", ts.URL, tenant.ID, up.ID), owner, "")); code != http.StatusNoContent {
		t.Fatalf("abort: want 204, got %d", code)
	}
}
