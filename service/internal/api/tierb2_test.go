package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/objectstore"
)

// D3: append is proportional to the turn, keeps the rev fence, and the
// resulting non-uniform chunk layout still range-reads correctly.
func TestD3AppendAndRangeAcrossAppends(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	st, b, _ := rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/files?name=log.jsonl", devAuth, "line1\n", nil)
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	var f struct {
		ID  string `json:"id"`
		Rev int64  `json:"rev"`
	}
	_ = json.Unmarshal(b, &f)

	// Append with the right rev.
	st, b, hdr := rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+f.ID+"/append", devAuth, "line2\n", map[string]string{"If-Match": fmt.Sprintf(`"%d"`, f.Rev)})
	if st != 200 {
		t.Fatalf("append: %d %s", st, b)
	}
	var ap struct {
		Rev  int64 `json:"rev"`
		Size int64 `json:"size"`
	}
	_ = json.Unmarshal(b, &ap)
	if ap.Size != int64(len("line1\nline2\n")) || ap.Rev <= f.Rev || hdr.Get("ETag") != fmt.Sprintf(`"%d"`, ap.Rev) {
		t.Fatalf("append result %s etag %q", b, hdr.Get("ETag"))
	}
	// A stale rev is refused.
	st, _, _ = rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+f.ID+"/append", devAuth, "x", map[string]string{"If-Match": fmt.Sprintf(`"%d"`, f.Rev)})
	if st != http.StatusPreconditionFailed {
		t.Fatalf("stale append: want 412, got %d", st)
	}
	// Unconditional append.
	st, _, _ = rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+f.ID+"/append", devAuth, "line3\n", nil)
	if st != 200 {
		t.Fatalf("append 2: %d", st)
	}
	// Full read is the concatenation.
	_, rb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+f.ID, devAuth, "", nil)
	if string(rb) != "line1\nline2\nline3\n" {
		t.Fatalf("content %q", rb)
	}
	// Range across the (now non-uniform) chunk boundaries.
	_, rb, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+f.ID, devAuth, "", map[string]string{"Range": "bytes=4-13"})
	if string(rb) != "1\nline2\nli" {
		t.Fatalf("range across appends %q", rb)
	}
	_, rb, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+f.ID, devAuth, "", map[string]string{"Range": "bytes=-6"})
	if string(rb) != "line3\n" {
		t.Fatalf("suffix after appends %q", rb)
	}
}

// Conversation turns ride D3: the transcript grows by the turn only and
// keeps its line discipline.
func TestAppendTurnUsesAppend(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	resp, b := doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/conversations", devAuth, `{"title":"t"}`)
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		t.Fatalf("create conversation: %d %s", resp.StatusCode, b)
	}
	var conv struct {
		ConversationID string `json:"conversation_id"`
		TranscriptID   string `json:"transcript_id"`
	}
	_ = json.Unmarshal(b, &conv)
	for i := 1; i <= 3; i++ {
		resp, b = doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/conversations/"+conv.ConversationID+"/turns", devAuth,
			fmt.Sprintf(`{"turn":"{\"n\":%d}"}`, i))
		if resp.StatusCode != 200 {
			t.Fatalf("turn %d: %d %s", i, resp.StatusCode, b)
		}
	}
	_, rb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+conv.TranscriptID, devAuth, "", nil)
	if string(rb) != "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n" {
		t.Fatalf("transcript %q", rb)
	}
}

// D5: the feed carries node facts, filters to a subtree (including deletes
// by their recorded parent), and long-poll returns as soon as a change lands.
func TestD5SubtreeChangesAndLongPoll(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	_, body = doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/folders", devAuth, `{"name":"A"}`)
	var fa struct{ ID string }
	_ = json.Unmarshal(body, &fa)
	_, body = doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/folders", devAuth, `{"name":"B"}`)
	var fb struct{ ID string }
	_ = json.Unmarshal(body, &fb)

	// Files in A and in B.
	st, b, _ := rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/files?name=a.txt&parent_id="+fa.ID, devAuth, "a", nil)
	if st != 201 {
		t.Fatalf("a.txt: %d %s", st, b)
	}
	var fileA struct{ ID string }
	_ = json.Unmarshal(b, &fileA)
	st, _, _ = rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/files?name=b.txt&parent_id="+fb.ID, devAuth, "b", nil)
	if st != 201 {
		t.Fatalf("b.txt: %d", st)
	}

	// Subtree A sees only A's file.
	_, cb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/changes?since=0&root="+fa.ID, devAuth, "", nil)
	var rows []changeJSON
	_ = json.Unmarshal(cb, &rows)
	names := map[string]bool{}
	for _, r := range rows {
		names[r.Name] = true
		if r.Kind == "" || r.NodeID == "" {
			t.Fatalf("row lacks facts: %+v", r)
		}
	}
	if !names["a.txt"] || names["b.txt"] {
		t.Fatalf("subtree filter wrong: %s", cb)
	}
	last := rows[len(rows)-1].Seq

	// Delete a.txt: the delete row is still attributed to subtree A via its
	// recorded parent, even though the node is gone.
	rawReq(t, "DELETE", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+fileA.ID, devAuth, "", nil)
	_, cb, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/changes?since="+fmt.Sprint(last)+"&root="+fa.ID, devAuth, "", nil)
	rows = nil
	_ = json.Unmarshal(cb, &rows)
	if len(rows) != 1 || rows[0].Op != "delete" || rows[0].Name != "a.txt" || rows[0].ParentID != fa.ID {
		t.Fatalf("delete row: %s", cb)
	}
	last = rows[0].Seq

	// Folder A's rev advanced on child add and remove.
	_, fab, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=A", devAuth, "", nil)
	var folderA struct {
		Rev int64 `json:"rev"`
	}
	_ = json.Unmarshal(fab, &folderA)
	if folderA.Rev < 2 {
		t.Fatalf("folder rev did not bump on child add/remove: %d", folderA.Rev)
	}

	// Long-poll: a request with wait=5 returns as soon as a change lands.
	done := make(chan []byte, 1)
	go func() {
		_, pb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/changes?since="+fmt.Sprint(last)+"&root="+fa.ID+"&wait=5", devAuth, "", nil)
		done <- pb
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	rawReq(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/files?name=late.txt&parent_id="+fa.ID, devAuth, "late", nil)
	select {
	case pb := <-done:
		rows = nil
		_ = json.Unmarshal(pb, &rows)
		if len(rows) != 1 || rows[0].Name != "late.txt" {
			t.Fatalf("long-poll rows: %s", pb)
		}
		if time.Since(start) > 3*time.Second {
			t.Fatalf("long-poll took %v, expected to wake on the change", time.Since(start))
		}
	case <-time.After(8 * time.Second):
		t.Fatal("long-poll never returned")
	}
}

// The drain is a manifest ACTION: it must be reachable at the top-level
// /actions/... paths through the full server, not only inside /v1. On an
// instance whose backend is still local the action is refused (409), and
// the status tool answers idle.
func TestDrainActionRoutesAreTopLevel(t *testing.T) {
	ts := newFullServer(t, nil)
	st, b, _ := rawReq(t, "GET", ts.URL+"/actions/drain_local_objects/status", devAuth, "", nil)
	if st != 200 || !strings.Contains(string(b), `"state":"idle"`) {
		t.Fatalf("status route: %d %s", st, b)
	}
	st, b, _ = rawReq(t, "POST", ts.URL+"/actions/drain_local_objects", devAuth, "{}", nil)
	if st != http.StatusConflict {
		t.Fatalf("drain on a local backend: want 409, got %d %s", st, b)
	}

	// With a bucket configured the action starts the copy and reports it.
	// (The handler once reset the status by assigning a struct literal over
	// the held mutex, which crashed the process on the first real drain.)
	var srv2 *Server
	ts2 := newFullServer(t, func(s *Server) { srv2 = s })
	srv2.objectMu.Lock()
	srv2.Backend = notLocal{srv2.Backend}
	srv2.objectMu.Unlock()
	st, b, _ = rawReq(t, "POST", ts2.URL+"/actions/drain_local_objects", devAuth, "{}", nil)
	if st != http.StatusAccepted || !strings.Contains(string(b), `"state":"running"`) {
		t.Fatalf("drain on a bucket: want 202 running, got %d %s", st, b)
	}
	srv2.bg.Wait()
	st, b, _ = rawReq(t, "GET", ts2.URL+"/actions/drain_local_objects/status", devAuth, "", nil)
	if st != 200 || !strings.Contains(string(b), `"state":"done"`) {
		t.Fatalf("drain status after run: %d %s", st, b)
	}
	// A second run is allowed once the first finished (the reset path again).
	st, _, _ = rawReq(t, "POST", ts2.URL+"/actions/drain_local_objects", devAuth, "{}", nil)
	if st != http.StatusAccepted {
		t.Fatalf("second drain: want 202, got %d", st)
	}
	srv2.bg.Wait()
}

// Point 1: the drain copies every local object into the target, skips what
// is already there, and reports counts.
func TestDrainCopiesLocalObjects(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	src, _ := objectstore.NewLocal(srcDir)
	dst, _ := objectstore.NewLocal(dstDir)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("t/aa/c/%02d/obj%d", i, i)
		if err := src.PutChunk(ctx, key, strings.NewReader(strings.Repeat("x", i+1)), int64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	// One already present at the destination.
	_ = dst.PutChunk(ctx, "t/aa/c/00/obj0", strings.NewReader("x"), 1)
	// A stray temp file that must be ignored.
	_ = os.WriteFile(filepath.Join(srcDir, ".tmp-123"), []byte("junk"), 0o600)

	s := &Server{StateDir: filepath.Dir(srcDir)}
	_ = os.Rename(srcDir, filepath.Join(filepath.Dir(srcDir), "objects"))
	src, _ = objectstore.NewLocal(filepath.Join(s.StateDir, "objects"))
	s.runDrain(ctx, src, dst)
	snap := s.drainSnapshot()
	if snap["state"] != "done" || snap["copied"].(int64) != 4 || snap["skipped"].(int64) != 1 || snap["failed"].(int64) != 0 {
		t.Fatalf("drain snapshot: %+v", snap)
	}
	for i := 0; i < 5; i++ {
		if _, err := dst.Head(ctx, fmt.Sprintf("t/aa/c/%02d/obj%d", i, i)); err != nil {
			t.Fatalf("obj%d missing at destination: %v", i, err)
		}
	}
}

// notLocal hides the concrete *LocalBackend so the drain handler treats the
// instance store as a bucket.
type notLocal struct{ objectstore.Backend }
