package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/objectstore"
)

// TestConversationLifecycle drives the §8.7 conversation flow through the
// tool surface: create → append turns → resume → attach (both intents) →
// list, and checks the transcript is no_index while a knowledge
// attachment is not.
func TestConversationLifecycle(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner = "user-1"
	// Personal tenant.
	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)

	// Create a conversation.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/create_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"title":"Model pricing review","date":"2026-07-17"}`, tenant.ID)))
	if code != 201 {
		t.Fatalf("create_conversation: %d %s", code, b)
	}
	var conv struct {
		ConversationID string `json:"conversation_id"`
		Name           string `json:"name"`
		TranscriptID   string `json:"transcript_id"`
		FilesFolderID  string `json:"files_folder_id"`
		Finalized      bool   `json:"finalized"`
	}
	if err := json.Unmarshal(b, &conv); err != nil {
		t.Fatal(err)
	}
	if conv.Name != "2026-07-17-model-pricing-review" || conv.TranscriptID == "" || conv.FilesFolderID == "" {
		t.Fatalf("conversation shape: %s", b)
	}
	if conv.Finalized {
		t.Fatal("new conversation must not be finalized")
	}

	// Re-create is idempotent (same ids).
	code, b2 := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/create_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"title":"Model pricing review","date":"2026-07-17"}`, tenant.ID)))
	var conv2 struct {
		ConversationID string `json:"conversation_id"`
	}
	_ = json.Unmarshal(b2, &conv2)
	if code != 201 || conv2.ConversationID != conv.ConversationID {
		t.Fatalf("create not idempotent: %d %s", code, b2)
	}

	// Append two turns.
	for _, turn := range []string{`{"role":"user","content":"what is the H100 rate"}`, `{"role":"assistant","content":"7 GBP/hr"}`} {
		payload, _ := json.Marshal(map[string]string{
			"tenant_id": tenant.ID, "conversation_id": conv.ConversationID, "turn": turn,
		})
		code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/append_turn", owner, string(payload)))
		if code != 200 {
			t.Fatalf("append_turn: %d %s", code, b)
		}
	}

	// Resume: the transcript is two JSONL lines in order.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/get_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"conversation_id":%q}`, tenant.ID, conv.ConversationID)))
	if code != 200 {
		t.Fatalf("get_conversation: %d %s", code, b)
	}
	var got struct {
		Transcript string `json:"transcript"`
	}
	_ = json.Unmarshal(b, &got)
	lines := strings.Split(strings.TrimRight(got.Transcript, "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "H100 rate") || !strings.Contains(lines[1], "7 GBP") {
		t.Fatalf("transcript unexpected: %q", got.Transcript)
	}

	// The transcript node must be no_index (raw transcripts poison search).
	if _, noIndex, err := srv.Store.NodeIndexMeta(t.Context(), tenant.ID, conv.TranscriptID); err != nil || !noIndex {
		t.Fatalf("transcript should be no_index (noIndex=%v err=%v)", noIndex, err)
	}

	// Attach a knowledge-intent file: persists and is NOT no_index.
	kb := base64.StdEncoding.EncodeToString([]byte("# Notes\nThe rate is seven pounds per hour."))
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/attach_to_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"conversation_id":%q,"name":"notes.md","mime":"text/markdown","content_base64":%q,"intent":"knowledge"}`,
			tenant.ID, conv.ConversationID, kb)))
	if code != 200 {
		t.Fatalf("attach knowledge: %d %s", code, b)
	}
	var att struct {
		Node   nodeJSON `json:"node"`
		Intent string   `json:"intent"`
	}
	_ = json.Unmarshal(b, &att)
	if att.Intent != "knowledge" {
		t.Fatalf("intent: %s", b)
	}
	if _, noIndex, _ := srv.Store.NodeIndexMeta(t.Context(), tenant.ID, att.Node.ID); noIndex {
		t.Fatal("knowledge attachment must be indexable")
	}

	// Attach a session-intent file that expires immediately; the sweep GCs it.
	sess := base64.StdEncoding.EncodeToString([]byte("ephemeral draft"))
	past := time.Now().Add(-time.Minute).Unix()
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/attach_to_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"conversation_id":%q,"name":"draft.txt","mime":"text/plain","content_base64":%q,"intent":"session","expires_unix":%d}`,
			tenant.ID, conv.ConversationID, sess, past)))
	if code != 200 {
		t.Fatalf("attach session: %d %s", code, b)
	}
	var sessAtt struct {
		Node nodeJSON `json:"node"`
	}
	_ = json.Unmarshal(b, &sessAtt)
	if _, noIndex, _ := srv.Store.NodeIndexMeta(t.Context(), tenant.ID, sessAtt.Node.ID); !noIndex {
		t.Fatal("session attachment must be no_index")
	}
	removed, err := srv.Store.SweepExpiredNodes(t.Context(), time.Now())
	if err != nil || removed < 1 {
		t.Fatalf("sweep removed %d (err %v)", removed, err)
	}
	if _, gerr := srv.Store.GetNode(t.Context(), tenant.ID, sessAtt.Node.ID); gerr == nil {
		t.Fatal("expired session attachment should be gone")
	}
	// The knowledge attachment survives the sweep.
	if _, gerr := srv.Store.GetNode(t.Context(), tenant.ID, att.Node.ID); gerr != nil {
		t.Fatalf("knowledge attachment must survive: %v", gerr)
	}

	// List shows the conversation, not finalized.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/list_conversations", owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID)))
	if code != 200 {
		t.Fatalf("list_conversations: %d %s", code, b)
	}
	var list struct {
		Conversations []struct {
			ConversationID string `json:"conversation_id"`
			Finalized      bool   `json:"finalized"`
		} `json:"conversations"`
	}
	_ = json.Unmarshal(b, &list)
	if len(list.Conversations) != 1 || list.Conversations[0].ConversationID != conv.ConversationID || list.Conversations[0].Finalized {
		t.Fatalf("list unexpected: %s", b)
	}

	// A stranger cannot list or create in this tenant.
	if code, _ := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/list_conversations", "user-9",
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID))); code != http.StatusForbidden {
		t.Fatalf("stranger list: want 403, got %d", code)
	}
}

// TestDeleteConversation covers the delete surface: the whole conversation
// subtree (folder, transcript, files/, attachments, digest) is removed, its
// sealed blobs are reclaimed from the object store, and a node that is not a
// conversation folder is rejected rather than deleted.
func TestDeleteConversation(t *testing.T) {
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

	// A conversation with a turn (writes the transcript blob) and a knowledge
	// attachment (its own blob) — so the delete has descendant files to reclaim.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/create_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"title":"Trip planning","date":"2026-07-18"}`, tenant.ID)))
	if code != 201 {
		t.Fatalf("create_conversation: %d %s", code, b)
	}
	var conv struct {
		ConversationID string `json:"conversation_id"`
		TranscriptID   string `json:"transcript_id"`
		FilesFolderID  string `json:"files_folder_id"`
	}
	_ = json.Unmarshal(b, &conv)

	turn, _ := json.Marshal(map[string]string{
		"tenant_id": tenant.ID, "conversation_id": conv.ConversationID,
		"turn": `{"role":"user","content":"where to in July"}`,
	})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/append_turn", owner, string(turn))); code != 200 {
		t.Fatalf("append_turn: %d %s", code, b)
	}

	kb := base64.StdEncoding.EncodeToString([]byte("# Itinerary\nDay 1: arrive."))
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/attach_to_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"conversation_id":%q,"name":"plan.md","mime":"text/markdown","content_base64":%q,"intent":"knowledge"}`,
			tenant.ID, conv.ConversationID, kb)))
	if code != 200 {
		t.Fatalf("attach: %d %s", code, b)
	}
	var att struct {
		Node struct {
			ID string `json:"id"`
		} `json:"node"`
	}
	_ = json.Unmarshal(b, &att)

	root := srv.Backend.(*objectstore.LocalBackend).Root
	countBlobs := func() int {
		n := 0
		_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				n++
			}
			return nil
		})
		return n
	}
	before := countBlobs()
	if before == 0 {
		t.Fatal("expected sealed blobs before delete")
	}

	// Delete the conversation.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/delete_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"conversation_id":%q}`, tenant.ID, conv.ConversationID)))
	if code != 200 {
		t.Fatalf("delete_conversation: %d %s", code, b)
	}
	var del struct {
		Deleted string `json:"deleted"`
	}
	_ = json.Unmarshal(b, &del)
	if del.Deleted != conv.ConversationID {
		t.Fatalf("deleted mismatch: %s", b)
	}

	// The whole subtree is gone.
	for _, id := range []string{conv.ConversationID, conv.TranscriptID, conv.FilesFolderID, att.Node.ID} {
		if _, err := srv.Store.GetNode(t.Context(), tenant.ID, id); err == nil {
			t.Fatalf("node %s should be deleted", id)
		}
	}
	// The blobs were reclaimed, not orphaned.
	if after := countBlobs(); after >= before {
		t.Fatalf("blobs not reclaimed: before=%d after=%d", before, after)
	}
	// It no longer lists.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/list_conversations", owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID)))
	var list struct {
		Conversations []json.RawMessage `json:"conversations"`
	}
	_ = json.Unmarshal(b, &list)
	if code != 200 || len(list.Conversations) != 0 {
		t.Fatalf("still listed: %d %s", code, b)
	}

	// A plain folder that is not a conversation is rejected, not deleted.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/create_folder", owner,
		fmt.Sprintf(`{"tenant_id":%q,"name":"Docs"}`, tenant.ID)))
	if code != 200 && code != 201 {
		t.Fatalf("create_folder: %d %s", code, b)
	}
	// create_folder returns the node view directly (not wrapped in "node").
	var folder struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &folder)
	if folder.ID == "" {
		t.Fatalf("create_folder id missing: %s", b)
	}
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/delete_conversation", owner,
		fmt.Sprintf(`{"tenant_id":%q,"conversation_id":%q}`, tenant.ID, folder.ID))); code != http.StatusBadRequest {
		t.Fatalf("delete non-conversation: want 400, got %d %s", code, b)
	}
	if _, err := srv.Store.GetNode(t.Context(), tenant.ID, folder.ID); err != nil {
		t.Fatalf("non-conversation folder must survive a rejected delete: %v", err)
	}
}

// TestSharedConversationRead covers the read-only share path: the owner shares
// a conversation folder with another user (a share-link grant), who can then
// read the conversation — transcript included — while a stranger cannot, and
// the recipient still cannot write (append) to it.
func TestSharedConversationRead(t *testing.T) {
	base, _ := newTestServer(t)
	const owner, guest, stranger = "user-a", "user-b", "user-x"

	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"A"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)

	code, b = doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants/"+tenant.ID+"/conversations", owner,
		`{"title":"Roadmap sync","date":"2026-07-20"}`))
	if code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	var conv struct {
		ConversationID string `json:"conversation_id"`
	}
	_ = json.Unmarshal(b, &conv)

	turnURL := base.URL + "/v1/tenants/" + tenant.ID + "/conversations/" + conv.ConversationID + "/turns"
	if code, b = doReq(t, bearerReq(t, "POST", turnURL, owner, `{"turn":"{\"role\":\"user\",\"content\":\"ship it\"}"}`)); code != 200 {
		t.Fatalf("append: %d %s", code, b)
	}

	getURL := base.URL + "/v1/tenants/" + tenant.ID + "/conversations/" + conv.ConversationID

	// Before any share, the guest cannot read the conversation.
	if code, _ := doReq(t, bearerReq(t, "GET", getURL, guest, "")); code != http.StatusForbidden {
		t.Fatalf("pre-share get: want 403, got %d", code)
	}

	// Owner shares the conversation folder with the guest (read).
	code, b = doReq(t, bearerReq(t, "POST",
		base.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+conv.ConversationID+"/grants",
		owner, `{"subject":"subject:`+guest+`","scope":["read"]}`))
	if code != 201 {
		t.Fatalf("grant: %d %s", code, b)
	}

	// The guest can now read it as a conversation, transcript included.
	code, b = doReq(t, bearerReq(t, "GET", getURL, guest, ""))
	if code != 200 {
		t.Fatalf("shared get: %d %s", code, b)
	}
	var got struct {
		Transcript string `json:"transcript"`
	}
	_ = json.Unmarshal(b, &got)
	if !strings.Contains(got.Transcript, "ship it") {
		t.Fatalf("shared transcript missing content: %q", got.Transcript)
	}

	// A stranger with no grant still cannot.
	if code, _ := doReq(t, bearerReq(t, "GET", getURL, stranger, "")); code != http.StatusForbidden {
		t.Fatalf("stranger get: want 403, got %d", code)
	}

	// Read-only: the guest cannot append (writes stay owner-only).
	if code, _ := doReq(t, bearerReq(t, "POST", turnURL, guest, `{"turn":"{\"role\":\"user\",\"content\":\"hi\"}"}`)); code != http.StatusForbidden {
		t.Fatalf("guest append: want 403, got %d", code)
	}
}
