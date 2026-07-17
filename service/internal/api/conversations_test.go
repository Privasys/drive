package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
