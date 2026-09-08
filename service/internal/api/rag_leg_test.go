package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
)

// TestConfigureOverlay_RAGFields: rerank_model and summarise_on_ingest
// ride the merge-by-omission overlay like the other fleet settings, and
// the status document discloses them.
func TestConfigureOverlay_RAGFields(t *testing.T) {
	cur := &config.Config{Mode: config.ModeSovereign, EmbeddingsBaseURL: "https://fleet.example",
		EmbeddingsModel: "qwen3-embedding-06b", ChatModel: "chat", EmbeddingsDependency: `{"entries":[]}`}
	rerank, on := "qwen3-reranker-06b", true
	got := (&configureRequest{Mode: config.ModeSovereign, RerankModel: &rerank, SummariseOnIngest: &on}).overlay(cur)
	if got.RerankModel != "qwen3-reranker-06b" || !got.SummariseOnIngest || got.ChatModel != "chat" {
		t.Fatalf("overlay: %+v", got)
	}
	// Omitted: kept.
	got2 := (&configureRequest{Mode: config.ModeSovereign}).overlay(got)
	if got2.RerankModel != "qwen3-reranker-06b" || !got2.SummariseOnIngest {
		t.Fatalf("omission must keep the fields: %+v", got2)
	}
	// Explicit clear.
	empty, off := "", false
	got3 := (&configureRequest{Mode: config.ModeSovereign, RerankModel: &empty, SummariseOnIngest: &off}).overlay(got)
	if got3.RerankModel != "" || got3.SummariseOnIngest {
		t.Fatalf("explicit clear: %+v", got3)
	}

	srv := &Server{}
	setCfg := func(c *config.Config) {
		srv.cfgMu.Lock()
		srv.cfg = c
		srv.cfgMu.Unlock()
	}
	setCfg(got)
	doc := srv.statusDoc()
	if doc.AI == nil || doc.AI.RerankModel != "qwen3-reranker-06b" || !doc.AI.SummariseOnIngest || !doc.AI.Pinned {
		t.Fatalf("status disclosure: %+v", doc.AI)
	}
	setCfg(&config.Config{Mode: config.ModeSovereign, EmbeddingsBaseURL: "https://fleet.example", SummariseOnIngest: true})
	if doc := srv.statusDoc(); doc.AI == nil || doc.AI.SummariseOnIngest || doc.AI.Pinned {
		t.Fatalf("summaries need a chat model, and no pin means not pinned: %+v", doc.AI)
	}
}

// TestSummariesToggle: a folder opted out of summaries covers the files
// below it; re-enabling clears it. Write permission required.
func TestSummariesToggle(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner, stranger = "user-1", "user-9"
	tenantID, _, _ := ownerTenantWithFile(t, ts.URL, owner)

	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/folders", ts.URL, tenantID), owner, `{"name":"Confidential"}`))
	if code != 201 {
		t.Fatalf("create folder: %d %s", code, b)
	}
	var folder nodeJSON
	_ = json.Unmarshal(b, &folder)
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=inside.txt&parent_id=%s", ts.URL, tenantID, folder.ID),
		owner, "inside a confidential folder"))
	if code != 201 {
		t.Fatalf("upload inside: %d %s", code, b)
	}
	var inside nodeJSON
	_ = json.Unmarshal(b, &inside)

	if off, err := srv.Store.HasNoSummariseAncestor(t.Context(), tenantID, inside.ID); err != nil || off {
		t.Fatalf("default must summarise: off=%v err=%v", off, err)
	}
	if code, _ := doReq(t, bearerReq(t, "PUT",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/summaries", ts.URL, tenantID, folder.ID),
		stranger, `{"enabled":false}`)); code != http.StatusForbidden {
		t.Fatalf("stranger toggle: want 403, got %d", code)
	}
	code, b = doReq(t, bearerReq(t, "PUT",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/summaries", ts.URL, tenantID, folder.ID),
		owner, `{"enabled":false}`))
	if code != 200 {
		t.Fatalf("toggle: %d %s", code, b)
	}
	if off, err := srv.Store.HasNoSummariseAncestor(t.Context(), tenantID, inside.ID); err != nil || !off {
		t.Fatalf("ancestor opt-out: off=%v err=%v", off, err)
	}
	if code, _ := doReq(t, bearerReq(t, "PUT",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/summaries", ts.URL, tenantID, folder.ID),
		owner, `{"enabled":true}`)); code != 200 {
		t.Fatalf("re-enable: %d", code)
	}
	if off, _ := srv.Store.HasNoSummariseAncestor(t.Context(), tenantID, inside.ID); off {
		t.Fatalf("still opted out after re-enable")
	}
	if code, _ := doReq(t, bearerReq(t, "PUT",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/summaries", ts.URL, tenantID, "no-such-node"),
		owner, `{"enabled":false}`)); code != http.StatusNotFound {
		t.Fatalf("unknown node: want 404, got %d", code)
	}
}

// TestSectionSummariesStoredAndServed: summaries land on the sections by
// row id with the model stamp, and the doc tree shows them.
func TestSectionSummariesStoredAndServed(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, payload := ownerTenantWithFile(t, ts.URL, owner)
	ids, err := srv.Store.ReplaceSections(t.Context(), tenantID, fileID, []store.SectionInput{
		{ParentIdx: -1, Title: "root", Depth: 0, CharStart: 0, CharEnd: int64(len(payload))},
		{ParentIdx: 0, Title: "part", Depth: 1, CharStart: 0, CharEnd: int64(len(payload))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Store.SetSectionSummaries(t.Context(), tenantID, fileID,
		map[int64]string{ids[0]: "The whole file.", ids[1]: "The part."}, "chat/"+search.SummaryPromptVersion); err != nil {
		t.Fatal(err)
	}
	secs, err := srv.Store.ListSections(t.Context(), tenantID, fileID)
	if err != nil || len(secs) != 2 || secs[0].Summary != "The whole file." || secs[1].Summary != "The part." {
		t.Fatalf("summaries not stored: %+v err=%v", secs, err)
	}
	code, b := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s/tree", ts.URL, tenantID, fileID), owner, ""))
	if code != 200 {
		t.Fatalf("tree: %d %s", code, b)
	}
	var tree struct {
		Sections []struct {
			Summary string `json:"summary"`
		} `json:"sections"`
	}
	_ = json.Unmarshal(b, &tree)
	if len(tree.Sections) != 2 || tree.Sections[1].Summary != "The part." {
		t.Fatalf("tree summaries: %s", b)
	}
}

// TestApplyRerankReordersAndFallsBack: candidates come back in the
// reranker's order with the cosine kept as vector_score; a failing
// reranker leaves vector order and the caller's topK.
func TestApplyRerankReordersAndFallsBack(t *testing.T) {
	hits := []store.SearchHit{
		{NodeID: "a", Content: "alpha", Score: 0.9},
		{NodeID: "b", Content: "bravo", Score: 0.8},
		{NodeID: "c", Content: "charlie", Score: 0.7},
	}
	fleet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"index":2,"relevance_score":0.99},{"index":0,"relevance_score":0.4}]}`))
	}))
	defer fleet.Close()
	rr := &search.FleetReranker{BaseURL: fleet.URL, Model: "rr"}
	out, reranked := applyRerank(t.Context(), rr, "q", hits, 2)
	if !reranked || len(out) != 2 || out[0].NodeID != "c" || out[0].Score != 0.99 || out[0].VectorScore != 0.7 || out[1].NodeID != "a" {
		t.Fatalf("reranked: %+v (%v)", out, reranked)
	}
	if n := recallLimit(2, true); n != 20 {
		t.Fatalf("recall with rerank: %d", n)
	}
	if n := recallLimit(2, false); n != 2 {
		t.Fatalf("recall without rerank: %d", n)
	}
	if n := recallLimit(0, true); n != 40 {
		t.Fatalf("recall default with rerank: %d", n)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	out, reranked = applyRerank(t.Context(), &search.FleetReranker{BaseURL: down.URL, Model: "rr"}, "q", hits, 2)
	if reranked || len(out) != 2 || out[0].NodeID != "a" || out[0].VectorScore != 0 {
		t.Fatalf("fallback: %+v (%v)", out, reranked)
	}
	out, reranked = applyRerank(t.Context(), nil, "q", hits, 0)
	if reranked || len(out) != 3 {
		t.Fatalf("no reranker: %+v", out)
	}
}
