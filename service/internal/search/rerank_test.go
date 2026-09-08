package search

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFleetRerankerFormatsPairsAndOrders: the caller formats the Qwen3
// instruction frame on both sides of every pair, asks for top_n without
// return_documents, and gets results highest score first.
func TestFleetRerankerFormatsPairsAndOrders(t *testing.T) {
	var got struct {
		Model     string   `json:"model"`
		Query     string   `json:"query"`
		Documents []string `json:"documents"`
		TopN      int      `json:"top_n"`
		Return    *bool    `json:"return_documents"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/rerank" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("no bearer expected on the attested dial, got %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		// Deliberately unsorted: the client must order by score.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[{"index":0,"relevance_score":0.12},{"index":2,"relevance_score":0.97},{"index":1,"relevance_score":0.55}],"usage":{"total_tokens":42}}`))
	}))
	defer srv.Close()

	rr := &FleetReranker{BaseURL: srv.URL, Model: "qwen3-reranker-06b"}
	res, err := rr.Rerank(t.Context(), "capital of France", []string{"Berlin", "Paris is nice", "Paris is the capital"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "qwen3-reranker-06b" || got.TopN != 2 || got.Return != nil {
		t.Fatalf("request: %+v", got)
	}
	if !strings.Contains(got.Query, "<Query>: capital of France") || !strings.HasPrefix(got.Query, rerankPrefix) || !strings.Contains(got.Query, rerankInstruct) {
		t.Fatalf("query not framed: %q", got.Query)
	}
	if len(got.Documents) != 3 || got.Documents[2] != "<Document>: Paris is the capital"+rerankSuffix {
		t.Fatalf("documents not framed: %q", got.Documents)
	}
	if len(res) != 2 || res[0].Index != 2 || res[0].Score != 0.97 || res[1].Index != 1 {
		t.Fatalf("results: %+v", res)
	}
}

func TestFleetRerankerRejectsOutOfRangeIndex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"index":7,"relevance_score":0.9}]}`))
	}))
	defer srv.Close()
	rr := &FleetReranker{BaseURL: srv.URL, Model: "m"}
	if _, err := rr.Rerank(t.Context(), "q", []string{"a"}, 1); err == nil {
		t.Fatal("expected an error for an out-of-range index")
	}
}
