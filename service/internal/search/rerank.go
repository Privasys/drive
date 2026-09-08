package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Rerank leg (drive plan §8.4): the vector index recalls candidates, the
// fleet's cross-encoder (Qwen3-Reranker behind the Cohere-style
// /v1/rerank) scores each (query, chunk) pair and the top ones are
// returned. Similarity is not relevance; the reranker reads both texts.
//
// The Qwen3 reranker is instruction-aware and the fleet stays
// instruction-agnostic (it scores the pairs it is given), so the task
// instruction and the model's prompt frame are formatted HERE, as
// versioned image-baked constants: changing them is a measured Drive
// release, never a config edit.
const (
	rerankPrefix = "<|im_start|>system\nJudge whether the Document meets the requirements based on the Query and the Instruct provided. Note that the answer can only be \"yes\" or \"no\".<|im_end|>\n<|im_start|>user\n"
	rerankSuffix = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
	// rerankInstruct is the retrieval task the reranker judges against.
	rerankInstruct = "Given a search query, retrieve relevant passages that answer the query"
	// rerankMaxDocs bounds one call (the index recalls at most this many).
	rerankMaxDocs = 50
)

// RerankQuery formats the query side of every pair.
func RerankQuery(query string) string {
	return rerankPrefix + "<Instruct>: " + rerankInstruct + "\n<Query>: " + query + "\n"
}

// RerankDocument formats the document side of every pair.
func RerankDocument(doc string) string {
	return "<Document>: " + doc + rerankSuffix
}

// RerankResult is one scored candidate: Index into the documents passed
// in, Score the reranker's relevance in [0,1] (the "yes" probability).
type RerankResult struct {
	Index int
	Score float64
}

// FleetReranker calls the fleet's /v1/rerank. It rides the same fleet
// host + attested pin as FleetEmbedder (the caller passes the pinned
// RA-TLS client), so chunk plaintext only ever reaches the pinned peer.
type FleetReranker struct {
	BaseURL string
	Model   string
	APIKey  string
	Client  *http.Client
}

// Rerank scores docs against query and returns the topN best, highest
// first. return_documents is never requested: the caller holds the
// texts, and echoing them back is one more place content would appear.
func (r *FleetReranker) Rerank(ctx context.Context, query string, docs []string, topN int) ([]RerankResult, error) {
	if r.BaseURL == "" || r.Model == "" {
		return nil, fmt.Errorf("fleet rerank not configured")
	}
	if len(docs) == 0 {
		return nil, nil
	}
	if len(docs) > rerankMaxDocs {
		docs = docs[:rerankMaxDocs]
	}
	if topN <= 0 || topN > len(docs) {
		topN = len(docs)
	}
	formatted := make([]string, len(docs))
	for i, d := range docs {
		formatted[i] = RerankDocument(d)
	}
	body, err := json.Marshal(map[string]any{
		"model":     r.Model,
		"query":     RerankQuery(query),
		"documents": formatted,
		"top_n":     topN,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(r.BaseURL, "/")+"/v1/rerank", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.APIKey)
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("fleet rerank: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Results []struct {
			Index int     `json:"index"`
			Score float64 `json:"relevance_score"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	res := make([]RerankResult, 0, len(out.Results))
	for _, x := range out.Results {
		if x.Index < 0 || x.Index >= len(docs) {
			return nil, fmt.Errorf("fleet rerank: index %d out of range for %d documents", x.Index, len(docs))
		}
		res = append(res, RerankResult{Index: x.Index, Score: x.Score})
	}
	// The wire contract orders results by score; sort defensively so a
	// caller can rely on it regardless of the serving implementation.
	sort.SliceStable(res, func(i, j int) bool { return res[i].Score > res[j].Score })
	if len(res) > topN {
		res = res[:topN]
	}
	return res, nil
}
