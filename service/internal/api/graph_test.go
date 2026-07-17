package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// TestGraphAndLint: memory wikilinks resolve to edges, a dangling
// wikilink surfaces in lint, and the graph classifies nodes by folder.
func TestGraphAndLint(t *testing.T) {
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

	writeMemory := func(name, summary, body string) {
		payload, _ := json.Marshal(map[string]any{
			"tenant_id": tenant.ID, "name": name, "summary": summary, "body": body,
		})
		if code, rb := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/write_memory", owner, string(payload))); code != 201 {
			t.Fatalf("write memory %s: %d %s", name, code, rb)
		}
	}
	// coffee-preference links to espresso-machine (resolves) and to a
	// non-existent memory (dangling).
	writeMemory("espresso-machine", "The espresso machine model", "A dual-boiler machine.")
	writeMemory("coffee-preference", "Coffee preference",
		"Uses the [[espresso-machine]]; see also [[nonexistent-note]].")

	// Graph: both memories present, the resolved edge exists.
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/graph", base.URL, tenant.ID), owner, ""))
	if code != 200 {
		t.Fatalf("graph: %d %s", code, b)
	}
	var g struct {
		Nodes []struct {
			NodeID string `json:"node_id"`
			Name   string `json:"name"`
			Class  string `json:"class"`
		} `json:"nodes"`
		Edges []struct {
			FromNode string `json:"from_node"`
			ToNode   string `json:"to_node"`
			ToName   string `json:"to_name"`
			Kind     string `json:"kind"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	idByName := map[string]string{}
	for _, n := range g.Nodes {
		idByName[n.Name] = n.NodeID
		if n.Name == "coffee-preference.md" && n.Class != "memory" {
			t.Fatalf("memory node misclassified: %+v", n)
		}
	}
	from := idByName["coffee-preference.md"]
	to := idByName["espresso-machine.md"]
	if from == "" || to == "" {
		t.Fatalf("memory nodes missing from graph: %s", b)
	}
	var resolvedEdge, danglingEdge bool
	for _, e := range g.Edges {
		if e.Kind == "wikilink" && e.FromNode == from && e.ToNode == to {
			resolvedEdge = true
		}
		if e.Kind == "wikilink" && e.FromNode == from && e.ToNode == "" && e.ToName == "nonexistent-note" {
			danglingEdge = true
		}
	}
	if !resolvedEdge {
		t.Fatalf("resolved wikilink edge missing: %s", b)
	}
	if !danglingEdge {
		t.Fatalf("dangling wikilink edge missing: %s", b)
	}

	// Lint: the dangling wikilink shows up.
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/lint", base.URL, tenant.ID), owner, ""))
	if code != 200 {
		t.Fatalf("lint: %d %s", code, b)
	}
	var lint struct {
		Dangling []struct {
			ToName string `json:"to_name"`
		} `json:"dangling_links"`
	}
	_ = json.Unmarshal(b, &lint)
	found := false
	for _, d := range lint.Dangling {
		if d.ToName == "nonexistent-note" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dangling link not in lint: %s", b)
	}

	// Backlinks: espresso-machine is linked from coffee-preference.
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/backlinks", base.URL, tenant.ID, to), owner, ""))
	if code != 200 {
		t.Fatalf("backlinks: %d %s", code, b)
	}
	var bl struct {
		Backlinks []struct {
			FromNode string `json:"from_node"`
		} `json:"backlinks"`
	}
	_ = json.Unmarshal(b, &bl)
	if len(bl.Backlinks) != 1 || bl.Backlinks[0].FromNode != from {
		t.Fatalf("backlinks unexpected: %s", b)
	}
}
