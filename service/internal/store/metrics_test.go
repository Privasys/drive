package store

import (
	"context"
	"testing"
)

func TestAccessMetrics(t *testing.T) { forEachStore(t, testAccessMetrics) }

func testAccessMetrics(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "metrics-user"}
	if err := s.CreateTenant(ctx, tt, "owner-sub"); err != nil {
		t.Fatal(err)
	}
	n := &Node{TenantID: tt.ID, Kind: NodeFile, Name: "report.pdf",
		NameHMAC: []byte("0123456789abcdef0123456789abcdef")}
	if err := s.CreateNode(ctx, n, "owner-sub"); err != nil {
		t.Fatal(err)
	}

	events := []AccessEvent{
		{TenantID: tt.ID, Sub: "sub-a", Event: "view", NodeID: n.ID, DurationMS: 1200, Bytes: 500},
		{TenantID: tt.ID, Sub: "sub-a", Event: "download", NodeID: n.ID, DurationMS: 300, Bytes: 500},
		{TenantID: tt.ID, Sub: "sub-b", Event: "view", NodeID: n.ID, DurationMS: 800, Bytes: 500},
		// A nodeless event (e.g. future session events) must not break joins.
		{TenantID: tt.ID, Sub: "sub-b", Event: "view"},
	}
	for _, e := range events {
		if err := s.RecordAccessEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	series, err := s.MetricsSeries(ctx, tt.ID, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || series[0].Views != 3 || series[0].Downloads != 1 || series[0].UniqueSubs != 2 {
		t.Fatalf("series = %+v", series)
	}

	nodes, err := s.MetricsTopNodes(ctx, tt.ID, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].NodeID != n.ID || nodes[0].Name != "report.pdf" || nodes[0].Views != 3 {
		t.Fatalf("top nodes = %+v", nodes)
	}
	if nodes[0].LastAt == "" {
		t.Fatal("last_at missing")
	}

	subs, err := s.MetricsSubs(ctx, tt.ID, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 {
		t.Fatalf("subs = %+v", subs)
	}
	// sub-b has 2 views, sub-a 1 view + 1 download; ordering is by views.
	if subs[0].Sub != "sub-b" || subs[0].Views != 2 {
		t.Fatalf("subs[0] = %+v", subs[0])
	}
	if subs[1].Sub != "sub-a" || subs[1].Downloads != 1 || subs[1].TotalMS != 1500 {
		t.Fatalf("subs[1] = %+v", subs[1])
	}

	// Another tenant sees nothing.
	other, err := s.MetricsSubs(ctx, "no-such-tenant", 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("cross-tenant leak: %+v", other)
	}
}
