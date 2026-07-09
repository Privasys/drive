package store

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func newSQLiteStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db, DialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return s
}

// forEachStore runs a test against SQLite and, when DRIVE_TEST_PG_DSN
// is set (CI runs a postgres service), against Postgres with a fresh
// schema per test.
func forEachStore(t *testing.T, run func(t *testing.T, s *Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { run(t, newSQLiteStore(t)) })
	dsn := os.Getenv("DRIVE_TEST_PG_DSN")
	if dsn == "" {
		return
	}
	t.Run("postgres", func(t *testing.T) {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			t.Fatal(err)
		}
		s, err := New(db, DialectPostgres)
		if err != nil {
			t.Fatal(err)
		}
		run(t, s)
	})
}

func TestTenantAndMemberLifecycle(t *testing.T) { forEachStore(t, testtenantAndMemberLifecycle) }

func testtenantAndMemberLifecycle(t *testing.T, s *Store) {
	ctx := context.Background()

	tt := &Tenant{Kind: TenantEnterprise, Name: "Acme"}
	if err := s.CreateTenant(ctx, tt, "creator"); err != nil {
		t.Fatal(err)
	}
	if tt.ID == "" {
		t.Fatal("CreateTenant must populate ID")
	}
	got, err := s.GetTenant(ctx, tt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Acme" {
		t.Fatalf("got name %q", got.Name)
	}
	// The creator is recorded as owner.
	if r, err := s.MemberRoleOf(ctx, tt.ID, "creator"); err != nil || r != RoleOwner {
		t.Fatalf("creator role: %v %v", r, err)
	}

	if err := s.AddMember(ctx, &Member{TenantID: tt.ID, UserSub: "u1", Role: RoleOwner}); err != nil {
		t.Fatal(err)
	}
	r, err := s.MemberRoleOf(ctx, tt.ID, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if r != RoleOwner {
		t.Fatalf("role %q", r)
	}

	// User tenants get an owner membership too, but reject AddMember.
	ut := &Tenant{Kind: TenantUser, Name: "Bertrand"}
	if err := s.CreateTenant(ctx, ut, "bertrand-sub"); err != nil {
		t.Fatal(err)
	}
	if r, err := s.MemberRoleOf(ctx, ut.ID, "bertrand-sub"); err != nil || r != RoleOwner {
		t.Fatalf("user tenant owner role: %v %v", r, err)
	}
	if err := s.AddMember(ctx, &Member{TenantID: ut.ID, UserSub: "u1", Role: RoleAdmin}); err == nil {
		t.Fatal("AddMember on user tenant must fail")
	}

	// A tenant without an owner is rejected.
	if err := s.CreateTenant(ctx, &Tenant{Kind: TenantUser, Name: "x"}, ""); err == nil {
		t.Fatal("CreateTenant without owner must fail")
	}
}

func TestNodeUniqueWithinParent(t *testing.T) { forEachStore(t, testnodeUniqueWithinParent) }

func testnodeUniqueWithinParent(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	_ = s.CreateTenant(ctx, tt, "u")

	hmac := []byte("0123456789abcdef0123456789abcdef")
	n1 := &Node{TenantID: tt.ID, Kind: NodeFile, Name: "Report.pdf", NameHMAC: hmac, MimeHint: "application/pdf"}
	if err := s.CreateNode(ctx, n1, "u"); err != nil {
		t.Fatal(err)
	}
	n2 := &Node{TenantID: tt.ID, Kind: NodeFile, Name: "Report.pdf", NameHMAC: hmac, MimeHint: "application/pdf"}
	if err := s.CreateNode(ctx, n2, "u"); err != ErrConflict {
		t.Fatalf("want ErrConflict got %v", err)
	}
}

func TestListChildrenAndChanges(t *testing.T) { forEachStore(t, testlistChildrenAndChanges) }

func testlistChildrenAndChanges(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	_ = s.CreateTenant(ctx, tt, "actor-sub")

	folder := &Node{TenantID: tt.ID, Kind: NodeFolder, Name: "Docs", NameHMAC: []byte("docsdocsdocsdocsdocsdocsdocsdocs")}
	if err := s.CreateNode(ctx, folder, "actor-sub"); err != nil {
		t.Fatal(err)
	}
	parent := sql.NullString{String: folder.ID, Valid: true}
	for _, name := range []string{"a.txt", "b.txt"} {
		n := &Node{TenantID: tt.ID, ParentID: parent, Kind: NodeFile, Name: name,
			NameHMAC: []byte(name + "00000000000000000000000000000000")[:32]}
		if err := s.CreateNode(ctx, n, "actor-sub"); err != nil {
			t.Fatal(err)
		}
	}
	kids, err := s.ListChildren(ctx, tt.ID, folder.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 2 {
		t.Fatalf("want 2 children got %d", len(kids))
	}

	root, err := s.ListChildren(ctx, tt.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 1 || root[0].Name != "Docs" {
		t.Fatalf("unexpected root listing: %+v", root)
	}

	// Change feed should contain at least 3 creates, attributed.
	ch, err := s.ListChanges(ctx, tt.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) < 3 {
		t.Fatalf("want >=3 changes, got %d", len(ch))
	}
	for _, c := range ch {
		if c.Actor != "actor-sub" {
			t.Fatalf("change %d has actor %q", c.Seq, c.Actor)
		}
	}
}

func TestDeleteNodeRecursive(t *testing.T) { forEachStore(t, testdeleteNodeRecursive) }

func testdeleteNodeRecursive(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	_ = s.CreateTenant(ctx, tt, "u")

	folder := &Node{TenantID: tt.ID, Kind: NodeFolder, Name: "F", NameHMAC: []byte("ffffffffffffffffffffffffffffffff")}
	_ = s.CreateNode(ctx, folder, "u")
	parent := sql.NullString{String: folder.ID, Valid: true}
	child := &Node{TenantID: tt.ID, ParentID: parent, Kind: NodeFile, Name: "x",
		NameHMAC: []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")}
	_ = s.CreateNode(ctx, child, "u")

	if err := s.DeleteNode(ctx, tt.ID, folder.ID, "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNode(ctx, tt.ID, folder.ID); err != ErrNotFound {
		t.Fatal("folder must be gone")
	}
	if _, err := s.GetNode(ctx, tt.ID, child.ID); err != ErrNotFound {
		t.Fatal("child must be gone")
	}
}

func TestIsDescendantOrSelf(t *testing.T) { forEachStore(t, testisDescendantOrSelf) }

func testisDescendantOrSelf(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	_ = s.CreateTenant(ctx, tt, "u")

	top := &Node{TenantID: tt.ID, Kind: NodeFolder, Name: "top", NameHMAC: []byte("tttttttttttttttttttttttttttttttt")}
	_ = s.CreateNode(ctx, top, "u")
	mid := &Node{TenantID: tt.ID, ParentID: sql.NullString{String: top.ID, Valid: true},
		Kind: NodeFolder, Name: "mid", NameHMAC: []byte("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm")}
	_ = s.CreateNode(ctx, mid, "u")
	leaf := &Node{TenantID: tt.ID, ParentID: sql.NullString{String: mid.ID, Valid: true},
		Kind: NodeFile, Name: "leaf", NameHMAC: []byte("llllllllllllllllllllllllllllllll")}
	_ = s.CreateNode(ctx, leaf, "u")
	other := &Node{TenantID: tt.ID, Kind: NodeFolder, Name: "other", NameHMAC: []byte("oooooooooooooooooooooooooooooooo")}
	_ = s.CreateNode(ctx, other, "u")

	cases := []struct {
		ancestor, node string
		want           bool
	}{
		{top.ID, top.ID, true},
		{top.ID, mid.ID, true},
		{top.ID, leaf.ID, true},
		{mid.ID, leaf.ID, true},
		{mid.ID, top.ID, false},
		{top.ID, other.ID, false},
		{"", leaf.ID, false},
		{top.ID, "", false},
		{top.ID, "does-not-exist", false},
	}
	for _, c := range cases {
		got, err := s.IsDescendantOrSelf(ctx, tt.ID, c.ancestor, c.node)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Fatalf("IsDescendantOrSelf(%q, %q) = %v, want %v", c.ancestor, c.node, got, c.want)
		}
	}
}

func TestEffectiveACL(t *testing.T) { forEachStore(t, testeffectiveACL) }

func testeffectiveACL(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantEnterprise, Name: "e"}
	_ = s.CreateTenant(ctx, tt, "owner")

	top := &Node{TenantID: tt.ID, Kind: NodeFolder, Name: "top", NameHMAC: []byte("tttttttttttttttttttttttttttttttt")}
	_ = s.CreateNode(ctx, top, "owner")
	child := &Node{TenantID: tt.ID, ParentID: sql.NullString{String: top.ID, Valid: true},
		Kind: NodeFolder, Name: "child", NameHMAC: []byte("cccccccccccccccccccccccccccccccc")}
	_ = s.CreateNode(ctx, child, "owner")

	// No override anywhere: inherit (nil).
	if roles, err := s.EffectiveACL(ctx, tt.ID, child.ID); err != nil || roles != nil {
		t.Fatalf("no-override EffectiveACL = %v %v", roles, err)
	}
	// Override on top governs the child (nearest-ancestor walk).
	if err := s.SetNodeACL(ctx, tt.ID, top.ID, []string{"owner", "admin"}); err != nil {
		t.Fatal(err)
	}
	roles, err := s.EffectiveACL(ctx, tt.ID, child.ID)
	if err != nil || len(roles) != 2 || roles[0] != "owner" || roles[1] != "admin" {
		t.Fatalf("inherited EffectiveACL = %v %v", roles, err)
	}
	// A closer override on the child wins.
	_ = s.SetNodeACL(ctx, tt.ID, child.ID, []string{"contributor"})
	roles, _ = s.EffectiveACL(ctx, tt.ID, child.ID)
	if len(roles) != 1 || roles[0] != "contributor" {
		t.Fatalf("closest-override EffectiveACL = %v", roles)
	}
	// Clearing the child override falls back to top's.
	_ = s.SetNodeACL(ctx, tt.ID, child.ID, nil)
	roles, _ = s.EffectiveACL(ctx, tt.ID, child.ID)
	if len(roles) != 2 {
		t.Fatalf("after clear, EffectiveACL = %v", roles)
	}
	// ACL override on a file is rejected.
	f := &Node{TenantID: tt.ID, ParentID: sql.NullString{String: top.ID, Valid: true},
		Kind: NodeFile, Name: "f", NameHMAC: []byte("ffffffffffffffffffffffffffffffff")}
	_ = s.CreateNode(ctx, f, "owner")
	if err := s.SetNodeACL(ctx, tt.ID, f.ID, []string{"admin"}); err == nil {
		t.Fatal("SetNodeACL on a file must fail")
	}
}
