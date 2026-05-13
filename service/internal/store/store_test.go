package store

import (
	"context"
	"database/sql"
	"testing"

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

func TestTenantAndMemberLifecycle(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()

	tt := &Tenant{Kind: TenantEnterprise, Name: "Acme"}
	if err := s.CreateTenant(ctx, tt); err != nil {
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

	// User tenants reject members.
	ut := &Tenant{Kind: TenantUser, Name: "Bertrand"}
	if err := s.CreateTenant(ctx, ut); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(ctx, &Member{TenantID: ut.ID, UserSub: "u1", Role: RoleAdmin}); err == nil {
		t.Fatal("AddMember on user tenant must fail")
	}
}

func TestNodeUniqueWithinParent(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	_ = s.CreateTenant(ctx, tt)

	hmac := []byte("0123456789abcdef0123456789abcdef")
	n1 := &Node{TenantID: tt.ID, Kind: NodeFile, Name: "Report.pdf", NameHMAC: hmac, MimeHint: "application/pdf"}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	n2 := &Node{TenantID: tt.ID, Kind: NodeFile, Name: "Report.pdf", NameHMAC: hmac, MimeHint: "application/pdf"}
	if err := s.CreateNode(ctx, n2); err != ErrConflict {
		t.Fatalf("want ErrConflict got %v", err)
	}
}

func TestListChildrenAndChanges(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	_ = s.CreateTenant(ctx, tt)

	folder := &Node{TenantID: tt.ID, Kind: NodeFolder, Name: "Docs", NameHMAC: []byte("docsdocsdocsdocsdocsdocsdocsdocs")}
	if err := s.CreateNode(ctx, folder); err != nil {
		t.Fatal(err)
	}
	parent := sql.NullString{String: folder.ID, Valid: true}
	for _, name := range []string{"a.txt", "b.txt"} {
		n := &Node{TenantID: tt.ID, ParentID: parent, Kind: NodeFile, Name: name,
			NameHMAC: []byte(name + "00000000000000000000000000000000")[:32]}
		if err := s.CreateNode(ctx, n); err != nil {
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

	// Change feed should contain at least 3 creates.
	ch, err := s.ListChanges(ctx, tt.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) < 3 {
		t.Fatalf("want >=3 changes, got %d", len(ch))
	}
}

func TestDeleteNodeRecursive(t *testing.T) {
	s := newSQLiteStore(t)
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	_ = s.CreateTenant(ctx, tt)

	folder := &Node{TenantID: tt.ID, Kind: NodeFolder, Name: "F", NameHMAC: []byte("ffffffffffffffffffffffffffffffff")}
	_ = s.CreateNode(ctx, folder)
	parent := sql.NullString{String: folder.ID, Valid: true}
	child := &Node{TenantID: tt.ID, ParentID: parent, Kind: NodeFile, Name: "x",
		NameHMAC: []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")}
	_ = s.CreateNode(ctx, child)

	if err := s.DeleteNode(ctx, tt.ID, folder.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNode(ctx, tt.ID, folder.ID); err != ErrNotFound {
		t.Fatal("folder must be gone")
	}
	if _, err := s.GetNode(ctx, tt.ID, child.ID); err != ErrNotFound {
		t.Fatal("child must be gone")
	}
}
