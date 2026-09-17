package store

import (
	"bytes"
	"context"
	"testing"
)

// TestSwitchTenantKeysRewrapsRetainedRevisions is the regression guard for the
// gap a fleet-wide MEK switch would otherwise inflict: file_versions carries
// its OWN wrapped CEK per retained revision, so a sweep that touches only
// `nodes` leaves every previous version of every file undecryptable under the
// new key. The fake wrap here is a reversible transform, so "re-wrapped"
// is checked by value, not just by the row being written.
func TestSwitchTenantKeysRewrapsRetainedRevisions(t *testing.T) {
	forEachStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		tenant := &Tenant{ID: "t1", Kind: TenantUser, Name: "Personal"}
		if err := s.CreateTenant(ctx, tenant, "owner-sub"); err != nil {
			t.Fatal(err)
		}

		// A file with content, plus two retained revisions of it.
		file := &Node{
			ID: "n1", TenantID: tenant.ID, Kind: NodeFile, Name: "notes.txt",
			NameHMAC: []byte("old-hmac:notes.txt"), WrappedCEK: []byte("old:cek-current"),
		}
		if err := s.CreateNode(ctx, file, "owner-sub"); err != nil {
			t.Fatal(err)
		}
		for _, rev := range []int64{1, 2} {
			v := &FileVersion{
				TenantID: tenant.ID, NodeID: file.ID, Rev: rev,
				ObjectID:   "n1.v" + string(rune('0'+rev)),
				WrappedCEK: []byte("old:cek-rev"),
			}
			if err := s.InsertFileVersion(ctx, v); err != nil {
				t.Fatal(err)
			}
		}
		// A folder (no CEK) must survive the sweep untouched but re-HMACed.
		folder := &Node{
			ID: "n2", TenantID: tenant.ID, Kind: NodeFolder, Name: "docs",
			NameHMAC: []byte("old-hmac:docs"),
		}
		if err := s.CreateNode(ctx, folder, "owner-sub"); err != nil {
			t.Fatal(err)
		}

		rewrap := func(wrapped []byte) ([]byte, error) {
			if !bytes.HasPrefix(wrapped, []byte("old:")) {
				t.Fatalf("re-wrap saw something not wrapped under the old key: %q", wrapped)
			}
			return append([]byte("new:"), wrapped[len("old:"):]...), nil
		}
		counts, err := s.SwitchTenantKeys(ctx, tenant.ID, `{"handle":"h/v2"}`, TenantKeySwitch{
			Node: func(n *Node) error {
				n.NameHMAC = []byte("new-hmac:" + n.Name)
				if len(n.WrappedCEK) == 0 {
					return nil
				}
				w, werr := rewrap(n.WrappedCEK)
				if werr != nil {
					return werr
				}
				n.WrappedCEK = w
				return nil
			},
			CEK: rewrap,
		})
		if err != nil {
			t.Fatalf("switch: %v", err)
		}
		if counts.Nodes != 2 || counts.Versions != 2 {
			t.Fatalf("counts = %+v, want 2 nodes and 2 versions", counts)
		}

		// Every retained revision must now be wrapped under the new key.
		versions, err := s.ListFileVersions(ctx, tenant.ID, file.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(versions) != 2 {
			t.Fatalf("got %d versions, want 2", len(versions))
		}
		for _, v := range versions {
			if !bytes.Equal(v.WrappedCEK, []byte("new:cek-rev")) {
				t.Errorf("revision %d still wrapped under the old key: %q", v.Rev, v.WrappedCEK)
			}
		}

		got, err := s.GetNode(ctx, tenant.ID, file.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.WrappedCEK, []byte("new:cek-current")) {
			t.Errorf("current content not re-wrapped: %q", got.WrappedCEK)
		}
		if !bytes.Equal(got.NameHMAC, []byte("new-hmac:notes.txt")) {
			t.Errorf("name HMAC not recomputed: %q", got.NameHMAC)
		}
		ref, err := s.TenantMekRef(ctx, tenant.ID)
		if err != nil || ref != `{"handle":"h/v2"}` {
			t.Errorf("mek_ref = %q, %v", ref, err)
		}
	})
}

// TestSwitchTenantKeysAtomicOnRevisionFailure proves the tenant is left whole
// on the OLD key when a revision fails to re-wrap: the mek_ref must not move,
// or the tenant would point at a key that cannot open its own rows.
func TestSwitchTenantKeysAtomicOnRevisionFailure(t *testing.T) {
	forEachStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		tenant := &Tenant{ID: "t1", Kind: TenantUser, Name: "Personal"}
		if err := s.CreateTenant(ctx, tenant, "owner-sub"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetTenantMekRef(ctx, tenant.ID, `{"handle":"h/v1"}`); err != nil {
			t.Fatal(err)
		}
		file := &Node{
			ID: "n1", TenantID: tenant.ID, Kind: NodeFile, Name: "notes.txt",
			NameHMAC: []byte("old-hmac:notes.txt"), WrappedCEK: []byte("old:cek-current"),
		}
		if err := s.CreateNode(ctx, file, "owner-sub"); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertFileVersion(ctx, &FileVersion{
			TenantID: tenant.ID, NodeID: file.ID, Rev: 1,
			ObjectID: "n1.v1", WrappedCEK: []byte("undecryptable"),
		}); err != nil {
			t.Fatal(err)
		}

		_, err := s.SwitchTenantKeys(ctx, tenant.ID, `{"handle":"h/v2"}`, TenantKeySwitch{
			Node: func(n *Node) error {
				n.NameHMAC = []byte("new-hmac:" + n.Name)
				if len(n.WrappedCEK) > 0 {
					n.WrappedCEK = []byte("new:cek-current")
				}
				return nil
			},
			CEK: func(wrapped []byte) ([]byte, error) {
				if bytes.Equal(wrapped, []byte("undecryptable")) {
					return nil, errFakeUnwrap
				}
				return wrapped, nil
			},
		})
		if err == nil {
			t.Fatal("expected the switch to fail on the undecryptable revision")
		}

		ref, rerr := s.TenantMekRef(ctx, tenant.ID)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if ref != `{"handle":"h/v1"}` {
			t.Errorf("mek_ref moved despite a failed sweep: %q", ref)
		}
		got, gerr := s.GetNode(ctx, tenant.ID, file.ID)
		if gerr != nil {
			t.Fatal(gerr)
		}
		if !bytes.Equal(got.WrappedCEK, []byte("old:cek-current")) {
			t.Errorf("node was left re-wrapped after a rolled-back sweep: %q", got.WrappedCEK)
		}
	})
}

var errFakeUnwrap = errFake("unwrap failed")

type errFake string

func (e errFake) Error() string { return string(e) }
