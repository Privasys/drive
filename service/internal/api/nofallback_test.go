package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/vaultmek"
)

// v2FailMEKs is a key whose binding-2 plan cannot be built: every
// PrepareTeesApprovalV2 fails. It records any v2 update so the test can
// prove nothing was sent.
type v2FailMEKs struct {
	*fakeMEKs
	prepErr error
	v2sent  int
}

func (f *v2FailMEKs) PrepareTeesApprovalV2(context.Context, vaultmek.Ref, string, string) (*vaultmek.TeesApprovalV2, error) {
	return nil, f.prepErr
}

func (f *v2FailMEKs) RefreshTeesV2(context.Context, vaultmek.Ref, *vaultmek.TeesApprovalV2, string) error {
	f.v2sent++
	return nil
}

// TestBindingV2FailureHasNoFallback proves the measurement approval fails
// closed: when the key's binding-2 plan cannot be built (its rule cannot be
// read, or the stored form does not check out), the re-arm answers 502 and
// makes no v1 attempt, so no binding-0 card can reach the holder.
func TestBindingV2FailureHasNoFallback(t *testing.T) {
	begun := 0
	saved := approvalBegin
	approvalBegin = func(context.Context, string, string, string, *vaultmek.TeesApprovalV2) (string, bool, error) {
		begun++
		return "op", true, nil
	}
	t.Cleanup(func() { approvalBegin = saved })
	for _, prepErr := range []error{
		errors.New("vaultmek: approval v2: read policy on v1:1: server error (401)"),
		errors.New("vaultmek: approval v2: v1:1: the stored form does not match its digest"),
		errors.New("vaultmek: approval v2: v2:2: the vaults return different stored forms of the new policy"),
		vaultmek.ErrPolicyNotLossless,
	} {
		mek := sha256.Sum256([]byte("vault-held-tenant-mek"))
		fake := &v2FailMEKs{fakeMEKs: &fakeMEKs{mek: mek[:], clearOnRefresh: true}, prepErr: prepErr}
		ts := newFullServer(t, func(s *Server) { s.MEKs = fake })

		_, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
		var tenant struct{ ID string }
		_ = json.Unmarshal(body, &tenant)
		resp, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth,
			`{"grant":"g","handle":"apps.privasys.org/x/data/y/mek/v1","constellation":{"endpoints":["v1:1","v2:2"],"mrenclave":"00","attestation_server":"as","threshold":2}}`)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("adopt: %d %s", resp.StatusCode, body)
		}

		fake.loadErr = errors.New("vaultmek: only 0/2 shares recovered: vault error: caller is not in policy.principals")
		resp, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth, `{"grant":"fresh-grant"}`)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("%v: want 502, got %d %s", prepErr, resp.StatusCode, body)
		}
		if strings.Contains(string(body), "approval_pending") {
			t.Fatalf("%v: a wallet approval was asked for: %s", prepErr, body)
		}
		if len(fake.refreshed) != 0 {
			t.Fatalf("%v: the v1 path ran: %v", prepErr, fake.refreshed)
		}
		if fake.v2sent != 0 {
			t.Fatalf("%v: a v2 update was sent", prepErr)
		}
		if begun != 0 {
			t.Fatalf("%v: a wallet approval was begun at the IdP", prepErr)
		}
	}
}
