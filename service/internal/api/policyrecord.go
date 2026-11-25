package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/drive/service/internal/vaultmek"
	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// Every tenant key's policy is recorded while Drive can still open it.
//
// A measurement approval is built from the key's recorded policy, and the
// record is read as the enclave, which works only while the running build
// is one of the key's principals. A key nobody opens between a Drive deploy
// and the next runtime roll would otherwise reach that roll unrecorded and
// need a re-stage it can no longer have. So at boot and after every
// configure Drive records every key it can, and an operator checks
// GET /v1/admin/tenant-keys/records ("all recorded") before any runtime
// roll of a host that serves Drive.

// recordPass is the outcome of one eager pass.
type recordPass struct {
	At      time.Time `json:"at"`
	Total   int       `json:"total"`
	Filled  int       `json:"filled"`
	Present int       `json:"already_present"`
	Failed  []string  `json:"failed"` // tenant ids, first 8 characters
}

var (
	recordMu   sync.Mutex // one pass at a time
	recordLast recordPass
	recordSeen sync.Mutex // guards recordLast
)

// recordAllKeyPolicies fills the policy record of every tenant key that has
// none, as the enclave, from all members byte-identical (ReadStoredPolicy).
// A key Drive cannot open (its measurement already changed) fails and is
// listed; it is never guessed.
func (s *Server) recordAllKeyPolicies(ctx context.Context) recordPass {
	pass := recordPass{At: time.Now().UTC(), Failed: []string{}}
	pr, ok := s.MEKs.(policyRecorder)
	if !ok || s.Store == nil {
		return pass
	}
	if !recordMu.TryLock() {
		return pass // a pass is already running; it records the same keys
	}
	defer recordMu.Unlock()
	holders, err := s.Store.ListTenantMekRefs(ctx)
	if err != nil {
		log.Printf("tenantkey: policy records: listing keys failed: %v", err)
		return pass
	}
	for _, h := range holders {
		ref, perr := vaultmek.ParseRef(h.MekRef)
		if perr != nil {
			continue
		}
		pass.Total++
		if len(ref.Policy) > 0 {
			pass.Present++
			continue
		}
		p, v, rerr := pr.ReadStoredPolicy(ctx, ref)
		if rerr != nil {
			pass.Failed = append(pass.Failed, short(h.TenantID))
			continue
		}
		// Write only onto the ref that was read: a re-key in between wins.
		cur, cerr := s.Store.TenantMekRef(ctx, h.TenantID)
		if cerr != nil || cur != h.MekRef {
			pass.Failed = append(pass.Failed, short(h.TenantID))
			continue
		}
		ref.Policy, ref.PolicyVersion = p, v
		if serr := s.Store.SetTenantMekRef(ctx, h.TenantID, vaultmek.RefJSON(ref)); serr != nil {
			pass.Failed = append(pass.Failed, short(h.TenantID))
			continue
		}
		pass.Filled++
	}
	log.Printf("tenantkey: policy records: %d keys, %d filled, %d already present, %d failed [%s]",
		pass.Total, pass.Filled, pass.Present, len(pass.Failed), strings.Join(pass.Failed, " "))
	recordSeen.Lock()
	recordLast = pass
	recordSeen.Unlock()
	return pass
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// recordAllSoon runs a pass in the background (boot, configure).
func (s *Server) recordAllSoon() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		s.recordAllKeyPolicies(ctx)
	}()
}

// handleTenantKeyRecords reports whether every tenant key has its policy on
// record: the check before a runtime roll of a host serving Drive. POST
// runs a pass first; GET reads the current state.
func (s *Server) handleTenantKeyRecords(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.sweepAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	if r.Method == http.MethodPost {
		s.recordAllKeyPolicies(r.Context())
	}
	holders, err := s.Store.ListTenantMekRefs(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	missing := []string{}
	recorded, v2, v1 := 0, 0, 0
	for _, h := range holders {
		ref, perr := vaultmek.ParseRef(h.MekRef)
		if perr == nil && len(ref.Policy) > 0 {
			recorded++
			var kp vsdk.KeyPolicy
			if json.Unmarshal(ref.Policy, &kp) == nil && vaultmek.NeedsBindingV2(kp) {
				v2++
			} else {
				v1++
			}
			continue
		}
		missing = append(missing, short(h.TenantID))
	}
	recordSeen.Lock()
	last := recordLast
	recordSeen.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"total": len(holders), "recorded": recorded, "missing": missing,
		"all_recorded": len(missing) == 0, "last_pass": last,
		// v1 keys take no bound approval: the operator moves them (re-sweep).
		"binding_v2": v2, "binding_v1": v1,
	})
}
