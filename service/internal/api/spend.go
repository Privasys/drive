package api

// Spend tokens (acting-subject plan v2).
//
// Inbound: the runtime verifies a caller app's spend token and per-request
// proof and asserts the PAYING USER as X-Privasys-Peer-Payer (stripped from
// every request it did not verify). On the assistant surface that user is
// the acting user, so a harness carrying a spend token needs no
// on-behalf-of header; the header stays accepted during the dual run.
//
// Outbound: a query-time embedding (a user's search, or the assistant's
// scoped search) is inference the USER pays for. Drive fetches a spend
// token for that user from the identity provider (the user allowed Drive
// to spend at sign-in) and decorates the fleet call with it. Indexing has
// no acting user and stays the Drive owner's cost, as before.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"enclave-os-mini/clients/go/spend"
)

// payerHeader is the runtime-asserted paying user (spend.HeaderPayer).
const payerHeader = spend.HeaderPayer

// spendSubjectKey carries the acting user for the outbound decoration.
type spendSubjectKey struct{}

// withSpendSubject marks ctx with the user whose credits a fleet call made
// under it should spend.
func withSpendSubject(ctx context.Context, sub string) context.Context {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return ctx
	}
	return context.WithValue(ctx, spendSubjectKey{}, sub)
}

func spendSubjectFrom(ctx context.Context) string {
	s, _ := ctx.Value(spendSubjectKey{}).(string)
	return s
}

var (
	spendOnce      sync.Once
	spendSignerVal *spend.Signer
	spendNoConsent sync.Map // sub → time.Time
)

// spendSigner returns the process-wide signer, armed from the runtime's
// environment (PRIVASYS_APP_ID, PRIVASYS_ISSUER) on first use; nil off
// platform.
func spendSigner() *spend.Signer {
	spendOnce.Do(func() {
		appID := os.Getenv("PRIVASYS_APP_ID")
		if appID == "" {
			return
		}
		s, err := spend.NewSigner(appID, spend.IssuerFromEnv(os.Getenv),
			spend.WithHTTPClient(&http.Client{Timeout: 15 * time.Second}))
		if err != nil {
			log.Printf("spend: signer disabled: %v", err)
			return
		}
		spendSignerVal = s
		log.Printf("spend: signer armed for app %s (key %s)", s.AppID(), s.Kid())
	})
	return spendSignerVal
}

// spendDecorate is the FleetEmbedder hook: name the acting user, when the
// context carries one and they allowed Drive to spend.
func spendDecorate(ctx context.Context, req *http.Request) {
	sub := spendSubjectFrom(ctx)
	s := spendSigner()
	if s == nil || sub == "" {
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := s.Decorate(dctx, req, sub)
	if err == nil {
		return
	}
	if errors.Is(err, spend.ErrNoConsent) {
		if last, ok := spendNoConsent.Load(sub); !ok || time.Since(last.(time.Time)) > 10*time.Minute {
			spendNoConsent.Store(sub, time.Now())
			log.Printf("spend: user %.8s… has not allowed Drive to spend their credits; fleet call goes out as Drive", sub)
		}
		return
	}
	log.Printf("spend: token for %.8s… unavailable (%v); fleet call goes out as Drive", sub, err)
}

// handleSpendKeys serves the app's spend-key JWKS at spend.WellKnownPath.
func handleSpendKeys(w http.ResponseWriter, r *http.Request) {
	s := spendSigner()
	if s == nil {
		http.NotFound(w, r)
		return
	}
	s.ServeJWKS(w, r)
}
