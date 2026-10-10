package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The holder approves a Drive upgrade for their key, in their wallet.
//
// A holder's vault key is owned by their account, and after a Drive upgrade
// the vault accepts the new measurement only against a token whose subject
// is that account. While Drive's subjects were account ids, the token the
// wallet called Drive with was such a token and the approval went through
// silently. Once Drive has its own per-app subjects it is not, and the vault
// refuses it.
//
// Drive then asks the IdP for a vault approval of the key's policy update
// (operation "policy-update", the card the wallet already shows), started
// with the token it was handed: the IdP resolves that token's subject to
// the account and pushes the holder's wallet. The holder taps; the IdP
// issues an approval token whose subject is the account; Drive uses it for
// the measurement approval. No wallet change, no vault change.

// ownerApprovalWait is how long a re-arm holds the call open for the tap.
var ownerApprovalWait = 25 * time.Second

// pendingOwnerApproval is a wallet approval Drive is waiting on, per tenant.
type pendingOwnerApproval struct {
	vaultOp string
	expires time.Time
}

var pendingOwnerApprovals sync.Map // tenantID → *pendingOwnerApproval

// errApprovalPending means the holder has a request on their phone.
var errApprovalPending = errors.New("owner_approval_pending: approve the Privasys Drive key update in your Privasys Wallet, then open Drive again")

// The IdP round trips, swappable in tests.
var (
	approvalBegin   = idpApprovalBegin
	approvalCollect = idpApprovalCollect
)

// idpApprovalBegin starts a policy-update approval for handle, authenticated
// by bearer (any token of the holder's the IdP issued). It returns the
// vault_op to collect with, and whether a wallet can receive the request.
func idpApprovalBegin(ctx context.Context, bearer, handle string) (string, bool, error) {
	body, _ := json.Marshal(map[string]any{
		"operation":   "policy-update",
		"handle":      handle,
		"ttl_seconds": 300,
		"context": map[string]any{
			"app_name": "Privasys Drive",
			"key_type": "Your Drive key",
			"source":   "Privasys Drive was updated; approve the new version to keep opening your files.",
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, idpBase()+"/fido2/vault-approval/begin", bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	var out struct {
		VaultOp        string `json:"vault_op"`
		PushRegistered bool   `json:"push_registered"`
		Error          string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK || out.VaultOp == "" {
		return "", false, fmt.Errorf("vault approval: identity provider answered %d: %s", resp.StatusCode, out.Error)
	}
	return out.VaultOp, out.PushRegistered, nil
}

// idpApprovalCollect returns the approval token once the holder approved,
// "" while still pending.
func idpApprovalCollect(ctx context.Context, bearer, vaultOp string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		idpBase()+"/fido2/vault-approval/token?challenge="+url.QueryEscape(vaultOp), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return "", nil
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil || out.AccessToken == "" {
		return "", fmt.Errorf("vault approval: identity provider answered %d", resp.StatusCode)
	}
	return out.AccessToken, nil
}

// ownerApprovalToken gets a token naming the key's owner by asking the
// holder's wallet, starting or resuming the request for this tenant. It
// returns errApprovalPending while the holder has not tapped yet.
func (s *Server) ownerApprovalToken(ctx context.Context, tenantID, bearer, handle string) (string, error) {
	var vaultOp string
	if v, ok := pendingOwnerApprovals.Load(tenantID); ok && time.Now().Before(v.(*pendingOwnerApproval).expires) {
		vaultOp = v.(*pendingOwnerApproval).vaultOp
	} else {
		op, push, err := approvalBegin(ctx, bearer, handle)
		if err != nil {
			return "", err
		}
		if !push {
			return "", errors.New("measurement_approval_required: your wallet cannot receive the approval request; open the Privasys Wallet to approve the Drive update")
		}
		vaultOp = op
		pendingOwnerApprovals.Store(tenantID, &pendingOwnerApproval{vaultOp: op, expires: time.Now().Add(5 * time.Minute)})
		log.Printf("tenant-key: the vault refused the token for tenant %.8s…; asked the holder's wallet to approve the upgrade", tenantID)
	}
	deadline := time.Now().Add(ownerApprovalWait)
	for {
		tok, err := approvalCollect(ctx, bearer, vaultOp)
		if err != nil {
			pendingOwnerApprovals.Delete(tenantID)
			return "", err
		}
		if tok != "" {
			pendingOwnerApprovals.Delete(tenantID)
			log.Printf("tenant-key: the holder approved the upgrade for tenant %.8s… in their wallet", tenantID)
			return tok, nil
		}
		if time.Now().Add(2 * time.Second).After(deadline) {
			return "", errApprovalPending
		}
		select {
		case <-ctx.Done():
			return "", errApprovalPending
		case <-time.After(2 * time.Second):
		}
	}
}

// vaultUnreachable tells a transport failure (worth a retry, not a push to
// the holder's phone) from the vault refusing the request.
func vaultUnreachable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"dial", "connection refused", "connection reset", "timeout", "deadline exceeded", "no route", "eof"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
