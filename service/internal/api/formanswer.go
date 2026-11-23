package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/store"
)

// A sharer answers a share request inside the wallet: the wallet posts the
// IdP's answer token here, and that token is the only authority. It is the
// holder's biometric act, signed by the IdP, bound to this app, to the
// exact form Drive sent and to the action they chose, valid five minutes.
// No Drive sign-in comes with it, so everything is checked on the token.

// FormAnswerType is the JOSE typ of the IdP's answer token.
const FormAnswerType = "app-form-answer+jwt"

// FormAnswerAudience is the audience the IdP gives an answer to a form this
// app sent: "app-form:" and the dashed app id.
func FormAnswerAudience(appID string) string {
	return "app-form:" + dashedAppID(appID)
}

var errRequestDecided = errors.New("request already decided")

type formAnswerRequest struct {
	FormID string `json:"form_id"`
	Action string `json:"action"`
	Answer string `json:"answer"`
}

func (s *Server) handleFormAnswer(w http.ResponseWriter, r *http.Request) {
	if !s.appMessages() || s.FormAnswers == nil {
		httpError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	var req formAnswerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil ||
		req.FormID == "" || req.Answer == "" {
		httpError(w, http.StatusBadRequest, errors.New("form_id, action and answer are required"))
		return
	}
	id, err := s.FormAnswers.Verify(r.Context(), req.Answer)
	if err != nil {
		httpError(w, http.StatusUnauthorized, errors.New("the answer is not valid"))
		return
	}
	claim := func(k string) string { v, _ := id.Claims[k].(string); return v }
	if claim("form_id") != req.FormID || claim("action") != req.Action {
		httpError(w, http.StatusForbidden, errors.New("the answer is for another form or action"))
		return
	}
	decision := map[string]string{"approve": "approve", "deny": "deny"}[req.Action]
	if decision == "" {
		httpError(w, http.StatusBadRequest, errors.New("the form offered approve or deny"))
		return
	}
	lr, err := s.Store.LinkRequestByID(r.Context(), req.FormID)
	if err != nil || lr.FormDigest == "" {
		httpError(w, http.StatusNotFound, errors.New("no such request"))
		return
	}
	// The form the holder saw is the form Drive sent, and they are the
	// person it was sent to.
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(claim("form_digest"))), []byte(lr.FormDigest)) != 1 ||
		id.Sub != lr.FormSub {
		httpError(w, http.StatusForbidden, errors.New("the answer does not match the request"))
		return
	}
	if lr.Status != "pending" {
		httpError(w, http.StatusConflict, errRequestDecided)
		return
	}
	// Still allowed to share in that drive (they may have left it since).
	if !s.canShare(r.Context(), lr.TenantID, id.Sub) || !s.aclAllows(r.Context(), lr.TenantID, lr.NodeID, id.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	status, grantID, err := s.decideLinkRequest(r.Context(), lr, decision, id.Sub)
	if errors.Is(err, errRequestDecided) {
		httpError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := map[string]any{"status": status}
	if grantID != "" {
		out["grant_id"] = grantID
	}
	writeJSON(w, http.StatusOK, out)
}

// decideLinkRequest records an approve or deny, once: decisions are taken
// one at a time and the request re-read under the lock, so a second answer
// (the wallet and Drive's own screen, or a replay) cannot mint twice.
func (s *Server) decideLinkRequest(ctx context.Context, lr *store.LinkRequest, decision, by string) (status, grantID string, err error) {
	s.decideMu.Lock()
	defer s.decideMu.Unlock()
	cur, err := s.Store.GetLinkRequest(ctx, lr.TenantID, lr.ID)
	if err != nil {
		return "", "", err
	}
	if cur.Status != "pending" {
		return "", "", errRequestDecided
	}
	if decision == "deny" {
		if err := s.Store.DecideLinkRequest(ctx, cur.TenantID, cur.ID, "denied", "", by); err != nil {
			return "", "", err
		}
		s.notifyShareDecision(ctx, cur, "denied")
		return "denied", "", nil
	}
	g, err := s.mintSubjectGrant(ctx, cur.TenantID, cur.NodeID, cur.RequesterSub, splitScopeStrings(cur.Scope), cur.LinkID)
	if err != nil {
		return "", "", err
	}
	if err := s.Store.DecideLinkRequest(ctx, cur.TenantID, cur.ID, "approved", g.ID, by); err != nil {
		return "", "", err
	}
	s.notifyShareDecision(ctx, cur, "approved")
	return "approved", g.ID, nil
}

// handleFormOpen lets the wallet confirm, over its attested channel, that
// Drive itself sent the form it is about to show and that the form is still
// waiting: 200 only for an open request whose stored digest is the one
// asked about, and the same bare 404 for anything else, so the answer never
// says whether an id exists.
func (s *Server) handleFormOpen(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	digest := strings.ToLower(r.URL.Query().Get("digest"))
	notFound := func() { http.Error(w, "not found", http.StatusNotFound) }
	if !s.appMessages() || id == "" || len(digest) != 64 {
		notFound()
		return
	}
	lr, err := s.Store.LinkRequestByID(r.Context(), id)
	if err != nil || lr.Status != "pending" || lr.FormDigest == "" ||
		subtle.ConstantTimeCompare([]byte(digest), []byte(lr.FormDigest)) != 1 {
		notFound()
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": true, "form_id": lr.ID, "form_digest": lr.FormDigest})
}
