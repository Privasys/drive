package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/Privasys/drive/service/internal/vaultmek"
)

// toolMaxBytes caps JSON-carried file content (both directions). Larger
// files use the streaming REST endpoints.
const toolMaxBytes = 8 << 20

// Tools returns the manifest-tool invocation surface: the plain-JSON
// POST endpoints the privasys.json tools point at. Each is a thin
// wrapper over the same internals as the REST surface, with identical
// auth (OIDC bearer or AppGrant) and access checks.
func (s *Server) Tools() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /tools/list_root", s.auth(s.toolListRoot))
	mux.Handle("POST /tools/list_folder", s.auth(s.toolListFolder))
	mux.Handle("POST /tools/create_folder", s.auth(s.toolCreateFolder))
	mux.Handle("POST /tools/write_file", s.auth(s.toolWriteFile))
	mux.Handle("POST /tools/read_file", s.auth(s.toolReadFile))
	mux.Handle("POST /tools/delete_node", s.auth(s.toolDeleteNode))
	mux.Handle("POST /tools/changes", s.auth(s.toolChanges))
	mux.Handle("POST /tools/my_drive", s.auth(s.toolMyDrive))
	mux.Handle("POST /tools/share_link_create", s.auth(s.toolShareLinkCreate))
	mux.Handle("POST /tools/redeem_link", s.auth(s.toolRedeemLink))
	mux.Handle("POST /tools/list_link_requests", s.auth(s.toolListLinkRequests))
	mux.Handle("POST /tools/decide_link_request", s.auth(s.toolDecideLinkRequest))
	mux.Handle("POST /tools/create_conversation", s.auth(s.toolCreateConversation))
	mux.Handle("POST /tools/list_conversations", s.auth(s.toolListConversations))
	mux.Handle("POST /tools/get_conversation", s.auth(s.toolGetConversation))
	mux.Handle("POST /tools/delete_conversation", s.auth(s.toolDeleteConversation))
	mux.Handle("POST /tools/append_turn", s.auth(s.toolAppendTurn))
	mux.Handle("POST /tools/attach_to_conversation", s.auth(s.toolAttachToConversation))
	mux.Handle("POST /tools/get_folder_tree", s.auth(s.toolFolderTree))
	mux.Handle("POST /tools/get_memory", s.auth(s.toolGetMemory))
	mux.Handle("POST /tools/write_memory", s.auth(s.toolWriteMemory))
	mux.Handle("POST /tools/finalize_conversation", s.auth(s.toolFinalizeConversation))
	mux.Handle("POST /tools/get_graph", s.auth(s.toolGraph))
	mux.Handle("POST /tools/enable_ai", s.auth(s.toolEnableAI))
	mux.Handle("POST /tools/disable_ai", s.auth(s.toolDisableAI))
	mux.Handle("POST /tools/list_ai_scope", s.auth(s.toolListAIScope))
	mux.Handle("POST /tools/rearm_tenant_key", s.auth(s.toolRearmTenantKey))
	mux.Handle("POST /tools/set_bucket_cred", s.auth(s.toolSetBucketCred))
	mux.Handle("POST /tools/get_bucket_cred", s.auth(s.toolGetBucketCred))
	mux.Handle("POST /tools/delete_bucket_cred", s.auth(s.toolDeleteBucketCred))
	mux.Handle("POST /tools/provision_org_mek", s.auth(s.toolProvisionOrgMEK))
	mux.Handle("POST /tools/request_recovery", s.auth(s.toolRequestRecovery))
	mux.Handle("POST /tools/approve_recovery", s.auth(s.toolApproveRecovery))
	mux.Handle("POST /tools/recovery_status", s.auth(s.toolRecoveryStatus))
	mux.Handle("POST /tools/purge_tenant", s.auth(s.toolPurgeTenant))
	mux.Handle("POST /tools/search_semantic", s.auth(s.toolSearchSemantic))
	mux.Handle("POST /tools/get_doc_tree", s.auth(s.toolDocTree))
	mux.Handle("POST /tools/read_section", s.auth(s.toolReadSection))
	return mux
}

// toolProvisionOrgMEK creates MEK_org for an escrowed instance from a
// key-creation grant bundle the org admin fetched from the control
// plane. The grant itself is the authorisation (IdP-signed, app-bound,
// owner = the org admin); the enclave generates the key, Shamir-splits
// it to the constellation and returns the ref JSON to put in the
// configure org_mek_ref field.
func (s *Server) toolProvisionOrgMEK(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.IsUser() || p.Via != viaBearer {
		httpError(w, http.StatusForbidden, errors.New("a full bearer identity is required"))
		return
	}
	if s.MEKs == nil {
		httpError(w, http.StatusNotImplemented, errors.New("vault-held keys are not available on this instance"))
		return
	}
	var b vaultmek.Bundle
	if err := readJSON(r, &b); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ref, err := s.MEKs.Provision(r.Context(), b)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"org_mek_ref": vaultmek.RefJSON(ref),
		"handle":      ref.Handle,
	})
}

// toolRequestRecovery files an escrowed-mode recovery request.
func (s *Server) toolRequestRecovery(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID   string `json:"tenant_id"`
		Reason     string `json:"reason"`
		GranteeSub string `json:"grantee_sub"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	rec, status, err := s.requestRecovery(r.Context(), p, req.TenantID, req.Reason, req.GranteeSub, req.TTLSeconds)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recovery_id":     rec.ID,
		"status":          rec.Status,
		"ceremony_handle": s.ceremonyHandle(rec.ID),
		"digest_hex":      recoveryDigest(rec.ID, rec.TenantID, rec.GranteeSub, rec.Reason),
		"expires_at":      rec.ExpiresAt,
	})
}

// toolApproveRecovery delivers one approval token; executes at quorum.
func (s *Server) toolApproveRecovery(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID      string `json:"tenant_id"`
		RecoveryID    string `json:"recovery_id"`
		ApprovalToken string `json:"approval_token"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	out, status, err := s.approveRecovery(r.Context(), p, req.TenantID, req.RecoveryID, req.ApprovalToken)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, status, out)
}

// toolRecoveryStatus reports a recovery's progress.
func (s *Server) toolRecoveryStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID   string `json:"tenant_id"`
		RecoveryID string `json:"recovery_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	out, status, err := s.recoveryStatus(r.Context(), p, req.TenantID, req.RecoveryID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, status, out)
}

// toolMyDrive gets or creates the caller's personal tenant — the tool
// form of POST /v1/me/tenant, so agents and the portal reach a drive
// without the wallet's sealed-transport session.
func (s *Server) toolMyDrive(w http.ResponseWriter, r *http.Request, p *Principal) {
	t, created, status, err := s.ensurePersonalTenant(r.Context(), p)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": t.ID, "name": t.Name, "kind": t.Kind, "created": created,
	})
}

// toolRearmTenantKey refreshes the attestation token on the caller's
// personal-tenant vault MEK ref and warms the MEK cache — the recovery
// for a 409 vault_key_stale. Token-only: provisioning a NEW tenant key
// (grant bundle) stays on the wallet's sealed REST path.
func (s *Server) toolRearmTenantKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		AttestationToken string `json:"attestation_token"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("user principals only"))
		return
	}
	if s.MEKs == nil {
		httpError(w, http.StatusNotImplemented, errors.New("vault-held tenant keys are not available on this instance"))
		return
	}
	t, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		httpError(w, http.StatusNotFound, errors.New("no personal tenant"))
		return
	}
	existing, _ := s.Store.TenantMekRef(r.Context(), t.ID)
	if existing == "" {
		httpError(w, http.StatusConflict, errors.New("tenant has no vault MEK to re-arm"))
		return
	}
	handle, status, rerr := s.rearmTenantKey(r.Context(), t.ID, existing, req.AttestationToken)
	if rerr != nil {
		httpError(w, status, rerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "loaded", "handle": handle})
}

// toolSetBucketCred stores or rotates a tenant's sealed BYO bucket
// credential. The body carries only the vault-sealed ciphertext + the
// operator key ref — never the plaintext credential.
func (s *Server) toolSetBucketCred(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		SealedBucketCred
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if status, err := s.setBucketCred(r.Context(), p, req.TenantID, req.SealedBucketCred); err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "stored", "content_type": req.ContentType})
}

// toolGetBucketCred reports whether a tenant has a BYO credential and
// its non-secret metadata.
func (s *Server) toolGetBucketCred(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	meta, status, err := s.bucketCredMeta(r.Context(), p, req.TenantID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

// toolDeleteBucketCred clears a tenant's BYO credential (falls back to
// the platform-managed bucket).
func (s *Server) toolDeleteBucketCred(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if status, err := s.clearBucketCred(r.Context(), p, req.TenantID); err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
}

func (s *Server) toolListRoot(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	kids, status, err := s.listChildren(r.Context(), p, req.TenantID, "")
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": mapNodes(kids)})
}

func (s *Server) toolListFolder(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		FolderID string `json:"folder_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.FolderID == "" {
		httpError(w, http.StatusBadRequest, errors.New("folder_id required"))
		return
	}
	kids, status, err := s.listChildren(r.Context(), p, req.TenantID, req.FolderID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": mapNodes(kids)})
}

func (s *Server) toolCreateFolder(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		ParentID string `json:"parent_id"`
		Name     string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	n, status, err := s.createFolder(r.Context(), p, req.TenantID, req.ParentID, req.Name)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, nodeView(n))
}

func (s *Server) toolWriteFile(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID      string `json:"tenant_id"`
		ParentID      string `json:"parent_id"`
		Name          string `json:"name"`
		Mime          string `json:"mime"`
		ContentBase64 string `json:"content_base64"`
		Index         *bool  `json:"index,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	content, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.New("content_base64 is not valid base64"))
		return
	}
	if len(content) > toolMaxBytes {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("content exceeds the 8 MiB tool cap; use the streaming REST upload"))
		return
	}
	n, status, err := s.uploadFile(r.Context(), p, req.TenantID, req.ParentID, req.Name, req.Mime, bytes.NewReader(content), req.Index != nil && !*req.Index)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, nodeView(n))
}

func (s *Server) toolReadFile(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		FileID   string `json:"file_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	n, rc, status, err := s.openFile(r.Context(), p, req.TenantID, req.FileID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	defer rc.Close()
	if n.PlainSize > toolMaxBytes {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("file exceeds the 8 MiB tool cap; use the streaming REST download"))
		return
	}
	content, err := io.ReadAll(io.LimitReader(rc, toolMaxBytes+1))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if len(content) > toolMaxBytes {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("file exceeds the 8 MiB tool cap; use the streaming REST download"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node":            nodeView(n),
		"content_base64":  base64.StdEncoding.EncodeToString(content),
		"merkle_root_hex": hex.EncodeToString(n.MerkleRoot),
	})
}

func (s *Server) toolDeleteNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		NodeID   string `json:"node_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if status, err := s.deleteNode(r.Context(), p, req.TenantID, req.NodeID); err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": req.NodeID})
}

func (s *Server) toolDeleteConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID       string `json:"tenant_id"`
		ConversationID string `json:"conversation_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if status, err := s.deleteConversation(r.Context(), p, req.TenantID, req.ConversationID); err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": req.ConversationID})
}

func (s *Server) toolChanges(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Since    int64  `json:"since"`
		Limit    int    `json:"limit"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	rows, status, err := s.listChanges(r.Context(), p, req.TenantID, req.Since, req.Limit)
	if err != nil {
		httpError(w, status, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{
			"seq": c.Seq, "node_id": c.NodeID, "op": c.Op,
			"actor": c.Actor, "at": c.At,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": out})
}

// legacyToolCatalog keeps the pre-manifest GET /mcp/v1/tools endpoint
// alive, serving the tool list straight from the image's privasys.json
// (single source of truth) instead of a hand-maintained catalog.
func legacyToolCatalog(manifestPath string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp/v1/tools", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(manifestPath)
		if err != nil {
			httpError(w, http.StatusNotFound, errors.New("manifest not available"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	return mux
}
