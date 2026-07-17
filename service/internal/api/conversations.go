package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/store"
)

// --- Manifest tools (delegate to the REST handlers) ----------------------

func (s *Server) toolCreateConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Title    string `json:"title"`
		Date     string `json:"date"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p, map[string]string{"tenantID": req.TenantID},
		map[string]string{"title": req.Title, "date": req.Date}, s.handleCreateConversation)
}

func (s *Server) toolListConversations(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	s.handleListConversations(w, r2, p)
}

func (s *Server) toolGetConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID       string `json:"tenant_id"`
		ConversationID string `json:"conversation_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	r2.SetPathValue("convID", req.ConversationID)
	s.handleGetConversation(w, r2, p)
}

func (s *Server) toolAppendTurn(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID       string `json:"tenant_id"`
		ConversationID string `json:"conversation_id"`
		Turn           string `json:"turn"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p,
		map[string]string{"tenantID": req.TenantID, "convID": req.ConversationID},
		map[string]string{"turn": req.Turn}, s.handleAppendTurn)
}

func (s *Server) toolAttachToConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID       string `json:"tenant_id"`
		ConversationID string `json:"conversation_id"`
		Name           string `json:"name"`
		Mime           string `json:"mime"`
		ContentBase64  string `json:"content_base64"`
		Intent         string `json:"intent"`
		ExpiresUnix    int64  `json:"expires_unix"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p,
		map[string]string{"tenantID": req.TenantID, "convID": req.ConversationID},
		map[string]any{
			"name": req.Name, "mime": req.Mime, "content_base64": req.ContentBase64,
			"intent": req.Intent, "expires_unix": req.ExpiresUnix,
		}, s.handleAttachToConversation)
}

// StartExpirySweep runs the session-attachment GC (§8.7 intent A): every
// interval it deletes nodes whose expiry has passed, cascading their
// index rows. Stops when ctx is cancelled. Safe to call once at boot.
func (s *Server) StartExpirySweep(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := s.Store.SweepExpiredNodes(ctx, time.Now()); err != nil {
					log.Printf("expiry sweep: %v", err)
				} else if n > 0 {
					log.Printf("expiry sweep: removed %d expired attachment(s)", n)
				}
			}
		}
	}()
}

// decodeBase64Field decodes a base64 content field, tolerating both
// standard and raw (unpadded) encodings.
func decodeBase64Field(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("content_base64 is not valid base64")
	}
	return b, nil
}

// digestName is the conversation digest file (§8.7); its presence marks
// a conversation finalized.
const digestName = "digest.md"

// Conversations in Drive (§8.7). A conversation is a folder convention,
// not a new type:
//
//	Chat conversations/
//	  <date>-<slug>/
//	    conversation.jsonl   transcript (no_index, the canonical record)
//	    files/               attachments uploaded IN this conversation
//	    digest.md            distilled digest (indexed, on finalize)
//
// Everything else — sovereign encryption, GDPR export, cascade-GC,
// share-a-conversation via grants — is inherited from ordinary Drive
// files. The chat front writes the transcript over its sealed session;
// these APIs set up the directory, append turns, and list/resume.

const (
	conversationsRoot = "Chat conversations"
	transcriptName    = "conversation.jsonl"
	conversationFiles = "files"
)

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// slugify renders a conversation title into a safe directory segment.
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 60 {
		s = strings.Trim(s[:60], "-")
	}
	if s == "" {
		s = "conversation"
	}
	return s
}

// ensureFolderByName returns the child folder named `name` under parent
// (root when parentID == ""), creating it when absent. Idempotent.
func (s *Server) ensureFolderByName(ctx context.Context, p *Principal, tenantID, parentID, name string) (*store.Node, error) {
	if n, err := s.Store.ChildByName(ctx, tenantID, parentID, name); err == nil {
		if n.Kind != store.NodeFolder {
			return nil, fmt.Errorf("%q exists but is not a folder", name)
		}
		return n, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	n, _, err := s.createFolder(ctx, p, tenantID, parentID, name)
	return n, err
}

// conversationDoc is the API view of a conversation directory.
type conversationDoc struct {
	ConversationID string `json:"conversation_id"` // the <slug> folder node id
	Name           string `json:"name"`
	TranscriptID   string `json:"transcript_id"`
	FilesFolderID  string `json:"files_folder_id"`
	DigestID       string `json:"digest_id,omitempty"`
	Finalized      bool   `json:"finalized"`
	CreatedAt      string `json:"created_at,omitempty"`
}

// handleCreateConversation provisions a conversation directory and its
// empty no_index transcript. Idempotent per (title) within a day: a
// repeat returns the existing conversation rather than duplicating.
func (s *Server) handleCreateConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	var req struct {
		Title string `json:"title"`
		// Date lets the caller pin the directory prefix (the chat front
		// passes the conversation's start date); defaults handled below.
		Date string `json:"date"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !p.IsUser() || !s.canWrite(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	dir := strings.TrimSpace(req.Date)
	if dir != "" {
		dir += "-"
	}
	dir += slugify(req.Title)

	root, err := s.ensureFolderByName(r.Context(), p, tenantID, "", conversationsRoot)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	conv, err := s.ensureFolderByName(r.Context(), p, tenantID, root.ID, dir)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	filesFolder, err := s.ensureFolderByName(r.Context(), p, tenantID, conv.ID, conversationFiles)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	doc := conversationDoc{
		ConversationID: conv.ID, Name: conv.Name, FilesFolderID: filesFolder.ID,
		CreatedAt: conv.CreatedAt.UTC().Format(time.RFC3339),
	}
	// The transcript is no_index (raw transcripts poison search, §8.5).
	if tr, err := s.Store.ChildByName(r.Context(), tenantID, conv.ID, transcriptName); err == nil {
		doc.TranscriptID = tr.ID
	} else {
		n, _, uerr := s.uploadFile(r.Context(), p, tenantID, conv.ID, transcriptName,
			"application/jsonl", bytes.NewReader(nil), true /* noIndex */)
		if uerr != nil {
			httpError(w, http.StatusInternalServerError, uerr)
			return
		}
		doc.TranscriptID = n.ID
	}
	if dg, err := s.Store.ChildByName(r.Context(), tenantID, conv.ID, digestName); err == nil {
		doc.DigestID, doc.Finalized = dg.ID, true
	}
	writeJSON(w, http.StatusCreated, doc)
}

// handleAppendTurn appends one JSONL line to a conversation transcript.
// Content is content-addressed, so an append is a manifest rewrite; the
// caller batches turns as it sees fit. The line is stored verbatim (the
// caller owns the turn schema) with a trailing newline enforced.
func (s *Server) handleAppendTurn(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	convID := r.PathValue("convID")
	if !p.IsUser() || !s.canWrite(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	var req struct {
		Turn string `json:"turn"` // one JSON object, serialised
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	line := strings.TrimRight(req.Turn, "\n")
	if line == "" {
		httpError(w, http.StatusBadRequest, errors.New("turn is empty"))
		return
	}
	tr, err := s.Store.ChildByName(r.Context(), tenantID, convID, transcriptName)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	existing, err := s.readNodeBytes(r.Context(), tenantID, tr.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	buf := bytes.NewBuffer(existing)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString(line)
	buf.WriteByte('\n')
	if _, status, err := s.overwriteFile(r.Context(), p, tenantID, tr.ID, buf.Bytes()); err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"transcript_id": tr.ID, "bytes": buf.Len()})
}

// handleListConversations lists the conversation directories with their
// transcript / digest node ids and finalized flag.
func (s *Server) handleListConversations(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	root, err := s.Store.ChildByName(r.Context(), tenantID, "", conversationsRoot)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"conversations": []conversationDoc{}})
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	convs, err := s.Store.ListChildren(r.Context(), tenantID, root.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]conversationDoc, 0, len(convs))
	for _, c := range convs {
		if c.Kind != store.NodeFolder {
			continue
		}
		doc := s.conversationDocOf(r.Context(), tenantID, c)
		out = append(out, doc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": out})
}

// handleGetConversation returns a conversation's metadata plus its
// transcript text, for cross-device resume.
func (s *Server) handleGetConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	convID := r.PathValue("convID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	conv, err := s.Store.GetNode(r.Context(), tenantID, convID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	doc := s.conversationDocOf(r.Context(), tenantID, conv)
	transcript := ""
	if doc.TranscriptID != "" {
		if b, rerr := s.readNodeBytes(r.Context(), tenantID, doc.TranscriptID); rerr == nil {
			transcript = string(b)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"conversation": doc, "transcript": transcript,
	})
}

// conversationDocOf builds the view for a conversation folder node.
func (s *Server) conversationDocOf(ctx context.Context, tenantID string, conv *store.Node) conversationDoc {
	doc := conversationDoc{
		ConversationID: conv.ID, Name: conv.Name,
		CreatedAt: conv.CreatedAt.UTC().Format(time.RFC3339),
	}
	if tr, err := s.Store.ChildByName(ctx, tenantID, conv.ID, transcriptName); err == nil {
		doc.TranscriptID = tr.ID
	}
	if ff, err := s.Store.ChildByName(ctx, tenantID, conv.ID, conversationFiles); err == nil {
		doc.FilesFolderID = ff.ID
	}
	if dg, err := s.Store.ChildByName(ctx, tenantID, conv.ID, digestName); err == nil {
		doc.DigestID, doc.Finalized = dg.ID, true
	}
	return doc
}

// Attachment intents (§8.7). Intent A ("use in this chat") stores the
// file session-scoped: no_index and auto-expiring. Intent B ("add to my
// knowledge base") persists and indexes it. Both land in the
// conversation's files/ folder; the size-tiered read behaviour (full
// text vs tree navigation) is the chat client's choice, driven by the
// returned size.
const (
	intentSession   = "session"   // A
	intentKnowledge = "knowledge" // B
	// defaultSessionTTL bounds how long an intent-A attachment lingers
	// after upload; the chat front may pass expires_unix to override.
	defaultSessionTTL = 30 * 24 * time.Hour
)

func (s *Server) handleAttachToConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	convID := r.PathValue("convID")
	var req struct {
		Name          string `json:"name"`
		Mime          string `json:"mime"`
		ContentBase64 string `json:"content_base64"`
		Intent        string `json:"intent"`       // session | knowledge
		ExpiresUnix   int64  `json:"expires_unix"` // intent A override
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !p.IsUser() || !s.canWrite(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	content, err := decodeBase64Field(req.ContentBase64)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(content) > toolMaxBytes {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("attachment exceeds the 8 MiB tool cap; use the streaming upload"))
		return
	}
	intent := strings.ToLower(strings.TrimSpace(req.Intent))
	if intent == "" {
		intent = intentSession
	}
	if intent != intentSession && intent != intentKnowledge {
		httpError(w, http.StatusBadRequest, errors.New("intent must be session or knowledge"))
		return
	}
	conv, err := s.Store.GetNode(r.Context(), tenantID, convID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	filesFolder, err := s.ensureFolderByName(r.Context(), p, tenantID, conv.ID, conversationFiles)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	// Intent A stores no_index; intent B indexes (full pipeline runs).
	noIndex := intent == intentSession
	n, status, err := s.uploadFile(r.Context(), p, tenantID, filesFolder.ID, req.Name, req.Mime,
		bytes.NewReader(content), noIndex)
	if err != nil {
		httpError(w, status, err)
		return
	}
	if intent == intentSession {
		exp := time.Now().Add(defaultSessionTTL)
		if req.ExpiresUnix > 0 {
			exp = time.Unix(req.ExpiresUnix, 0)
		}
		if eerr := s.Store.SetNodeExpiry(r.Context(), tenantID, n.ID, exp); eerr != nil {
			// The file is stored; expiry is best-effort bookkeeping.
			// Surface it without failing the attach.
			writeJSON(w, http.StatusOK, map[string]any{
				"node": nodeView(n), "intent": intent,
				"warning": "attachment stored but expiry not set: " + eerr.Error(),
			})
			return
		}
	}
	// Indexing for intent B is scheduled by uploadFile (noIndex=false).
	writeJSON(w, http.StatusOK, map[string]any{"node": nodeView(n), "intent": intent})
}

// readNodeBytes decrypts a file's whole plaintext (bounded), reusing the
// indexer's internal read path (no principal — it reads only what the
// tenant stored). Used for transcript append/resume.
func (s *Server) readNodeBytes(ctx context.Context, tenantID, nodeID string) ([]byte, error) {
	// An empty file (a freshly created transcript) has no stored chunks;
	// short-circuit rather than hitting a not-found on the empty manifest.
	if n, err := s.Store.GetNode(ctx, tenantID, nodeID); err == nil && n.PlainSize == 0 {
		return nil, nil
	}
	rc, err := s.indexContent(ctx, tenantID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 8<<20))
}

// overwriteFile rewrites an existing file node's bytes in place: writes a
// fresh manifest for the same node id, updates the node's content
// pointers, and drops the old manifest. Used for transcript append and
// digest regenerate. Re-indexes unless the node is no_index.
func (s *Server) overwriteFile(ctx context.Context, p *Principal, tenantID, nodeID string, content []byte) (*store.Node, int, error) {
	n, err := s.Store.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	if !s.allowNode(ctx, p, tenantID, nodeID, grants.ScopeWrite) {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	// Write reuses the same manifest key (fileID), overwriting the blob
	// in place. The previous chunks orphan harmlessly (content-addressed,
	// possibly shared); a manifest.Delete here would wipe the manifest we
	// just wrote, since Write and Delete key on the same fileID.
	wr, err := manifest.Write(ctx, bk, dek, tenantID, n.ID, n.MimeHint, 0, bytes.NewReader(content))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	root, _ := hex.DecodeString(wr.Manifest.MerkleRoot)
	if err := s.Store.UpdateNodeContent(ctx, tenantID, n.ID, wr.WrappedCEK, root,
		wr.ManifestKey, wr.Manifest.PlainSize, p.Sub); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	n.WrappedCEK, n.ManifestRef, n.PlainSize = wr.WrappedCEK, wr.ManifestKey, wr.Manifest.PlainSize
	n.MerkleRoot = root
	// Keep the semantic index current for indexed files (digest.md).
	if _, noIndex, merr := s.Store.NodeIndexMeta(ctx, tenantID, n.ID); merr == nil && !noIndex {
		s.scheduleIndexing(ctx, n, false)
	}
	return n, http.StatusOK, nil
}
