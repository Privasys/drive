package api

// D6 — search over RPC: grep and glob over a granted folder, mirroring the
// argument shape dsh's tool-fs-search uses so a Drive backend is a
// drop-in. An in-process walker over decrypted streams: no plaintext
// touches a disk, no scratch space to bound, no sidecar binary to pin.
// Go regexp is RE2 syntax (no look-around, no back-references), which
// ripgrep's default engine is a superset of; the tool description says so,
// so a model does not retry a pattern that cannot work.
//
// D8 — metering: bytes_scanned per call is compute Drive does on the
// caller's behalf; it is recorded as a "search" access event attributed
// to the caller (a grant subject or a user), which the tenant metrics
// already aggregate per subject and per node.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/store"
)

const (
	grepDefaultMaxMatches = 250
	grepDefaultLineBytes  = 2000
	grepMaxLineBytes      = 64 << 10
	// grepScanBudget caps plaintext bytes decrypted per call; above it the
	// tool refuses with a "narrow the query" error rather than scanning a
	// whole Drive on every prompt.
	grepScanBudget = 256 << 20
	globDefaultMax = 100
	// searchConcurrency bounds simultaneous searches per instance so one
	// caller cannot starve uploads by decrypting a large Drive repeatedly.
	searchConcurrency = 2
)

// walkedFile is one file under the search root with its path relative to it.
type walkedFile struct {
	node *store.Node
	rel  string
}

// walkFiles lists every file under root (depth-first, folders recursed)
// with root-relative slash paths. root "" is the tenant root.
func (s *Server) walkFiles(ctx context.Context, tenantID, root string) ([]walkedFile, error) {
	var out []walkedFile
	var rec func(parent, prefix string) error
	rec = func(parent, prefix string) error {
		kids, err := s.Store.ListChildren(ctx, tenantID, parent)
		if err != nil {
			return err
		}
		for _, n := range kids {
			rel := n.Name
			if prefix != "" {
				rel = prefix + "/" + n.Name
			}
			if n.Kind == store.NodeFolder {
				if err := rec(n.ID, rel); err != nil {
					return err
				}
				continue
			}
			out = append(out, walkedFile{node: n, rel: rel})
		}
		return nil
	}
	if err := rec(root, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// globMatch matches a slash path against a glob: '*', '?' and classes per
// path segment, '**' for any number of segments. A pattern without a '/'
// matches the basename at any depth (ripgrep's --glob convention).
func globMatch(pattern, name string) bool {
	pattern = strings.Trim(pattern, "/")
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "/") {
		ok, err := path.Match(pattern, path.Base(name))
		return err == nil && ok
	}
	return matchSegs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegs(p, n []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			for i := 0; i <= len(n); i++ {
				if matchSegs(p[1:], n[i:]) {
					return true
				}
			}
			return false
		}
		if len(n) == 0 {
			return false
		}
		ok, err := path.Match(p[0], n[0])
		if err != nil || !ok {
			return false
		}
		p, n = p[1:], n[1:]
	}
	return len(n) == 0
}

func (s *Server) acquireSearch(ctx context.Context) (func(), error) {
	s.searchSemOnce.Do(func() { s.searchSem = make(chan struct{}, searchConcurrency) })
	select {
	case s.searchSem <- struct{}{}:
		return func() { <-s.searchSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// searchScope authorises a search under root and returns the decryption
// context shared by every file it opens.
func (s *Server) searchScope(ctx context.Context, p *Principal, tenantID, root string) (dek []byte, bk backendIface, status int, err error) {
	if !s.allowNode(ctx, p, tenantID, root, grants.ScopeRead) {
		return nil, nil, http.StatusForbidden, errors.New("forbidden")
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return nil, nil, http.StatusBadGateway, err
	}
	dek, err = crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return nil, nil, http.StatusInternalServerError, err
	}
	bk, err = s.backendFor(ctx, tenantID)
	if err != nil {
		return nil, nil, http.StatusBadGateway, err
	}
	return dek, bk, http.StatusOK, nil
}

type grepMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// toolGrep — {root, pattern, include?, max_matches?, max_line_bytes?} →
// {matches:[{path,line,text}], truncated, bytes_scanned}.
func (s *Server) toolGrep(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID     string `json:"tenant_id"`
		Root         string `json:"root"`
		Pattern      string `json:"pattern"`
		Include      string `json:"include"`
		MaxMatches   int    `json:"max_matches"`
		MaxLineBytes int    `json:"max_line_bytes"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Pattern == "" {
		httpError(w, http.StatusBadRequest, errors.New("pattern required"))
		return
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.New("pattern is not valid RE2: "+err.Error()))
		return
	}
	if req.MaxMatches <= 0 {
		req.MaxMatches = grepDefaultMaxMatches
	}
	if req.MaxLineBytes <= 0 {
		req.MaxLineBytes = grepDefaultLineBytes
	}
	if req.MaxLineBytes > grepMaxLineBytes {
		req.MaxLineBytes = grepMaxLineBytes
	}
	ctx := r.Context()
	dek, bk, status, err := s.searchScope(ctx, p, req.TenantID, req.Root)
	if err != nil {
		httpError(w, status, err)
		return
	}
	release, err := s.acquireSearch(ctx)
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, err)
		return
	}
	defer release()

	files, err := s.walkFiles(ctx, req.TenantID, req.Root)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}
	start := time.Now()
	var (
		matches   []grepMatch
		scanned   int64
		truncated bool
	)
	defer func() { s.recordAccess(p, req.TenantID, req.Root, "search", scanned, time.Since(start)) }()
	for _, f := range files {
		if req.Include != "" && !globMatch(req.Include, f.rel) {
			continue
		}
		if scanned+f.node.PlainSize > grepScanBudget {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"error":         "SEARCH_RAW_OUTPUT_OVERFLOW",
				"message":       "the search would scan more than the per-call budget; narrow the query with include or a smaller root",
				"bytes_scanned": scanned,
				"budget_bytes":  grepScanBudget,
			})
			return
		}
		_, rc, rerr := manifest.Read(ctx, bk, dek, req.TenantID, f.node.ID, f.node.WrappedCEK)
		if rerr != nil {
			continue // unreadable file: skip rather than fail the search
		}
		n, hit := grepStream(rc, re, f.rel, req.MaxLineBytes, req.MaxMatches-len(matches), &matches)
		rc.Close()
		scanned += n
		if hit && len(matches) >= req.MaxMatches {
			truncated = true
			break
		}
	}
	if matches == nil {
		matches = []grepMatch{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matches": matches, "truncated": truncated, "bytes_scanned": scanned,
	})
}

// grepStream scans one decrypted stream line by line, appending up to
// budget matches. Lines longer than maxLine are matched on their first
// maxLine bytes and reported truncated. Returns bytes read and whether the
// budget was exhausted.
func grepStream(rc io.Reader, re *regexp.Regexp, rel string, maxLine, budget int, out *[]grepMatch) (int64, bool) {
	var (
		read    int64
		lineNo  = 1
		buf     = make([]byte, 32<<10)
		line    []byte
		overLen bool
	)
	flush := func() bool {
		if re.Match(line) {
			text := string(line)
			if overLen {
				text += "…"
			}
			*out = append(*out, grepMatch{Path: rel, Line: lineNo, Text: text})
			budget--
		}
		lineNo++
		line = line[:0]
		overLen = false
		return budget <= 0
	}
	for {
		n, err := rc.Read(buf)
		read += int64(n)
		chunk := buf[:n]
		for len(chunk) > 0 {
			i := indexByte(chunk, '\n')
			if i < 0 {
				if len(line) < maxLine {
					take := maxLine - len(line)
					if take > len(chunk) {
						take = len(chunk)
					}
					line = append(line, chunk[:take]...)
					if take < len(chunk) {
						overLen = true
					}
				} else {
					overLen = true
				}
				break
			}
			seg := chunk[:i]
			if len(line) < maxLine {
				take := maxLine - len(line)
				if take > len(seg) {
					take = len(seg)
				}
				line = append(line, seg[:take]...)
				if take < len(seg) {
					overLen = true
				}
			} else if len(seg) > 0 {
				overLen = true
			}
			chunk = chunk[i+1:]
			if flush() {
				return read, true
			}
		}
		if err != nil {
			if len(line) > 0 {
				if flush() {
					return read, true
				}
			}
			return read, false
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// toolGlob — {root, pattern, max_results?} → {paths, truncated},
// modification-time ordered (newest first).
func (s *Server) toolGlob(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID   string `json:"tenant_id"`
		Root       string `json:"root"`
		Pattern    string `json:"pattern"`
		MaxResults int    `json:"max_results"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Pattern == "" {
		httpError(w, http.StatusBadRequest, errors.New("pattern required"))
		return
	}
	if req.MaxResults <= 0 {
		req.MaxResults = globDefaultMax
	}
	ctx := r.Context()
	if !s.allowNode(ctx, p, req.TenantID, req.Root, grants.ScopeRead) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	files, err := s.walkFiles(ctx, req.TenantID, req.Root)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}
	var hits []walkedFile
	for _, f := range files {
		if globMatch(req.Pattern, f.rel) {
			hits = append(hits, f)
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].node.UpdatedAt.After(hits[j].node.UpdatedAt) })
	truncated := false
	if len(hits) > req.MaxResults {
		hits = hits[:req.MaxResults]
		truncated = true
	}
	paths := make([]string, 0, len(hits))
	for _, h := range hits {
		paths = append(paths, h.rel)
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": paths, "truncated": truncated})
}

// backendIface is the object-store contract the search needs (kept local
// so this file does not import objectstore just for the type name).
type backendIface = interface {
	GetChunk(ctx context.Context, key string) (io.ReadCloser, error)
	PutChunk(ctx context.Context, key string, body io.Reader, size int64) error
	Head(ctx context.Context, key string) (int64, error)
	Delete(ctx context.Context, key string) error
	Name() string
}

var _ = sync.Mutex{}
