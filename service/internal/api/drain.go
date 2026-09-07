package api

// drain_local_objects — the owner action that moves an instance off the
// local sealed-volume object store onto its configured bucket (point 1 of
// plans/drive-as-remote-disk.md), and the primitive a later cloud move
// (bucket to bucket) reuses.
//
// Sequence for an instance with existing data: configure object_backend
// (new writes go to the bucket) → run this action (every object still on
// the volume is copied to the bucket, key for key, opaque ciphertext) →
// nothing on the volume is referenced any more. Idempotent: an object the
// bucket already holds is skipped, so re-running after a partial copy or
// after a write that raced the switch is safe. Nothing is deleted from the
// volume here; that is a separate, explicit act.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Privasys/drive/service/internal/objectstore"
)

type drainStatus struct {
	mu       sync.Mutex
	State    string    `json:"state"` // idle | running | done | failed
	Copied   int64     `json:"copied"`
	Skipped  int64     `json:"skipped"`
	Failed   int64     `json:"failed"`
	Bytes    int64     `json:"bytes"`
	Message  string    `json:"message,omitempty"`
	Started  time.Time `json:"started,omitempty"`
	Finished time.Time `json:"finished,omitempty"`
}

func (s *Server) drainState() *drainStatus {
	s.drainOnce.Do(func() { s.drain = &drainStatus{State: "idle"} })
	return s.drain
}

// handleDrainLocalObjects starts the copy (owner-gated like configure).
func (s *Server) handleDrainLocalObjects(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.configureAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	target := s.instanceBackend()
	if _, isLocal := target.(*objectstore.LocalBackend); isLocal {
		httpError(w, http.StatusConflict, errors.New("instance object backend is still local; configure object_backend to a bucket first"))
		return
	}
	src, err := objectstore.NewLocal(filepath.Join(s.StateDir, "objects"))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	st := s.drainState()
	st.mu.Lock()
	if st.State == "running" {
		st.mu.Unlock()
		writeJSON(w, http.StatusAccepted, s.drainSnapshot())
		return
	}
	// Reset field by field: assigning a struct literal over *st would also
	// overwrite the mutex we are holding (fatal "unlock of unlocked mutex").
	st.State, st.Copied, st.Skipped, st.Failed, st.Bytes = "running", 0, 0, 0, 0
	st.Message, st.Started, st.Finished = "", time.Now().UTC(), time.Time{}
	st.mu.Unlock()

	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		s.runDrain(context.Background(), src, target)
	}()
	writeJSON(w, http.StatusAccepted, s.drainSnapshot())
}

func (s *Server) runDrain(ctx context.Context, src *objectstore.LocalBackend, dst objectstore.Backend) {
	st := s.drainState()
	err := src.Walk(ctx, func(key string, size int64) error {
		if _, herr := dst.Head(ctx, key); herr == nil {
			st.mu.Lock()
			st.Skipped++
			st.mu.Unlock()
			return nil
		}
		rc, oerr := src.GetChunk(ctx, key)
		if oerr != nil {
			st.mu.Lock()
			st.Failed++
			st.Message = key + ": " + oerr.Error()
			st.mu.Unlock()
			return nil
		}
		perr := dst.PutChunk(ctx, key, rc, size)
		rc.Close()
		st.mu.Lock()
		if perr != nil {
			st.Failed++
			st.Message = key + ": " + perr.Error()
		} else {
			st.Copied++
			st.Bytes += size
		}
		st.mu.Unlock()
		return nil
	})
	st.mu.Lock()
	defer st.mu.Unlock()
	st.Finished = time.Now().UTC()
	switch {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		st.State = "failed"
		st.Message = err.Error()
	case st.Failed > 0:
		st.State = "failed"
	default:
		st.State = "done"
	}
}

func (s *Server) drainSnapshot() map[string]any {
	st := s.drainState()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := map[string]any{
		"state": st.State, "copied": st.Copied, "skipped": st.Skipped,
		"failed": st.Failed, "bytes": st.Bytes,
	}
	if st.Message != "" {
		out["message"] = st.Message
	}
	if !st.Started.IsZero() {
		out["started"] = st.Started.Format(time.RFC3339)
	}
	if !st.Finished.IsZero() {
		out["finished"] = st.Finished.Format(time.RFC3339)
	}
	return out
}

// handleDrainStatus reports progress; the manifest's progress contract
// polls it to a terminal state (done | failed).
func (s *Server) handleDrainStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.configureAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, s.drainSnapshot())
}
