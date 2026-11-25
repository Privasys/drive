package vaultmek

import (
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// Backoff keeps a failing key or a failing token refresh from turning into
// a tight loop against the vaults and the control plane (a key the running
// build can no longer open is retried by every read and the indexer). Each
// failure doubles the wait, from backoffMin up to backoffMax, with jitter
// so many callers do not retry in step; a success resets it.

var (
	backoffMin = 5 * time.Second
	backoffMax = 10 * time.Minute
)

// errBackingOff wraps the last failure while a retry is not yet due.
var errBackingOff = errors.New("vaultmek: backing off after a recent failure")

type backoffState struct {
	err   error
	delay time.Duration
	until time.Time
}

// backoffs tracks failures by key (a handle, or "" for the token refresh).
type backoffs struct {
	mu sync.Mutex
	m  map[string]*backoffState
}

// wait returns the last failure while a retry is not yet due, else nil.
func (b *backoffs) wait(key string, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.m[key]; ok && now.Before(s.until) {
		return &backoffErr{last: s.err, until: s.until}
	}
	return nil
}

// fail records a failure and schedules the next try.
func (b *backoffs) fail(key string, err error, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]*backoffState{}
	}
	s := b.m[key]
	if s == nil {
		s = &backoffState{}
		b.m[key] = s
	}
	s.err = err
	switch {
	case s.delay <= 0:
		s.delay = backoffMin
	case s.delay*2 > backoffMax:
		s.delay = backoffMax
	default:
		s.delay *= 2
	}
	// Jitter in [0.5, 1.5) of the delay.
	j := time.Duration(float64(s.delay) * (0.5 + rand.Float64()))
	s.until = now.Add(j)
}

// reset forgets a key's failures (a success, or a change that makes a new
// try worthwhile at once, such as an approved measurement).
func (b *backoffs) reset(key string) {
	b.mu.Lock()
	delete(b.m, key)
	b.mu.Unlock()
}

type backoffErr struct {
	last  error
	until time.Time
}

func (e *backoffErr) Error() string {
	return errBackingOff.Error() + " (next try after " + e.until.UTC().Format(time.RFC3339) + "): " + e.last.Error()
}

// Unwrap keeps the last failure visible to errors.Is / PrincipalMismatch
// callers (a re-arm still recognises a measurement change).
func (e *backoffErr) Unwrap() []error { return []error{errBackingOff, e.last} }
