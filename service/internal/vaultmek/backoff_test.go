package vaultmek

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The wait grows on each failure, stays within the cap with jitter, keeps
// the last failure visible, and a reset clears it.
func TestBackoffGrowsCapsAndResets(t *testing.T) {
	var b backoffs
	now := time.Unix(1_000_000, 0)
	mismatch := errors.New("vault error: caller is not in policy.principals")
	if err := b.wait("h", now); err != nil {
		t.Fatalf("no failure yet: %v", err)
	}
	var last time.Duration
	for i := 0; i < 12; i++ {
		b.fail("h", mismatch, now)
		s := b.m["h"]
		if i > 0 && s.delay < last {
			t.Fatalf("delay shrank: %v after %v", s.delay, last)
		}
		if s.delay > backoffMax {
			t.Fatalf("delay %v over the cap", s.delay)
		}
		if got := s.until.Sub(now); got < s.delay/2 || got >= s.delay*3/2 {
			t.Fatalf("jittered wait %v outside [%v, %v)", got, s.delay/2, s.delay*3/2)
		}
		last = s.delay
	}
	if last != backoffMax {
		t.Fatalf("delay did not reach the cap: %v", last)
	}
	err := b.wait("h", now)
	if !errors.Is(err, errBackingOff) || !errors.Is(err, mismatch) || !PrincipalMismatch(err) {
		t.Fatalf("waiting error hides the cause: %v", err)
	}
	if err := b.wait("h", now.Add(2*backoffMax)); err != nil {
		t.Fatalf("still waiting after the backoff: %v", err)
	}
	b.reset("h")
	if _, ok := b.m["h"]; ok {
		t.Fatal("reset kept the state")
	}
}

// A token refresh that fails is not retried until its backoff is due, so
// a refusing control plane is not hammered by every load.
func TestRefreshTokenBacksOff(t *testing.T) {
	c := New("", "")
	calls := 0
	c.SetTokenRefresher(func(context.Context) (string, int64, error) {
		calls++
		return "", 0, errors.New("vaultmek: token refresh 401 Unauthorized: app attestation failed")
	})
	for i := 0; i < 5; i++ {
		if _, err := c.refreshToken(context.Background()); err == nil {
			t.Fatal("refresh should fail")
		}
	}
	if calls != 1 {
		t.Fatalf("the control plane was asked %d times within the backoff, want 1", calls)
	}
}
