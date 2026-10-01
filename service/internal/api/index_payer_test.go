package api

import (
	"context"
	"errors"
	"testing"

	"enclave-os-mini/clients/go/spend"

	"github.com/Privasys/drive/service/internal/store"
)

func TestPickPayer(t *testing.T) {
	ctx := context.Background()
	members := []*store.Member{
		{UserSub: "alice", Role: store.RoleReader},
		{UserSub: "bob", Role: store.RoleOwner},
		{UserSub: "carol", Role: store.RoleOwner},
	}
	consent := func(allowed ...string) func(context.Context, string) error {
		return func(_ context.Context, sub string) error {
			for _, a := range allowed {
				if a == sub {
					return nil
				}
			}
			return spend.ErrNoConsent
		}
	}

	// Only an owner pays, never a reader, however willing.
	if got, err := pickPayer(ctx, members, consent("alice", "bob")); err != nil || got != "bob" {
		t.Fatalf("want bob, got %q %v", got, err)
	}
	// An owner who has not allowed Drive to spend is passed over.
	if got, err := pickPayer(ctx, members, consent("carol")); err != nil || got != "carol" {
		t.Fatalf("want carol, got %q %v", got, err)
	}
	// Nobody allowed: the files wait, for that stated reason.
	if _, err := pickPayer(ctx, members, consent()); !errors.Is(err, errNoIndexPayer) {
		t.Fatalf("want errNoIndexPayer, got %v", err)
	}
	// A transient failure is not a refusal: stop rather than bill the next
	// owner for a fault that says nothing about the first.
	down := errors.New("identity provider unreachable")
	_, err := pickPayer(ctx, members, func(context.Context, string) error { return down })
	if !errors.Is(err, down) {
		t.Fatalf("want the transient error, got %v", err)
	}
}
