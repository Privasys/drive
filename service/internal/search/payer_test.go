package search

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type payerMark struct{}

// recordingEmbedder counts the paid calls and whether they carried a payer.
type recordingEmbedder struct {
	LocalEmbedder
	calls    int
	sawPayer bool
}

func (r *recordingEmbedder) Embed(ctx context.Context, texts []string, mode Mode) ([][]float32, error) {
	r.calls++
	if ctx.Value(payerMark{}) != nil {
		r.sawPayer = true
	}
	return r.LocalEmbedder.Embed(ctx, texts, mode)
}

const payerDoc = "# Plan\nfunding round notes, see [[Investors]]\n\n# Annex\nfigures"

func payerIndexer(ops *fakeOps, emb *recordingEmbedder, payer func(context.Context, string) (context.Context, error)) *Indexer {
	return &Indexer{
		Ops: ops,
		Content: func(context.Context, string, string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(payerDoc)), nil
		},
		Embedder: func() Embedder { return emb },
		Payer:    payer,
		Sync:     true,
	}
}

// With nobody to pay, a file waits: no inference call is made, and it is not
// marked failed, so it indexes once its owner allows Drive to spend. The free
// work still happens, so the document's structure and its graph links exist
// in the meantime.
func TestNoPayerParksTheFileWithoutCallingOut(t *testing.T) {
	ops := newFakeOps()
	emb := &recordingEmbedder{}
	ix := payerIndexer(ops, emb, func(ctx context.Context, _ string) (context.Context, error) {
		return ctx, errors.New("no owner has allowed Drive to spend their credits")
	})
	ix.Enqueue("t1", "n1", "plan.md", "text/markdown")

	if emb.calls != 0 {
		t.Fatalf("no payer, yet %d embedding call(s) went out", emb.calls)
	}
	if got := ops.status["n1"]; got != "pending" {
		t.Fatalf("a file with no payer must wait, not %q", got)
	}
	if len(ops.secs["n1"]) == 0 {
		t.Fatal("sections are free and should exist while the file waits")
	}
	if len(ops.links["n1"]) == 0 {
		t.Fatal("graph links are free and should exist while the file waits")
	}
}

// With a payer, every paid call carries it: that is what the embedder's and
// summariser's Decorate hooks turn into a spend token.
func TestPayerTravelsWithThePaidCalls(t *testing.T) {
	ops := newFakeOps()
	emb := &recordingEmbedder{}
	ix := payerIndexer(ops, emb, func(ctx context.Context, tenantID string) (context.Context, error) {
		if tenantID != "t1" {
			t.Errorf("payer asked about tenant %q, want t1", tenantID)
		}
		return context.WithValue(ctx, payerMark{}, "owner"), nil
	})
	ix.Enqueue("t1", "n1", "plan.md", "text/markdown")

	if got := ops.status["n1"]; got != "indexed" {
		t.Fatalf("status %q, want indexed", got)
	}
	if emb.calls == 0 || !emb.sawPayer {
		t.Fatalf("embedding calls %d, carried the payer: %v", emb.calls, emb.sawPayer)
	}
}
