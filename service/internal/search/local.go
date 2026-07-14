package search

import (
	"context"
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// LocalEmbedder is the lexical space used ONLY while no fleet model is
// configured (drive plan §8.4: once a real model exists, fleet failures
// park files pending — the fallback never writes into a configured
// deployment). It is a deterministic random-projection ("hashing
// trick") of token and bigram counts into Dim dimensions,
// L2-normalised: real recall for keyword-ish queries, none of a neural
// model's paraphrase understanding. Its rows live in their own
// embed_space and never mix with a model's.
type LocalEmbedder struct{}

func (LocalEmbedder) Space() string { return "local-lexical/1024/v1" }

// Embed ignores the mode: the lexical projection is symmetric (no
// instruction asymmetry to honour).
func (LocalEmbedder) Embed(_ context.Context, texts []string, _ Mode) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = lexicalVector(t)
	}
	return out, nil
}

func lexicalVector(text string) []float32 {
	v := make([]float32, Dim)
	toks := tokenize(text)
	add := func(s string, weight float32) {
		h := fnv.New64a()
		_, _ = h.Write([]byte(s))
		sum := h.Sum64()
		idx := int(sum % uint64(Dim))
		// The next hash bit picks the sign, spreading mass around zero
		// so unrelated texts decorrelate.
		sign := float32(1)
		if (sum>>63)&1 == 1 {
			sign = -1
		}
		v[idx] += sign * weight
	}
	prev := ""
	for _, tok := range toks {
		add(tok, 1)
		if prev != "" {
			add(prev+" "+tok, 0.5)
		}
		prev = tok
	}
	// L2 normalise so cosine distance is well-behaved.
	var norm float64
	for _, f := range v {
		norm += float64(f) * float64(f)
	}
	if norm > 0 {
		inv := float32(1 / math.Sqrt(norm))
		for i := range v {
			v[i] *= inv
		}
	}
	return v
}

func tokenize(text string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 1 { // single letters carry no signal
			toks = append(toks, cur.String())
		}
		cur.Reset()
	}
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return toks
}
