package api

import (
	"testing"

	"github.com/Privasys/drive/service/internal/config"
)

func strp(s string) *string { return &s }

// TestConfigureOverlay_MergeByOmission: a re-configure that only
// touches the embeddings settings must keep the escrow reference,
// recovery policy and every other omitted field.
func TestConfigureOverlay_MergeByOmission(t *testing.T) {
	cur := &config.Config{
		Mode:              config.ModeEscrowed,
		QuotaDefaultBytes: 42,
		MgmtBaseURL:       "https://api.example",
		OrgMEKRef:         `{"handle":"h"}`,
		Recovery:          &config.RecoveryPolicy{Issuer: "https://idp", Quorum: 2, ApproverRole: "org:admin", Disclose: true},
	}
	req := &configureRequest{
		Mode:                 config.ModeEscrowed,
		EmbeddingsBaseURL:    strp("https://fleet.example"),
		EmbeddingsModel:      strp("qwen3-embedding-0.6b"),
		EmbeddingsDependency: strp(`{"entries":[{"app_id":"x","measurements":[{"sgx":"aa"}],"required_oids":[]}]}`),
	}
	got := req.overlay(cur)
	if got.OrgMEKRef != cur.OrgMEKRef || got.Recovery == nil || got.Recovery.Quorum != 2 {
		t.Fatalf("escrow fields lost: %+v", got)
	}
	if got.MgmtBaseURL != cur.MgmtBaseURL || got.QuotaDefaultBytes != 42 {
		t.Fatalf("ops fields lost: %+v", got)
	}
	if got.EmbeddingsBaseURL != "https://fleet.example" || got.EmbeddingsDependency == "" {
		t.Fatalf("embeddings fields not applied: %+v", got)
	}
	// The current config must not have been mutated in place.
	if cur.EmbeddingsBaseURL != "" {
		t.Fatal("overlay mutated the current config")
	}
}

// TestConfigureOverlay_ExplicitClear: an empty string clears; first
// configure starts from zero.
func TestConfigureOverlay_ExplicitClear(t *testing.T) {
	cur := &config.Config{Mode: config.ModeSovereign, EmbeddingsBaseURL: "https://fleet.example"}
	got := (&configureRequest{Mode: config.ModeSovereign, EmbeddingsBaseURL: strp("")}).overlay(cur)
	if got.EmbeddingsBaseURL != "" {
		t.Fatalf("explicit clear ignored: %q", got.EmbeddingsBaseURL)
	}
	first := (&configureRequest{Mode: config.ModeSovereign}).overlay(nil)
	if first.Mode != config.ModeSovereign || first.MgmtBaseURL != "" {
		t.Fatalf("first configure = %+v", first)
	}
}

// TestConfigureOverlay_ObjectBackend: object-store fields apply through
// merge-by-omission like every other configure field.
func TestConfigureOverlay_ObjectBackend(t *testing.T) {
	cur := &config.Config{Mode: config.ModeSovereign, EmbeddingsBaseURL: "https://fleet.example"}
	got := (&configureRequest{
		Mode:             config.ModeSovereign,
		ObjectBackend:    strp("gcs"),
		ObjectBucket:     strp("privasys-drive-prod"),
		ObjectCredential: strp(`{"type":"service_account"}`),
	}).overlay(cur)
	if got.ObjectBackend != "gcs" || got.ObjectBucket != "privasys-drive-prod" || got.ObjectCredential == "" {
		t.Fatalf("object fields not applied: %+v", got)
	}
	// An omitted object_backend on a later configure keeps the store set.
	next := (&configureRequest{Mode: config.ModeSovereign, ChatModel: strp("m")}).overlay(got)
	if next.ObjectBackend != "gcs" || next.ObjectBucket != "privasys-drive-prod" {
		t.Fatalf("object fields lost on omission: %+v", next)
	}
}

// TestValidate_ObjectBackend: a remote backend needs bucket + credential;
// an unknown backend is rejected; local needs nothing.
func TestValidate_ObjectBackend(t *testing.T) {
	base := func() *config.Config { return &config.Config{Mode: config.ModeSovereign} }
	if err := (&config.Config{Mode: config.ModeSovereign, ObjectBackend: "gcs"}).Validate(); err == nil {
		t.Fatal("gcs without bucket/credential should fail")
	}
	c := base()
	c.ObjectBackend, c.ObjectBucket = "gcs", "b"
	if err := c.Validate(); err == nil {
		t.Fatal("gcs without credential should fail")
	}
	c.ObjectCredential = `{"type":"service_account"}`
	if err := c.Validate(); err != nil {
		t.Fatalf("valid gcs config rejected: %v", err)
	}
	if err := (&config.Config{Mode: config.ModeSovereign, ObjectBackend: "wat"}).Validate(); err == nil {
		t.Fatal("unknown backend should fail")
	}
	if err := (&config.Config{Mode: config.ModeSovereign, ObjectBackend: "local"}).Validate(); err != nil {
		t.Fatalf("local backend rejected: %v", err)
	}
}
