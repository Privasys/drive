# `service/` — Privasys Drive service

Go binary that:

- Stores per-tenant trees in a SQL index (Postgres in production,
  SQLite in tests + `--dev`).
- Stores AEAD-sealed, content-addressed chunks via a pluggable
  [object backend](internal/objectstore/objectstore.go) (GCS, OVH, S3,
  local-disk).
- Exposes the operations as both a REST API and an MCP tool catalog.
- Verifies bearer tokens issued by `https://privasys.id` (audience
  `privasys-drive`).
- Mints + verifies Ed25519-signed AppGrant tokens that let
  third-party platform apps act on the tenant's behalf with a
  scoped, time-bounded, revocable grant.

## Layout

```
cmd/drive/             entrypoint
internal/api/          REST handlers + auth glue
internal/crypto/       XChaCha20-Poly1305, HKDF, Merkle, name-HMAC
internal/export/       GDPR ZIP builder (plaintext + ciphertext)
internal/grants/       share + AppGrant repo + Ed25519 token format
internal/manifest/     chunked AEAD file format + Merkle manifest
internal/mcp/          MCP tool catalog + transport
internal/objectstore/  Backend interface + local-disk impl
internal/oidc/         OIDC bearer verifier (dev stub + JWKS-ready)
internal/store/        SQL index (tenants, members, nodes, grants, changes)
```

## Build & test

```bash
go test ./...
go run ./cmd/drive serve --dev
```

## Threat model in one paragraph

Plaintext bytes never leave the enclave's RAM. The object backend sees
nothing but content-addressed AEAD ciphertext — even the operator with
root on the storage host cannot enumerate, modify, or correlate
chunks beyond byte counts. Filenames are stored in plaintext in the
index because the index lives inside the TDX VM's encrypted disk; an
HMAC tag is computed alongside for a deterministic uniqueness key.
The per-tenant DEK never persists outside the enclave; it is derived
on demand from the tenant's MEK, which itself is reconstructed from a
2-of-4 RawShare held by the SGX vault constellation. See
[../SECURITY.md](../SECURITY.md).
