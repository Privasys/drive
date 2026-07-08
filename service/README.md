# `service/` — Privasys Drive service

Go binary that:

- Runs as a standard Privasys container app: `$PORT` listener, typed
  capabilities in [privasys.json](privasys.json) (baked into the image's
  `org.privasys.manifest` OCI label), instance config on the sealed
  `/data` volume with configure-then-freeze self-recovery on restart.
- Stores per-tenant trees in a SQL index (SQLite on the sealed volume;
  the DDL stays Postgres-portable via the Dialect layer).
- Stores AEAD-sealed, content-addressed chunks via a pluggable
  [object backend](internal/objectstore/objectstore.go) (local-disk
  today; GCS/OVH/S3 in Phase 3).
- Exposes the operations as REST (`/v1/...`) and as manifest tools
  (`/tools/...`, plain-JSON POST — what the portal, CLI and MCP surface
  invoke).
- Verifies `privasys.id` bearer tokens in-enclave (offline JWKS), with
  revoked-session polling and the configure-authz role check
  (`privasys-platform:app:<id-hex>:owner|admin`) on privileged tools.
- Mints + verifies Ed25519-signed AppGrant tokens that let third-party
  platform apps act on the tenant's behalf with a scoped, time-bounded,
  revocable grant, confined to the granted node's subtree.

## Layout

```
cmd/drive/             entrypoint
internal/api/          REST + tool handlers, auth, configure/status/health
internal/config/       persisted instance config (operating mode, defaults)
internal/crypto/       XChaCha20-Poly1305, HKDF, Merkle, name-HMAC
internal/export/       GDPR ZIP builder (plaintext + ciphertext)
internal/grants/       share + AppGrant repo + Ed25519 token format
internal/manifest/     chunked AEAD file format + Merkle manifest
internal/objectstore/  Backend interface + local-disk impl
internal/oidc/         OIDC verifiers (JWKS + dev stub) + revoked-sid set
internal/platform/     enclave-manager env + config-complete client
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
index because the index lives on the platform's sealed per-app volume
(vault-backed, measurement-gated DEK); an HMAC tag is computed alongside
for a deterministic uniqueness key. The per-tenant DEK never persists
outside the enclave; it is derived on demand from the tenant's MEK,
held in the SGX vault constellation with the tenant as the only owner
principal (sovereign mode) or additionally escrow-wrapped under the org
master key (escrowed mode). See [../SECURITY.md](../SECURITY.md).
