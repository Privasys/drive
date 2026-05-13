# Architecture

This is a high-level overview of how Privasys Drive is built. It is the
canonical, long-lived description of the system.

## 1. Components

```
┌─────────────────────────────────────────────────────────────────────┐
│  Client (wallet / chat.privasys.org / 3rd-party platform app)        │
│  - holds OIDC ID-token from privasys.id                              │
│  - holds (or mints) AppGrant tokens for non-wallet apps              │
└─────────────────────────────────────────────────────────────────────┘
                            │  HTTPS + RA-TLS (MRTD pinned)
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Drive enclave (TDX, enclave-os-virtual)                             │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────────────┐   │
│  │ REST API│  │ MCP cat. │  │ Grants   │  │ AEAD chunk store    │   │
│  └─────────┘  └──────────┘  └──────────┘  └─────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Postgres index (tenants, members, nodes, grants, changes)    │   │
│  │ — lives on a LUKS-encrypted LV inside the VM disk            │   │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                            │       │
              backend keys  │       │  ed25519 keys for AppGrants,
              (DEK, NameHMAC│       │  bound to wallet pubkey
              derived from  │       │
              MEK)          ▼       ▼
                  ┌────────────────────────┐
                  │ SGX vault constellation │  (k=2 / n=4 RawShare; key
                  │ vault:drive/<tenant>/mek│   path versioned per
                  │                  /v1     │   tenant DEK rotation)
                  └────────────────────────┘
                            │
                            ▼
              ┌───────────────────────────────┐
              │ Object backend per tenant      │
              │  default: GCS                  │
              │     bucket: privasys-drive-…   │
              │  alt: OVH/S3/Azure/local-disk  │
              └───────────────────────────────┘
```

The optional **extraction enclave** lives in a *separate* trust domain
with its own MRTD. It subscribes to Drive's change feed (REST), pulls
plaintext for opted-in folders, extracts text + computes embeddings,
and *pushes* the result into [private-rag](https://github.com/Privasys/private-rag).
Drive itself never calls a model.

## 2. Data model

- **Tenant** — `User` (one owner) or `Enterprise` (members with roles
  `owner | admin | contributor | reader`). Per-folder `acl_override`
  jsonb supports SharePoint-style fine-grained ACLs without altering
  the closure tree.
- **Node** — folder or file. Filenames are stored in plaintext (the
  index lives inside the TDX-protected disk); a 32-byte HMAC tag
  enforces (parent, name) uniqueness.
- **File manifest** — JSON describing a list of AEAD-sealed chunks
  (max 4 MiB plaintext each, XChaCha20-Poly1305) plus a SHA-256
  Merkle root over the chunk ciphertext hashes. The manifest itself
  is sealed under the per-file CEK and persisted next to the chunks.
- **Grant** — three-audience share:
  - `subject:<sub>` user-to-user (wallet re-wraps the CEK)
  - `link` anonymous static link with URL fragment-secret
  - `app:<mrtd>` third-party platform app authenticated by an
    Ed25519-signed AppGrant token bound to the wallet pubkey

## 3. Cryptography

| Use | Algorithm |
|---|---|
| Chunk + manifest AEAD | XChaCha20-Poly1305 (256-bit key, 192-bit nonce) |
| Key derivation | HKDF-SHA-256 (versioned labels) |
| Filename HMAC | HMAC-SHA-256 (fixed 32-byte tag) |
| Merkle tree | SHA-256, last-node-duplicated odd handling |
| AppGrant signature | Ed25519 |
| Transport | TLS 1.3 + RA-TLS (0xFFBB attestation extension) |

Per-tenant keys are *derived* from a tenant MEK held by the SGX vault
constellation (RawShare, k=2 / n=4). Rotation is performed by minting
a v2 label and queuing a re-encryption pass; the manifest format
already carries a `v` field.

## 4. APIs

| Surface | Use |
|---|---|
| REST `/v1/...` | Wallet, web clients, server-to-server |
| MCP `/mcp/v1/tools` | LLM agents (`chat.privasys.org`, future copilots) |

Both surfaces share the same internal handlers; MCP advertises a
catalog and lets agents call the corresponding REST endpoint.

## 5. Operational notes

- The service is delivered as a reproducible OCI image
  (`ghcr.io/privasys/drive:<sha>`) consumed by Enclave OS Virtual.
- Postgres runs on a LUKS-encrypted LV inside the VM; backups are
  PG-native + ciphertext-only chunk replication.
- Per-tenant quotas, a pull-based change-stream cursor for the
  extraction enclave, and a streamed GDPR ZIP exporter are first-class
  features rather than bolt-ons.
