# Architecture

This is a high-level overview of how Privasys Drive is built. It is the
canonical, long-lived description of the system.

## 1. Components

```
┌────────────────────────────────────────────────────────────────────┐
│  Client (wallet / chat.privasys.org / 3rd-party platform app)      │
│  - holds OIDC ID-token from privasys.id                            │
│  - holds (or mints) AppGrant tokens for non-wallet apps            │
└────────────────────────────────────────────────────────────────────┘
                            │  HTTPS + RA-TLS (MRTD pinned)
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│  Drive enclave (TDX, enclave-os-virtual)                           │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────────────┐  │
│  │ REST API│  │ Tools    │  │ Grants   │  │ AEAD chunk store    │  │
│  └─────────┘  └──────────┘  └──────────┘  └─────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ SQL index (tenants, members, nodes, grants, changes)         │  │
│  │   lives on the sealed per-app /data volume                   │  │
│  │   (container_storage; vault-backed, measurement-gated DEK)   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
                            │       │
              backend keys  │       │  ed25519 keys for AppGrants,
              (DEK, NameHMAC│       │  bound to wallet pubkey
              derived from  │       │
              MEK)          ▼       ▼
              ┌────────────────────────────────────┐
              │ SGX vault constellation            │
              │ vault:apps.privasys.org/<app-id>/  │
              │   data/<tenant-ref>/mek/v1         │
              │ (owner = the tenant's sub; version │
              │  bumped per tenant MEK rotation)   │
              └────────────────────────────────────┘
                            │
                            ▼
              ┌───────────────────────────────┐
              │ Object backend per tenant     │
              │  default: GCS                 │
              │     bucket: privasys-drive-…  │
              │  alt: OVH/S3/Azure/local-disk │
              └───────────────────────────────┘
```

The optional **extraction enclave** lives in a *separate* trust domain
with its own MRTD. It subscribes to Drive's change feed (REST), pulls
plaintext for opted-in folders, extracts text + computes embeddings,
and *pushes* the result into [private-rag](https://github.com/Privasys/private-rag).
Drive itself never calls a model.

## 2. Data model

- **Tenant**: `User` (one owner) or `Enterprise` (members with roles
  `owner | admin | contributor | reader`). Per-folder `acl_override`
  (`{"roles":[...]}`) narrows the inherited tenant ACL SharePoint-style:
  a member's role must be in the nearest ancestor override's permitted
  set (the owner is never locked out). Set via
  `PUT /v1/tenants/{id}/nodes/{folderID}/acl` (owner/admin);
  enforced in `allowNode` on every read/write.
- **Node**: folder or file. Filenames are stored in plaintext (the
  index lives inside the TDX-protected disk); a 32-byte HMAC tag
  enforces (parent, name) uniqueness.
- **File manifest**: JSON describing a list of AEAD-sealed chunks
  (max 4 MiB plaintext each, XChaCha20-Poly1305) plus a SHA-256
  Merkle root over the chunk ciphertext hashes. The manifest itself
  is sealed under the per-file CEK and persisted next to the chunks.
- **Grant**: three-audience share:
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
| REST `/v1/...` | Wallet, web clients, server-to-server (streaming up/download) |
| Manifest tools `/tools/...` | Portal Configure/Manage, CLI, MCP, LLM agents; declared in `privasys.json` (`org.privasys.manifest` OCI label) |

Both surfaces share the same internal handlers and access checks; the
tools are plain-JSON POST wrappers capped at 8 MiB per file (larger
transfers use REST streaming).

## 5. Operational notes

- The service is delivered as an OCI image (`ghcr.io/privasys/drive`,
  `provenance: false`) consumed by Enclave OS Virtual; deployments pin
  the registry digest, never a mutable tag.
- The index lives on the platform's sealed per-app volume and survives
  restarts and (owner-promoted) upgrades; backups are ciphertext-only
  chunk replication plus the platform volume story.
- Per-tenant quotas, a pull-based change-stream cursor for the
  extraction enclave, and a streamed GDPR ZIP exporter are first-class
  features rather than bolt-ons.
