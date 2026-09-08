# Privasys Drive

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

**Privasys Drive** is the per-tenant, end-to-end encrypted file storage
service that powers Privasys Wallet, Privasys Chat, Privasys Harness, and
any third-party app on the Privasys platform. It is also the disk of a
confidential app: an app the user has approved on their wallet gets a
folder of its own, reachable through a filesystem-grade API, and the user
keeps one storage gauge, one list of apps with access, and one Revoke.

The tenant (an individual user OR an enterprise) owns the bytes. The
platform never sees plaintext. Files at rest live as AEAD-sealed,
content-addressed chunks in any object store the tenant chooses (GCS,
OVH, S3, Azure, …). The directory listing, ACLs, and key wrapping live
in a TDX enclave (`enclave-os-virtual`); the wallet pins the enclave's
measurement via RA-TLS.

## Layout

This is a monorepo:

| Path | Description |
|---|---|
| [service/](service/) | Go service: REST + MCP API, Postgres index, object backends, AEAD chunk store, share + AppGrant flow, wallet consent, GDPR exports. |
| [sdk/](sdk/) | TypeScript SDK consumed by the wallet, by `chat.privasys.org`, and by any web client. Browser + React Native compatible. |
| [docs/](docs/) | [Architecture](docs/architecture.md), [deployment](docs/deploy.md), and the [guide for apps](docs/apps.md) (consent, the filesystem API, workspace snapshots). |
| [extraction/](extraction/) | (Phase 4) Text-extraction + embeddings enclave that subscribes to Drive's change feed and pushes results into `private-rag`. |
| [render/](render/) | (Phase 4) PDF / Office / video render enclaves. |
| [web/](web/) | (Phase 4) Static-link share recipient viewer. |

## Highlights

- **End-to-end encrypted.** XChaCha20-Poly1305 chunks under per-file
  CEKs wrapped under per-tenant DEKs derived from a Shamir-shared MEK
  held in the SGX vault constellation.
- **Tenant model.** `User` (one owner) or `Enterprise` (multiple
  owners + role-based ACLs at the folder level, SharePoint-style).
- **Multi-cloud.** Pluggable `ObjectBackend` interface: local disk,
  GCS, S3 and OVH Object Storage ship; a running instance switches
  backends live and drains its local objects into the bucket with one
  owner action.
- **Tamper-evident.** Per-file Merkle tree over chunk ciphertext;
  the wallet remembers the root hash.
- **Apps get a folder, with the user's consent.** An app asks for
  storage; the user approves on their wallet; Drive places the folder
  under `AppData/<app>/` in the user's personal tenant and issues a
  holder-of-key **AppGrant** bound to the app's key. A grant presented
  over an attested channel must also match the attested app id, so a
  stolen token is worthless. The Privasys runtime brokers the whole
  exchange for apps that declare `resources` in their manifest.
- **A filesystem, not a bucket.** Revision tokens with conditional
  writes (`If-Match`, 412 on a stale write), addressing by path with
  parents created on demand, append-only writes, byte-range reads, a
  subtree change feed with long-polling, and `grep` / `glob` over a
  granted folder that run inside the enclave.
- **Workspace snapshots.** A working tree is stored as one item: a
  manifest beside content-addressed blobs, never exploded into the file
  list. Drive flags it, renders it read-only, and exports it as a ZIP.
- **The user model of a drive.** One quota per user (1 GiB today) with a
  by-folder and by-app breakdown, an "apps with access" list with
  Revoke, and app folders that are ordinary, browsable, deletable folders.
- **AI-native.** Drive is itself an MCP server. Any platform agent
  (`chat.privasys.org`, future copilots, third-party LLMs) can read
  + write files via a scoped, time-bounded AppGrant.
- **Push, don't pull, into RAG.** When a tenant opts in, the
  extraction enclave (separate trust domain) consumes Drive's change
  feed, extracts + embeds, and pushes the results into `private-rag`.
  Drive itself does no AI work.
- **GDPR Art. 20 export.** `POST /v1/exports` produces a deterministic
  ZIP of the tenant's tree, plaintext (default) or ciphertext (cold
  archival).

## Quick start (development)

Requires Go 1.25, Node 20, Postgres 17. From the repo root:

```bash
# Run the service against an ephemeral SQLite + local-disk backend
cd service
go test ./...
go run ./cmd/drive serve --dev
# -> listens on http://127.0.0.1:8443
```

```bash
# Try the SDK against the dev server
cd sdk
npm install
npm test
```

See [service/README.md](service/README.md) and [sdk/README.md](sdk/README.md)
for the per-component developer docs, and [docs/apps.md](docs/apps.md) for
how an app obtains and uses a folder.

## Production deployment

Drive runs as a **standard Privasys container app** on `enclave-os-virtual`
(TDX): it listens on the platform-injected `$PORT`, declares its typed
capabilities in [service/privasys.json](service/privasys.json) (baked into
the image's `org.privasys.manifest` OCI label), persists its index +
instance config on the sealed per-app `/data` volume
(`container_storage: true`), and self-recovers the configure-then-freeze
gate on restart. The image is published to `ghcr.io/privasys/drive` by
[.github/workflows/service.yml](.github/workflows/service.yml). **Pin
deployments by the registry digest printed in the workflow summary, never
by a mutable tag**. See [docs/deploy.md](docs/deploy.md), including what a
new Drive digest means for the apps that pin it.

An instance runs in one of two attestable operating modes, set once at
configure time: **sovereign** (only tenants can unlock their data; the
operator holds no key) or **escrowed** (org master-key escrow with
policy-gated, audited recovery).

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[AGPL-3.0](LICENSE).
