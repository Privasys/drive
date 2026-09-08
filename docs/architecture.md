# Architecture

This is a high-level overview of how Privasys Drive is built. It is the
canonical, long-lived description of the system.

## 1. Components

```
┌────────────────────────────────────────────────────────────────────┐
│  Client (wallet / chat.privasys.org / 3rd-party platform app)      │
│  - holds OIDC ID-token from privasys.id                            │
│  - or holds an AppGrant token bound to its own Ed25519 key         │
└────────────────────────────────────────────────────────────────────┘
                            │  HTTPS + RA-TLS (measurement pinned)
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
              (DEK, NameHMAC│       │  bound to the app's pubkey
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
              │ Object backend per instance   │
              │  local disk / GCS / S3 / OVH  │
              │  (tenants may bring their own)│
              └───────────────────────────────┘
```

**The search index lives inside Drive.** A file is converted to text in
the image (docling for PDF, Office and images), given a deterministic
section tree with stable anchors, chunked along its sections and embedded
into pgvector rows on the same sealed volume as the node index. The only
model calls leave over a measurement-pinned mutual RA-TLS dial to the
confidential-AI fleet, which identifies Drive by its attested client
certificate: embeddings at index time, an optional cross-encoder rerank
of the vector candidates at query time (`rerank_model`), and, when the
instance enables `summarise_on_ingest`, one chat call per section
producing the summaries and document descriptions the tree tools show.
What the instance sends to which fleet is disclosed in `/status`
(`ai` block); a folder opts out of summaries for its subtree.

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
  enforces (parent, name) uniqueness. Every node carries a **revision**
  (`rev`), a counter bumped on each content or metadata change and, for
  a folder, whenever a direct child is added, removed or moved. It is
  the `ETag` on reads and the `If-Match` fence on writes.
- **File manifest**: JSON describing a list of AEAD-sealed chunks
  (max 4 MiB plaintext each, XChaCha20-Poly1305) plus a SHA-256
  Merkle root over the chunk ciphertext hashes. The manifest itself
  is sealed under the per-file CEK and persisted next to the chunks.
  Appends add chunks under the same CEK and rewrite the manifest, so a
  session log grows in time proportional to the turn, not the log.
- **Grant**: three-audience share:
  - `subject:<sub>` user-to-user. The owner mints a read (or write)
    grant on a node with `POST /v1/tenants/{id}/nodes/{node}/grants`;
    the recipient then reads it through the normal file endpoints and
    the enclave decrypts server-side with the owner's tenant MEK, over
    the attested channel. Recipients discover their inbound shares via
    `GET /v1/shared`. A share on a folder covers its subtree, and
    revocation (`DELETE .../grants/{grantID}`) removes access
    immediately.
  - `link` anonymous static link with URL fragment-secret. A
    `restricted` link may require attributes of its recipient. Those the
    platform marketplace prices are *proven* (read from the recipient's
    verified token, never from a form) and paid for by the **sharer**:
    creating the link mints an attribute billing grant against the
    sharer's own account, and `POST /v1/links/{id}/preview` hands the
    grant id to the visitor's sign-in (`billing_grant` on `/authorize`).
    A grant funds one sign-in; a link handed to a second person is
    re-armed with `POST /v1/tenants/{t}/links/{id}/billing-grant`.
    Assurance is a property of the attribute KEY (`given_name` and
    `given_name_id` are two requirements at two prices); the link
    records which claim proves each one when it is created and the
    redeem path reads that claim and no other.
  - `app:<app id>` a platform app, authenticated by an Ed25519-signed
    **AppGrant** token whose key the app holds. The subject is the app's
    platform id (32 hex); older grants may carry a code digest or an
    enclave measurement. When the call arrives over an attested channel
    the runtime republishes the caller's verified app id, and Drive
    refuses a grant whose subject does not match it: a token alone
    never suffices once the peer is known. Section 6 describes how an
    app obtains such a grant.

## 3. Cryptography

| Use | Algorithm |
|---|---|
| Chunk + manifest AEAD | XChaCha20-Poly1305 (256-bit key, 192-bit nonce) |
| Key derivation | HKDF-SHA-256 (versioned labels) |
| Filename HMAC | HMAC-SHA-256 (fixed 32-byte tag) |
| Merkle tree | SHA-256, last-node-duplicated odd handling |
| AppGrant signature | Ed25519 |
| Transport | TLS 1.3 + RA-TLS (attested, channel-bound) |

Per-tenant keys are *derived* from a tenant MEK held by the SGX vault
constellation (RawShare, k=2 / n=4). Rotation is performed by minting
a v2 label and queuing a re-encryption pass; the manifest format
already carries a `v` field. The MEK's policy pins the Drive image
digest: after a release, a sovereign user re-approves the new
measurement for their own tenant at their next sign-in (a fresh
wallet-issued grant), while an instance owner approves it once for an
escrowed instance's tenants.

## 4. APIs

| Surface | Use |
|---|---|
| REST `/v1/...` | Wallet, web clients, apps and server-to-server (streaming up/download, the filesystem API of section 5) |
| Manifest tools `/tools/...` | Portal Configure/Manage, CLI, MCP, LLM agents; declared in `privasys.json` (`org.privasys.manifest` OCI label) |
| Manifest actions `/actions/...` | Owner operations with progress (the object drain) |

Both surfaces share the same internal handlers and access checks; the
tools are plain-JSON POST wrappers capped at 8 MiB per file (larger
transfers use REST streaming).

## 5. The filesystem API

Apps that treat their folder as a disk need more than upload and
download. These endpoints are what a client library or a runtime
snapshot engine builds on; all of them accept an AppGrant as well as a
user bearer, and all of them respect the grant's scope.

| Need | Endpoint |
|---|---|
| Conditional write | `PUT /v1/tenants/{t}/nodes/{id}/content` with `If-Match: "<rev>"`; `412 {"error":"stale","rev":N}` on a lost race. Reads answer with `ETag`. |
| Address by path | `GET` and `PUT /v1/tenants/{t}/path?root=<folder id>&path=a/b/c.txt`; `X-Drive-Parents: create` makes intermediate folders; `If-None-Match: *` refuses to overwrite. |
| Append | `POST /v1/tenants/{t}/nodes/{id}/append` (body = bytes to add, `If-Match` optional); new chunks only. |
| Range read | `GET /v1/tenants/{t}/files/{id}` with `Range: bytes=…` answers `206` and `Content-Range`. |
| Change feed | `GET /v1/tenants/{t}/changes?since=<seq>&root=<folder id>&wait=<seconds ≤ 60>`; long-polls until something changes under the root. |
| Search | Tools `grep` (RE2 pattern, `include` glob, byte budget of 256 MiB per call) and `glob` (`**` supported) over a granted root, executed inside the enclave over decrypted streams. |
| Rediscover grants | `GET /v1/grants/mine` with the AppGrant as bearer lists every active grant bound to that key. |
| Storage | `GET /v1/tenants/{t}/quota`: used and limit bytes plus a by-folder `breakdown` and a per-app `apps` breakdown of `AppData/`. |

Each conditional write takes a per-node lock and checks the revision
before the sealed manifest is rewritten, so a refused writer cannot
clobber the file's fixed-key manifest.

## 6. Apps on the Drive

An app never receives a user's keys and never picks its own folder. The
flow, from the app's point of view, has three parts.

**Consent.** The app asks for a `storage.folder` capability naming only
a label. The user's wallet fetches the ask over an attested channel to
the app, shows what is being requested, and, on approval, calls Drive's
`POST /v1/capabilities` with the app's id and the app's binding public
key. Drive resolves the user's personal tenant, places the folder under
`AppData/<label>/` (suffixing the label when another app already owns
it, never handing over a user-made folder), mints the AppGrant, and
returns `service_result` with `tenant_id`, `node_id` and `path`. Apps
that declare `resources` in their manifest have this brokered by the
Privasys runtime and only call its loopback endpoints; see
[apps.md](apps.md).

**Use.** The app presents the AppGrant as a bearer on the endpoints of
section 5. Denials are delivered too, so an app stops asking after a
refusal until the user reopens the question.

**The user's view.** `GET /v1/tenants/{t}/apps` lists the apps holding
a grant, with the app's display name, its folder, scope and expiry;
revocation is the ordinary grant `DELETE`. The folder stays: the user's
files are theirs. The storage gauge breaks usage down per app.

## 7. Workspace snapshots

A working tree (a repository, a build, a data directory) must not be
mapped file-per-node onto Drive. The contract Drive defines instead: a
folder holding `.workspace.json` beside a `.blobs/` folder, where the
manifest lists paths and the sha256 of each file's content and every
blob is a file named by that hash. The folder is excluded from indexing.
Listings flag such folders (`workspace_manifest_id`) so a client renders
them as one item, and `GET /v1/tenants/{t}/nodes/{id}/workspace.zip`
rebuilds the tree as a ZIP. The runtime writes snapshots at explicit
points (session end, commit, idle, shutdown), uploading only changed
blobs. The exact manifest format is in [apps.md](apps.md).

## 8. Operational notes

- The service is delivered as an OCI image (`ghcr.io/privasys/drive`,
  `provenance: false`) consumed by Enclave OS Virtual; deployments pin
  the registry digest, never a mutable tag.
- The index lives on the platform's sealed per-app volume and survives
  restarts and (owner-promoted) upgrades; backups are ciphertext-only
  chunk replication plus the platform volume story.
- The instance object backend can be switched live through `configure`;
  the `drain_local_objects` action then copies every object still on the
  volume into the bucket, key for key, idempotently.
- Per-tenant quotas, the change feed, and the streamed GDPR ZIP exporter
  are first-class features rather than bolt-ons.
