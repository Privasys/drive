# Drive for apps

How a confidential app gets a folder in a user's Drive, what it can do
with it, and how a working tree is kept there. This is the developer
guide; [architecture.md](architecture.md) has the design.

## 1. Getting a folder

An app never chooses where it writes and never sees a key. It asks, the
user approves on their wallet, and Drive hands back coordinates.

### The easy way: declare the resource

An app running on the Privasys runtime declares what it needs in its
manifest (`privasys.json`, baked into the image label):

```json
{
  "resources": [
    { "kind": "storage.folder", "name": "storage", "label": "Harness",
      "permissions": ["read", "write"] }
  ]
}
```

The runtime then brokers consent on the app's behalf. The app talks to
its enclave manager over loopback, authenticated by the container token
the runtime injects (`PRIVASYS_CONTAINER_TOKEN`), and never implements
the wallet protocol:

| Call | Body | Answer |
|---|---|---|
| `POST /api/v1/resources/storage/request` | `{"subject": "<acting user's sub>", "retry": false}` | `{"status": "pending", "nonce": "…", "app_host": "…"}` while the user decides; `already_granted` with `capability_id` and `service_result`; or `declined` |
| `GET /api/v1/resources/storage/status?subject=…` | | `{"persistent": true, "capability_id": "…", "service_result": {"tenant_id": "…", "node_id": "…", "path": "AppData/Harness"}}` |
| `POST /api/v1/resources/sign` | `{"payload_b64": "…"}` | `{"signature_b64": "…", "pubkey_b64": "…"}`: the holder-of-key proof over a payload, signed by the app's sealed binding key |

The runtime holds the app's binding key sealed on the enclave's data
volume, pushes the user's wallet through the control plane with the
app's own attested identity, serves the wallet's attested fetch of the
ask on the app's hostname, and records the outcome per user. A denial
sticks: the app should only pass `retry: true` on an explicit user
gesture.

### The direct way: the wallet protocol

An app can also speak the protocol itself. It serves
`GET /.well-known/privasys/capability-request?nonce=…` returning

```json
{
  "nonce": "…",
  "binding_pubkey": "<base64 Ed25519 public key>",
  "resource_app": "<Drive's app id, 32 hex>",
  "capability": {
    "kind": "storage.folder",
    "permissions": ["read", "write"],
    "resource_label": "Harness",
    "request": { "folder": "Harness" }
  }
}
```

and accepts `POST /.well-known/privasys/capability-result` with
`{"nonce", "status": "approved" | "denied", "capability_id",
"service_result"}`. The wallet fetches the ask over RA-TLS, so the key
being authorised is learned inside an attested channel, never from the
push. The request never names a tenant: Drive derives the boundary from
the authenticated holder and refuses any request that names one.

### What Drive does on approval

The wallet calls `POST /v1/capabilities` on Drive:

```json
{
  "nonce": "…",
  "subject_app_id": "<app id, 32 hex>",
  "binding_pubkey": "<base64>",
  "expires_unix": 0,
  "kind": "storage.folder",
  "permissions": ["read", "write"],
  "request": { "folder": "Harness" }
}
```

Drive resolves the holder's personal tenant, creates or reuses
`AppData/<label>/` (the label is sanitised; if another app already owns
that name the folder becomes `<label> (<8 hex of the app id>)`; a folder
the user made is never handed to an app), mints the AppGrant bound to
`binding_pubkey` with subject `app:<app id>`, and answers:

```json
{
  "capability_id": "<grant id>",
  "status": "approved",
  "service_result": {
    "tenant_id": "…", "node_id": "…", "path": "AppData/Harness"
  }
}
```

Read the path from `service_result`; do not assume the label.

## 2. Using the grant

The AppGrant is a compact signed token. Present it as
`Authorization: Bearer <token>`. When the call arrives over an attested
channel, the runtime republishes the caller's verified app id and Drive
requires it to match the grant's subject; a leaked token cannot be used
from anywhere else.

Everything below is scoped to the granted folder and to the grant's
permissions. `{t}` is `service_result.tenant_id`, `{root}` is
`service_result.node_id`.

### Read and write by path

```
GET  /v1/tenants/{t}/path?root={root}&path=notes/today.md
PUT  /v1/tenants/{t}/path?root={root}&path=notes/today.md
     X-Drive-Parents: create        # make notes/ if missing
     If-None-Match: *               # create only, 412 if it exists
     If-Match: "7"                  # replace only revision 7, else 412
```

A `GET` on a path answers the node (with its `rev`) for a folder, or
the bytes with an `ETag` for a file. Every write answers with the new
`ETag`.

### Conditional replace and append

```
PUT  /v1/tenants/{t}/nodes/{id}/content   If-Match: "<rev>"
POST /v1/tenants/{t}/nodes/{id}/append    If-Match: "<rev>" (optional)
```

`412 {"error":"stale","rev":N}` means another writer got there first:
re-read, merge, retry against `N`. Append adds chunks under the file's
existing key, so a log grows in time proportional to what is added.

### Range reads

```
GET /v1/tenants/{t}/files/{id}   Range: bytes=0-1048575
```

answers `206 Partial Content` with `Content-Range`.

### Watch a subtree

```
GET /v1/tenants/{t}/changes?since=<seq>&root={root}&wait=60
```

holds the request until something changes under the root or the wait
elapses, and returns the rows (`seq`, node, parent, name, kind, rev).
Deletions are attributed to the parent they were in.

### Search inside the folder

The `grep` and `glob` tools run inside the enclave over decrypted
streams and never write plaintext to disk:

```
POST /tools/grep {"tenant_id": "{t}", "root": "{root}",
                  "pattern": "TODO|FIXME", "include": "**/*.go",
                  "max_matches": 200}
POST /tools/glob {"tenant_id": "{t}", "root": "{root}",
                  "pattern": "src/**/*.ts"}
```

Patterns are RE2 (no look-around, no back-references). A search that
would scan more than 256 MiB in one call is refused with
`SEARCH_RAW_OUTPUT_OVERFLOW`; narrow it with `include` or a smaller
root.

### Rediscover after a redeploy

`GET /v1/grants/mine` with the AppGrant as bearer lists every active
grant bound to that key, so an app that lost its local state finds its
folders again without asking the user.

## 3. Workspace snapshots

A working tree must not be stored file-per-node: a checkout with tens
of thousands of small files would be as many rows, names, manifests and
chunks. Keep the tree on the app's own local volume and store its
durability as a snapshot: one folder holding `.workspace.json` beside a
`.blobs/` folder.

```json
{
  "version": 1,
  "app": "<app id, 32 hex>",
  "saved_at": "2026-09-08T10:00:00Z",
  "files": [
    { "path": "src/main.go", "size": 1234, "mode": "0644",
      "blob": "<sha256 hex of the plaintext>" },
    { "path": "README.md", "size": 88, "blob": "<sha256 hex>" }
  ]
}
```

Rules:

- Each blob is a file named by its sha256, inside `.blobs/`. Upload only
  blobs the folder does not hold yet (`PUT …/path?…` with
  `If-None-Match: *` answers 412 for one that exists).
- Paths are relative, forward-slash, without `..` segments; the export
  drops anything else.
- Write the manifest last, with `If-Match` on its current revision, so
  a reader never sees a manifest whose blobs are still uploading.
- Exclude the folder from indexing:
  `PUT /v1/tenants/{t}/nodes/{folder}/indexing {"no_index": true}`.

Drive flags such a folder in listings with `workspace_manifest_id`, the
Drive front renders it as one item ("workspace · 340 MB · saved 2 min
ago") with a read-only tree, and `GET /v1/tenants/{t}/nodes/{folder}/workspace.zip`
rebuilds the working tree as a ZIP. A blob the manifest names but the
folder lacks is listed in `WORKSPACE-MISSING-BLOBS.txt` inside the
archive rather than failing the export.

Restore on start: read the manifest, fetch the blobs you do not have
(by hash), lay the tree out locally. Snapshot at explicit points:
session end, commit, a debounced idle, shutdown.

## 4. Quota and the user's view

Every user has one ceiling on plaintext bytes across their whole
personal tenant (1 GiB at the time of writing); every write path
enforces it and reads never refuse. `GET /v1/tenants/{t}/quota` returns
`used_bytes`, `limit_bytes`, a `breakdown` by top-level entry and an
`apps` breakdown of `AppData/`, largest first. An app whose writes hit
the ceiling should keep its local tree and report "Drive full" rather
than lose data.

The user sees the app as a row in "Apps with access": the app's name,
its folder, permissions, expiry, and Revoke. After a revoke the app's
next call fails with 401 and it should ask again through the normal
consent flow; the files stay with the user.
