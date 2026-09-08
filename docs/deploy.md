# Deploying Privasys Drive

Drive deploys as a **standard Privasys container app** on the TDX fleet
(`enclave-os-virtual`), with no bespoke plumbing. This document describes
the production deployment contract.

## 1. Image

Each push to `main` builds `ghcr.io/privasys/drive` with the app manifest
baked into the `org.privasys.manifest` OCI label (from
`service/privasys.json`) and `provenance: false` so the registry digest is
stable. The workflow summary prints the pinnable digest.

**Always deploy by digest, never by a mutable tag:**

```bash
privasys apps versions create privasys-drive --image ghcr.io/privasys/drive@sha256:<digest>
privasys apps versions stage privasys-drive <version-id> --enclave <enclave-id>
privasys apps versions promote privasys-drive --pending <n>     # owner approval on the wallet
privasys apps deploy privasys-drive --version <version-id> --enclave <enclave-id>
```

Note: a package/prebuilt app's capabilities are read from the image label
at app creation, so pushing a new manifest means a new image digest and a
new version.

### What a new digest means for the apps around Drive

Drive's workload code digest is pinned by the apps that call it and by the
apps it calls over mutual RA-TLS. After every Drive release, rebuild those
pins before reporting the release done:

- the callee side (`allowed_callers`) of every app Drive calls, which is
  applied at that app's next deploy;
- the caller side (`dependencies`) of every app that calls Drive, which the
  control plane pushes to the running app;
- Drive's own `embeddings_dependency` configuration when the fleet it
  calls changes.

Sovereign users re-approve the new measurement for their own tenant key at
their next sign-in; an escrowed instance's owner approves it once with the
`approve_org_mek_measurement` tool.

## 2. Platform contract

The service follows the app-capabilities contract:

- Listens on the manager-injected `$PORT` (never 8080, which is reserved).
- `container_storage: true` gives it the sealed per-app `/data` LUKS
  volume; the index (embedded PostgreSQL at `/data/pgdata`), the local
  object store (`/data/objects/`, until drained to a bucket) and the
  instance config (`/data/config.json`) live there. The volume's DEK is
  vault-backed and measurement-gated; an enclave-os or image upgrade
  requires the app owner to stage + promote the new measurement
  (WebAuthn step-up).
- Configure-then-freeze: the manager 503-gates the app until the first
  successful `POST /configure`. On restart the service re-applies the
  persisted config and calls the manager's `config-complete` itself; no
  owner is needed after the one-time setup.
- `/health` is process liveness (always 200; the manager's container
  health check probes it). `readiness_path: /readiness` (503 until
  configured), `status_path: /status` (state/activity/message document
  for the portal).
- Manifest actions live at the top level (`/actions/<name>`, with a
  status tool the runner polls with POST).

## 3. Configuration (the `configure` tool)

One required field: the **operating mode**, immutable once set and part
of the attested configuration. Configure merges by omission (a field left
out keeps its value) but the mode must always be restated.

| Field | Values | Meaning |
|---|---|---|
| `mode` | `sovereign` | Only tenants can unlock their data; the operator holds no key and no unlock path. The Privasys public instance runs this. |
| | `escrowed` | Tenant keys carry an escrow wrap under the org master key (`MEK_org`); every escrow is disclosed to the tenant via the audit log. Escrowed setup needs `org_mek_ref` (the `MEK_org` vault reference, a RawShare the org created) + `recovery` (`{issuer, quorum, approvers?, disclose}`), sent via the API/CLI (not the portal form). |
| `quota_default_bytes` | integer | Per-user storage ceiling in plaintext bytes across the whole personal tenant, enforced on every write path (0 = unlimited). `GET /v1/tenants/{id}/quota` reports usage with a by-folder and by-app breakdown. The public instance runs 1 GiB. |
| `object_backend`, `object_bucket`, `object_credential` | `local`, `gcs`, `s3`, `ovh` + bucket + a sealed credential reference | The instance object store. Switching a running instance swaps the backend live for new writes; run the `drain_local_objects` action afterwards to copy every object still on the volume into the bucket (idempotent, nothing deleted). |
| `mgmt_base_url` | URL | Control-plane API base. When set, the instance refreshes stale vault attestation tokens itself, resolves app display names for the "apps with access" list, and can notify a user's wallet. Mutable. |
| `embeddings_base_url`, `embeddings_model`, `embeddings_api_key`, `embeddings_dependency`, `embeddings_allow_debug` | | The confidential-AI fleet used for semantic indexing, reached over pinned mutual RA-TLS; `embeddings_dependency` is the canonical dependency-set JSON pinning the fleet's measurement and code digest. |
| `assistant_enclave_measurement`, `assistant_enclave_token`, `chat_model` | | The assistant identity the RAG-in-enclave gate requires, and the chat model recorded for disclosure. |

Configure via the portal Configure tab, or over RA-TLS:
`privasys apps configure privasys-drive --set mode=sovereign`.

The owner/admin configure-authz roles
(`privasys-platform:app:<app-id-hex>:owner|admin`) are enforced by the
enclave-os runtime in front of the app on every externally reachable
path; the app itself only requires an authenticated user (proxied
configure calls do not carry the user's bearer verbatim, so an in-app
role re-check would wrongly reject them).

## 4. Runtime environment

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | (platform-injected) | Listen port. Local default `127.0.0.1:8443`. |
| `DRIVE_STATE_DIR` | `/data` on platform, `data-dev` locally | Objects + instance config (+ the SQLite file for local runs). |
| `DRIVE_DB_DSN` | set by the image entrypoint to the embedded PostgreSQL over a **Unix socket** on `/data` (`postgres:///drive?host=/data/pgsock`), no TCP listener | Index DSN; a `postgres://` value selects the Postgres dialect, anything else falls back to SQLite (local dev/tests). The socket lives on the per-app LUKS volume, so a co-located app sharing the host network namespace cannot reach the index. |
| `OIDC_ISSUER` | `https://privasys.id` | JWKS verifier issuer (offline, in-enclave). |
| `OIDC_AUDIENCE` | (unset) | Optional required `aud`. |
| `OIDC_REVOKED_URL` | `<issuer>/sessions/revoked` | Revoked-session feed; `off` disables. |
| `DRIVE_MEK_HEX` | (unset) | Test-only MEK override. Without it the service generates a random instance MEK on first boot and persists it on the sealed state dir. Per-tenant vault-held MEKs supersede both. |
| `DRIVE_MANIFEST_PATH` | `/privasys.json` | Manifest served at `GET /privasys.json`. |
| `PRIVASYS_APP_ID` / `PRIVASYS_CONTAINER_NAME` / `PRIVASYS_CONTAINER_TOKEN` | (manager-injected) | App identity for configure-authz, the config-complete self-recovery call, and the manager-minted attested identity used towards the control plane and other enclaves. |

## 5. Vault (key model)

Per-tenant MEKs are vault keys minted via grant-based `CreateKey` with
the tenant's privasys.id sub as the only owner principal, handle
`vault:apps.privasys.org/<app-id>/data/<tenant-ref>/mek/v1`
(the data-owner-key namespace). Sovereign instances mark them
exportable to the owner only. The key's policy pins the Drive image
digest: a redeploy with a new digest is refused by the vaults until the
owner has re-approved it (wallet sign-in for a sovereign user, the
`approve_org_mek_measurement` tool for an escrowed instance).

## 6. Object backend

Keys are per-tenant-prefixed (`t/<tenant_prefix>/...`) so one bucket
hosts many tenants; a backend only ever sees opaque AEAD ciphertext.

The **instance** backend is selected at configure time
(`object_backend`) or, for local runs, by `DRIVE_OBJECT_BACKEND`:

| Value | Env (local runs) | Notes |
|---|---|---|
| (unset) / `local` | `DRIVE_STATE_DIR` | Local disk under `<state>/objects` (dev default). |
| `gcs` | `DRIVE_GCS_BUCKET`, `DRIVE_GCS_KEY_FILE` | Google Cloud Storage with a sealed service-account key (the enclave cannot reach the metadata server, so application-default credentials do not apply). |
| `s3` | `DRIVE_S3_BUCKET`, `DRIVE_S3_REGION`, `DRIVE_S3_ENDPOINT` (empty for AWS), `DRIVE_S3_ACCESS_KEY`, `DRIVE_S3_SECRET_KEY` | AWS S3 / MinIO / R2 (any S3 API). |
| `ovh` | same `DRIVE_S3_*` with OVH's S3 endpoint (e.g. `https://s3.gra.io.cloud.ovh.net`) | OVH Object Storage via its S3-compatible API. |

Moving an instance from one bucket to another is a copy of opaque
ciphertext followed by a configure; keys never move.

A **tenant** can BYO its own bucket: it seals a cloud credential
(`gcs-sa-json`, `s3-keypair`, or `ovh-s3`) via the vault wrapped-secret
flow and sets it with `PUT /v1/tenants/{id}/bucket-cred`. Drive unwraps
it in-enclave and stores that tenant's chunks in their bucket, falling
back to the instance backend when unset.

## 7. Smoke test

```bash
DRIVE_URL=https://<app>.apps.privasys.org

curl -sS "$DRIVE_URL/status"          # state: awaiting_config | ready
privasys apps call privasys-drive my_drive --data '{}'
privasys apps call privasys-drive list_root --data '{"tenant_id":"..."}'
privasys attest privasys-drive
```
