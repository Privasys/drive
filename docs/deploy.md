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
privasys apps create privasys-drive \
  --image ghcr.io/privasys/drive@sha256:<digest> \
  --container-storage
privasys apps deploy privasys-drive --watch
```

Note: a package/prebuilt app's capabilities are read from the image label
at app creation, so pushing a new manifest means a new image digest and a
new version.

## 2. Platform contract

The service follows the app-capabilities contract:

- Listens on the manager-injected `$PORT` (never 8080, which is reserved).
- `container_storage: true` gives it the sealed per-app `/data` LUKS
  volume; the index (embedded PostgreSQL at `/data/pgdata`), object store
  (`/data/objects/`) and instance config (`/data/config.json`) live
  there. The volume's DEK is vault-backed and measurement-gated; an
  enclave-os or image upgrade requires the app owner to stage + promote
  the new measurement (WebAuthn step-up).
- Configure-then-freeze: the manager 503-gates the app until the first
  successful `POST /configure`. On restart the service re-applies the
  persisted config and calls the manager's `config-complete` itself; no
  owner is needed after the one-time setup.
- `/health` is process liveness (always 200; the manager's container
  health check probes it). `readiness_path: /readiness` (503 until
  configured), `status_path: /status` (state/activity/message document
  for the portal).

## 3. Configuration (the `configure` tool)

One required field: the **operating mode**, immutable once set and part
of the attested configuration.

| Field | Values | Meaning |
|---|---|---|
| `mode` | `sovereign` | Only tenants can unlock their data; the operator holds no key and no unlock path. The Privasys public instance runs this. |
| | `escrowed` | Tenant keys carry an escrow wrap under the org master key (`MEK_org`); every escrow is disclosed to the tenant via the audit log. Escrowed setup needs `org_mek_ref` (the `MEK_org` vault reference, a RawShare the org created) + `recovery` (`{issuer, quorum, approvers?, disclose}`), sent via the API/CLI (not the portal form). Escrow-wrap and disclosure are active; the audited `recover_tenant` enforcement gate ships next (`POST /v1/tenants/{id}/recover` returns 501 until then). |
| `quota_default_bytes` | integer | Per-tenant storage ceiling in bytes, enforced on upload (0 = unlimited). `GET /v1/tenants/{id}/quota` reports usage. |
| `mgmt_base_url` | URL | Control-plane API base (e.g. `https://api.developer.privasys.org`). When set, the instance refreshes stale vault attestation tokens itself: it mints a challenge-bound app identity via the in-TD manager and asks the control plane's app-identity gate for a fresh token, so file operations self-heal after idle instead of returning `409 vault_key_stale` until the owner (or the `rearm_tenant_key` tool) re-arms. Mutable. |

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
| `DRIVE_DB_DSN` | set by the image entrypoint to the embedded PostgreSQL (`/data/pgdata`, loopback only) | Index DSN; a `postgres://` value selects the Postgres dialect, anything else falls back to SQLite (local dev/tests). |
| `OIDC_ISSUER` | `https://privasys.id` | JWKS verifier issuer (offline, in-enclave). |
| `OIDC_AUDIENCE` | (unset) | Optional required `aud`. |
| `OIDC_REVOKED_URL` | `<issuer>/sessions/revoked` | Revoked-session feed; `off` disables. |
| `DRIVE_MEK_HEX` | (unset) | Test-only MEK override. Without it the service generates a random instance MEK on first boot and persists it on the sealed state dir. Per-tenant vault-held MEKs supersede both. |
| `DRIVE_MANIFEST_PATH` | `/privasys.json` | Manifest served at `GET /privasys.json`. |
| `PRIVASYS_APP_ID` / `PRIVASYS_CONTAINER_NAME` / `PRIVASYS_CONTAINER_TOKEN` | (manager-injected) | App identity for configure-authz + the config-complete self-recovery call. |

## 5. Vault (target key model)

Per-tenant MEKs are vault keys minted via grant-based `CreateKey` with
the tenant's privasys.id sub as the only owner principal, handle
`vault:apps.privasys.org/<app-id>/data/<tenant-ref>/mek/v1`
(the data-owner-key namespace). Sovereign instances mark them
exportable to the owner only. Not wired in this build; the interim is a
random instance MEK generated on first boot and persisted on the sealed
state dir (protected by the platform's vault-backed volume DEK).

## 6. Object backend

Keys are per-tenant-prefixed (`t/<tenant_prefix>/...`) so one bucket
hosts many tenants; a backend only ever sees opaque AEAD ciphertext.

The **instance** backend is selected by `DRIVE_OBJECT_BACKEND`:

| Value | Env | Notes |
|---|---|---|
| (unset) / `local` | `DRIVE_STATE_DIR` | Local disk under `<state>/objects` (dev default). |
| `gcs` | `DRIVE_GCS_BUCKET`, `DRIVE_GCS_KEY_FILE` (or ADC) | Google Cloud Storage. |
| `s3` | `DRIVE_S3_BUCKET`, `DRIVE_S3_REGION`, `DRIVE_S3_ENDPOINT` (empty for AWS), `DRIVE_S3_ACCESS_KEY`, `DRIVE_S3_SECRET_KEY` | AWS S3 / MinIO / R2 (any S3 API). |
| `ovh` | same `DRIVE_S3_*` with OVH's S3 endpoint (e.g. `https://s3.gra.io.cloud.ovh.net`) | OVH Object Storage via its S3-compatible API. |

A **tenant** can BYO its own bucket: it seals a cloud credential
(`gcs-sa-json`, `s3-keypair`, or `ovh-s3`) via the vault wrapped-secret
flow and sets it with `PUT /v1/tenants/{id}/bucket-cred`. Drive unwraps
it in-enclave and stores that tenant's chunks in their bucket, falling
back to the instance backend when unset.

## 7. Smoke test

```bash
DRIVE_URL=https://drive-demo.apps-test.privasys.org

curl -sS "$DRIVE_URL/status"          # state: awaiting_config | ready
curl -sS "$DRIVE_URL/v1/healthz"      # process liveness
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "$DRIVE_URL/tools/list_root" -d '{"tenant_id":"..."}'
```
