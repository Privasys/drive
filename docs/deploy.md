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
  volume; the index DB (`/data/drive.db`), object store
  (`/data/objects/`) and instance config (`/data/config.json`) live
  there. The volume's DEK is vault-backed and measurement-gated; an
  enclave-os or image upgrade requires the app owner to stage + promote
  the new measurement (WebAuthn step-up).
- Configure-then-freeze: the manager 503-gates the app until the first
  successful `POST /configure`. On restart the service re-applies the
  persisted config and calls the manager's `config-complete` itself; no
  owner is needed after the one-time setup.
- `readiness_path: /health` (503 until configured), `status_path:
  /status` (state/activity/message document for the portal).

## 3. Configuration (the `configure` tool)

One required field: the **operating mode**, immutable once set and part
of the attested configuration.

| Field | Values | Meaning |
|---|---|---|
| `mode` | `sovereign` | Only tenants can unlock their data; the operator holds no key and no unlock path. The Privasys public instance runs this. |
| | `escrowed` | Tenant keys carry an escrow wrap under the org master key (`MEK_org`); recovery is policy-gated and audited. Requires the org key ceremony, which has not shipped yet; rejected by this build. |
| `quota_default_bytes` | integer | Default per-tenant quota; 0 = unlimited. |

Configure via the portal Configure tab, or over RA-TLS:
`privasys apps configure privasys-drive --set mode=sovereign`.

Privileged calls are additionally checked in-app against the
configure-authz roles (`privasys-platform:app:<app-id-hex>:owner|admin`).

## 4. Runtime environment

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | (platform-injected) | Listen port. Local default `127.0.0.1:8443`. |
| `DRIVE_STATE_DIR` | `/data` on platform, `data-dev` locally | Index DB + objects + config. |
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

The v1 backend is the sealed local volume (`/data/objects`). Cloud
backends (GCS first: bucket pattern `privasys-drive-<env>-<region>`,
per-tenant prefixes `t/<tenant_prefix>/...`) land in Phase 3.

## 7. Smoke test

```bash
DRIVE_URL=https://drive-demo.apps-test.privasys.org

curl -sS "$DRIVE_URL/status"          # state: awaiting_config | ready
curl -sS "$DRIVE_URL/v1/healthz"      # process liveness
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "$DRIVE_URL/tools/list_root" -d '{"tenant_id":"..."}'
```
