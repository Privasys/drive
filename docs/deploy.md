# Deploying Privasys Drive

This document describes how the production Drive enclave is deployed.

## 1. Image

Each push to `main` produces a reproducible image tagged
`ghcr.io/privasys/drive:<sha>` (and `:latest`). Operators pin the
`@sha256:...` digest in the Enclave OS Virtual workload manifest.

```bash
gh release download <tag> --repo Privasys/drive
docker pull ghcr.io/privasys/drive:<sha>
```

## 2. Confidential VM

Drive runs as a workload inside Enclave OS Virtual on a TDX-capable
host. The VM disk is LUKS-encrypted and the Postgres data directory
sits on a dedicated LV mounted under `/var/lib/postgresql/17/main`.

The container app manifest looks like:

```yaml
name: drive
image: ghcr.io/privasys/drive@sha256:<digest>
ports:
  - 8443
volumes:
  - name: pgdata
    path: /var/lib/postgresql/17/main
    luks: true
env:
  DRIVE_DB_DSN: "postgres://drive:..."
  DRIVE_OBJECT_BACKEND: "gcs"
  DRIVE_GCS_BUCKET: "privasys-drive-prod-europe-west9"
  DRIVE_OIDC_ISSUER: "https://privasys.id"
  DRIVE_OIDC_AUDIENCE: "privasys-drive"
ra_tls:
  oid_extensions:
    - "1.3.6.1.4.1.55720.1"  # MRTD measurement
```

## 3. Vault

Each tenant's MEK is reconstructed on demand from a 2-of-4 RawShare
held by the SGX vault constellation under
`vault:drive/<tenant_id>/mek/v1`. The wallet's RA-TLS handshake to
the vault grants a short-lived authorisation header that the Drive
enclave includes when pulling the share.

## 4. Object backend

In production the GCS bucket pattern is:

```
privasys-drive-<env>-<region>
e.g. privasys-drive-prod-europe-west9
```

Per-tenant prefixes (`t/<tenant_prefix>/...`) keep one bucket safe for
many tenants; per-region buckets keep data residency simple.

## 5. Smoke test

```bash
DRIVE_URL=https://drive-demo.apps-test.privasys.org
TOKEN=$(privasys-id login --audience privasys-drive)

curl -sS -H "Authorization: Bearer $TOKEN" "$DRIVE_URL/v1/healthz"
```
