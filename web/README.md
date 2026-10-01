# `web/`: the Drive UI

The web UI for **Privasys Drive** — a Google-Drive / SharePoint-style front for
the confidential Drive backend (an attested enclave app). Directories, files,
and per-file / per-folder permissioning, with everything sealed end-to-end from
the browser to the enclave.

## Architecture

- **Static Next.js export** (`output: 'export'`), built into the Drive image
  and served by the Drive service itself (`service/internal/api/webui.go`), so
  the page a user runs is covered by the enclave's attestation. Its paths are
  the only ones the image's `org.privasys.static-unsealed-prefixes` label lets
  the runtime serve in the clear.
- **Auth**: the Privasys wallet via `@privasys/auth` (copied provider from
  `chat.privasys.org`). Sign-in opts into the sealed session-relay flow with
  `sessionRelayHost` = the Drive enclave's platform host, so the wallet attests the
  Drive enclave's quote in the same ceremony.
- **Transport**: the browser talks to the Drive backend over a **sealed session**
  (`SealedSession.request`, CBOR-AES-GCM via `relay.privasys.org`). File bytes
  and metadata are sealed browser→enclave; the gateway only sees ciphertext.
  Drive authenticates the sealed session itself (the relay asserts the
  wallet-vouched `X-Privasys-Sub`), so no bearer travels in the clear.
- **API client**: `lib/drive-api.ts` maps the Drive REST surface
  (`/v1/...`) onto the sealed session.

## Permissioning

The UI exposes the Drive backend's three access layers:

- **Share with people** (Google-Drive style) — per-file and per-folder grants
  (`POST .../nodes/{id}/grants`, read or read+write), listed and revocable in the
  Share dialog. A folder share cascades to its subtree.
- **Folder ACL overrides** (SharePoint style) — narrow a folder subtree to a set
  of member roles (`PUT .../nodes/{id}/acl`), with inheritance; shown for
  enterprise workspaces.
- **Shared with me** — inbound shares across tenants (`GET /v1/shared`).

The Share dialog reads `GET /v1/tenants/{id}/nodes/{node}/permissions` (grants +
own ACL + effective ACL).

## Runtime config

Nothing per-environment is compiled in: one image runs on every platform. The
service writes `/privasys-config.js` (`window.__DRIVE_CFG__`) from the host
the gateway names it by, and the root layout loads it before the app's code
(`lib/runtime-config.ts`):

| Field | Source | Purpose |
|---|---|---|
| `appHost` | the request's Host (an alias domain is rewritten to the platform host by the gateway) | Drive enclave host the sealed session is attested against |
| `appId` | `PRIVASYS_APP_ID` from the runtime | the platform attestation report |
| `apiBase` | `*.apps.test.privasys.org` means the dev control plane, otherwise production; `DRIVE_UI_API_BASE` overrides | control plane: attestation, attribute prices, `/api/v1/me` |

## Develop

```bash
cd web
NODE_AUTH_TOKEN=<packages:read token> npm ci
NEXT_PUBLIC_DRIVE_APP_HOST=drive-demo.apps.test.privasys.org NEXT_PUBLIC_API_BASE_URL=https://api-test.developer.privasys.org NEXT_PUBLIC_DRIVE_APP_ID=02104572-ca2f-41e8-ae2d-24c0294e6f5e   npm run dev   # http://localhost:4215
npm test
```

The `NEXT_PUBLIC_*` variables only stand in for the runtime config under
`next dev`.

## Dependencies

Pinned exactly in `package.json` and `package-lock.json`: `@privasys/auth`,
`@privasys/ui` and `@privasys/attestation-view` from GitHub Packages, and
`@privasys/drive-client` from `../drive-client`. After changing a dependency,
run the **Web lockfile** workflow and commit the `package-lock.json` it
produces.

## Release

The UI ships with the service: a push to `main` builds one image holding both,
deployed like any Drive version. `drive.privasys.org` is an alias domain on the
Drive app, so it serves the same attested page.
