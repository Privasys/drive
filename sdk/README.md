# `sdk/`: `@privasys/drive-sdk`

Tiny TypeScript client over the Privasys Drive REST API. Browser, Node
(≥20), and React Native compatible; uses `fetch` and Web Streams only.

```ts
import { PrivasysDrive } from "@privasys/drive-sdk";

const drive = PrivasysDrive.connect({
  baseUrl: "https://drive-demo.apps-test.privasys.org",
  token: idTokenFromWallet,
});

const me = await drive.createTenant({ name: "Bertrand" });
const node = await drive.uploadFile(me.id, "hello.txt", "hello drive", { mime: "text/plain" });

for (const child of await drive.listRoot(me.id)) {
  console.log(child.kind, child.name, child.size_bytes);
}

const zip = await drive.exportZip(me.id);
```

## Scripts

```bash
npm install
npm test           # node --test, no network
npm run build      # tsc → dist/
```

## Beyond the SDK

The SDK wraps the core REST surface. The filesystem-grade endpoints an
app or an agent uses to treat a folder as a disk (revisions and
`If-Match`, path addressing, append, byte ranges, the long-polling
change feed, `grep` / `glob`, `grants/mine`, quota breakdown, workspace
snapshots) are plain HTTP and are documented in
[docs/apps.md](../docs/apps.md); call them with the same bearer through
`fetch` until the SDK grows wrappers for them.
