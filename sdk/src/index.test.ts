import { test } from "node:test";
import assert from "node:assert/strict";
import { PrivasysDrive, DriveError } from "./index.ts";

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function makeFakeFetch(handler: (r: Recorded) => Response | Promise<Response>): typeof fetch {
  return async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : input.toString();
    const body = init.body ? (typeof init.body === "string" ? init.body : await new Response(init.body).text()) : undefined;
    return handler({
      url,
      method: init.method ?? "GET",
      headers: Object.fromEntries(new Headers(init.headers).entries()),
      body,
    });
  };
}

test("createTenant posts JSON with bearer token", async () => {
  let captured: Recorded | undefined;
  const drive = PrivasysDrive.connect({
    baseUrl: "http://localhost:8443",
    token: "dev:user-1:b@p.org",
    fetch: makeFakeFetch((r) => {
      captured = r;
      return new Response(JSON.stringify({ id: "t1", kind: "user", name: "Bertrand", created_at: "2026-01-01T00:00:00Z" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    }),
  });
  const t = await drive.createTenant({ name: "Bertrand" });
  assert.equal(t.id, "t1");
  assert.equal(captured?.method, "POST");
  assert.equal(captured?.headers["authorization"], "Bearer dev:user-1:b@p.org");
  assert.deepEqual(JSON.parse(captured!.body!), { kind: "user", name: "Bertrand" });
});

test("downloadBytes returns the response body unchanged", async () => {
  const payload = new TextEncoder().encode("hello drive");
  const drive = PrivasysDrive.connect({
    baseUrl: "https://drive.example",
    token: "tok",
    fetch: makeFakeFetch(() => new Response(payload, { status: 200 })),
  });
  const got = await drive.downloadBytes("t1", "f1");
  assert.deepEqual(Array.from(got), Array.from(payload));
});

test("non-2xx responses raise DriveError", async () => {
  const drive = PrivasysDrive.connect({
    baseUrl: "https://drive.example",
    token: "tok",
    fetch: makeFakeFetch(() => new Response("forbidden\n", { status: 403 })),
  });
  await assert.rejects(() => drive.listRoot("t"), (err: unknown) => {
    assert.ok(err instanceof DriveError);
    assert.equal((err as DriveError).status, 403);
    return true;
  });
});

test("uploadFile encodes name + mime as query parameters", async () => {
  let captured: Recorded | undefined;
  const drive = PrivasysDrive.connect({
    baseUrl: "https://drive.example",
    token: "tok",
    fetch: makeFakeFetch((r) => {
      captured = r;
      return new Response(JSON.stringify({ id: "n1", tenant_id: "t1", kind: "file", name: "hello.txt", size_bytes: 11 }), {
        status: 201,
      });
    }),
  });
  const node = await drive.uploadFile("t1", "hello.txt", "hello drive", { mime: "text/plain" });
  assert.equal(node.name, "hello.txt");
  assert.match(captured!.url, /name=hello\.txt/);
  assert.match(captured!.url, /mime=text%2Fplain/);
  assert.equal(captured!.headers["content-type"], "text/plain");
});

test("listChanges builds the since/limit query", async () => {
  let captured: Recorded | undefined;
  const drive = PrivasysDrive.connect({
    baseUrl: "https://drive.example",
    token: "tok",
    fetch: makeFakeFetch((r) => {
      captured = r;
      return new Response("[]", { status: 200 });
    }),
  });
  await drive.listChanges("t1", 42, 10);
  assert.match(captured!.url, /since=42/);
  assert.match(captured!.url, /limit=10/);
});

test("createShareLink sends the chosen attributes and reports what they cost", async () => {
  let captured: Recorded | undefined;
  const drive = PrivasysDrive.connect({
    baseUrl: "https://drive.example",
    token: "tok",
    fetch: makeFakeFetch((r) => {
      captured = r;
      return new Response(JSON.stringify({
        id: "l1", secret: "s3cret", mode: "restricted", scope: ["read"], node_id: "n1",
        required_attributes: ["privasys:document_valid", "name"],
        paid_attributes: ["privasys:document_valid"],
        billing_state: "funded", billing_credits: 30,
      }), { status: 201 });
    }),
  });
  const link = await drive.createShareLink("t1", "n1", {
    mode: "restricted",
    requiredAttributes: ["document_valid", "name"],
  });
  assert.equal(link.billing_state, "funded");
  assert.equal(link.billing_credits, 30);
  assert.deepEqual(link.paid_attributes, ["privasys:document_valid"]);
  assert.deepEqual(JSON.parse(captured!.body!).required_attributes, ["document_valid", "name"]);
});

test("previewShareLink asks with the secret alone and yields the billing grant", async () => {
  let captured: Recorded | undefined;
  const preview = await PrivasysDrive.previewShareLink({
    baseUrl: "https://drive.example/",
    linkId: "l1",
    secret: "s3cret",
    fetch: makeFakeFetch((r) => {
      captured = r;
      return new Response(JSON.stringify({
        link_id: "l1", mode: "restricted",
        required_attributes: ["privasys:document_valid"],
        paid_attributes: ["privasys:document_valid"],
        billing_grant: "grant-1", billing_state: "funded",
      }), { status: 200 });
    }),
  });
  assert.equal(preview.billing_grant, "grant-1");
  // Token-less: the visitor has not signed in yet, which is the whole point.
  assert.equal(captured?.headers["authorization"], undefined);
  assert.equal(captured?.url, "https://drive.example/v1/links/l1/preview");
  assert.deepEqual(JSON.parse(captured!.body!), { secret: "s3cret" });
});

test("quoteAttributes prices the set before the share exists", async () => {
  let captured: Recorded | undefined;
  const drive = PrivasysDrive.connect({
    baseUrl: "https://drive.example",
    token: "tok",
    fetch: makeFakeFetch((r) => {
      captured = r;
      return new Response(JSON.stringify({
        attributes: [{ key: "privasys:document_valid", namespace: "privasys", assurance: "gov", price_credits: 30 }],
        total_credits: 30,
      }), { status: 200 });
    }),
  });
  const quote = await drive.quoteAttributes(["privasys:document_valid"]);
  assert.equal(quote.total_credits, 30);
  assert.equal(captured?.url, "https://drive.example/v1/attributes/quote");
  assert.equal(captured?.headers["authorization"], "Bearer tok");
});

test("setupPersonalDrive chains tenant, grant fetch and key provisioning", async () => {
  const calls: string[] = [];
  const drive = PrivasysDrive.connect({
    baseUrl: "https://drive.example",
    token: "tok",
    fetch: makeFakeFetch((r) => {
      calls.push(r.url);
      if (r.url.endsWith("/v1/me/tenant")) {
        return new Response(JSON.stringify({ ID: "t1", Kind: "user", Name: "me" }), { status: 201 });
      }
      if (r.url.includes("/data-keys/grant")) {
        assert.equal(r.headers["authorization"], "Bearer tok");
        return new Response(JSON.stringify({
          grant: "g",
          handle_hint: "apps.privasys.org/x/data/y/mek/v1",
          attestation_token: "at",
          constellation: { endpoints: ["v1:1"], mrenclave: "00", attestation_server: "as", threshold: 1 },
        }), { status: 201 });
      }
      if (r.url.endsWith("/v1/me/tenant/key")) {
        const body = JSON.parse(String(r.body));
        assert.equal(body.grant, "g");
        assert.equal(body.handle, "apps.privasys.org/x/data/y/mek/v1");
        assert.equal(body.constellation.threshold, 1);
        return new Response(JSON.stringify({ status: "provisioned", handle: body.handle }), { status: 201 });
      }
      throw new Error("unexpected url " + r.url);
    }),
  });
  const out = await drive.setupPersonalDrive({ mgmtBaseUrl: "https://mgmt.example/", appId: "app-1" });
  assert.equal(out.key.status, "provisioned");
  assert.equal(calls.length, 3);
  assert.match(calls[1], /mgmt\.example\/api\/v1\/apps\/app-1\/data-keys\/grant/);
});
