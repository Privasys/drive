/**
 * Privasys Drive SDK — minimal client for the REST surface.
 *
 * Browser- and Node-compatible (uses `fetch` + Web Streams). React Native
 * is supported via the polyfilled `fetch` shipped by `expo`.
 */

export type TenantKind = "user" | "enterprise";

export interface Tenant {
  id: string;
  kind: TenantKind;
  name: string;
  created_at: string;
}

export interface DriveNode {
  id: string;
  tenant_id: string;
  parent_id?: string;
  kind: "folder" | "file";
  name: string;
  mime_hint?: string;
  size_bytes: number;
  merkle_root_hex?: string;
  manifest_ref?: string;
}

export interface DriveChange {
  Seq: number;
  TenantID: string;
  NodeID: string;
  Op: string;
  Actor: string;
  At: string;
}

export interface Me {
  sub: string;
  email?: string;
  tenants: { id: string; kind: TenantKind; name: string; role: string }[];
}

/** One attribute a sharer may require, as published by its provider. */
export interface AttributeCatalogueEntry {
  /** Namespaced key (`privasys:document_valid`), as the reservation expects it. */
  key: string;
  namespace: string;
  name: string;
  /** `gov` attributes are proven against a credential; `self` are asserted. */
  assurance: string;
  price_credits: number;
  description?: string;
}

export interface AttributeQuoteLine {
  key: string;
  namespace: string;
  assurance: string;
  price_credits: number;
}

export interface AttributeQuote {
  attributes: AttributeQuoteLine[];
  total_credits: number;
}

/**
 * Billing state of a share link: `funded` (a grant is armed for the next
 * recipient), `free` (the chosen attributes disclose at no charge),
 * `expired` (the grant lapsed before anyone opened the link) or
 * `unavailable` (nobody could be billed here, so the attributes stay
 * self-asserted).
 */
export type ShareLinkBillingState = "funded" | "free" | "expired" | "unavailable";

export interface ShareLinkBilling {
  link_id: string;
  billing_state: ShareLinkBillingState;
  billing_credits: number;
  billing_grant_expires_at?: string;
  paid_attributes?: string[];
}

export interface ShareLink {
  id: string;
  /** Returned exactly once; it lives in the link's URL fragment. */
  secret: string;
  mode: "open" | "restricted";
  scope: string[];
  node_id: string;
  required_attributes?: string[];
  expires_at?: string;
  /** The subset the sharer is paying to have proven. */
  paid_attributes?: string[];
  billing_state?: ShareLinkBillingState;
  billing_credits?: number;
  billing_grant_expires_at?: string;
}

export interface ShareLinkPreview {
  link_id: string;
  mode: "open" | "restricted";
  required_attributes?: string[];
  paid_attributes?: string[];
  /** Present only while a grant is armed; carry it into `/authorize`. */
  billing_grant?: string;
  billing_state?: ShareLinkBillingState;
  billing_grant_expires_at?: string;
}

export interface ConnectOptions {
  baseUrl: string;
  token: string;
  /** Override the global fetch (e.g. to inject a polyfill). */
  fetch?: typeof fetch;
}

export class DriveError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "DriveError";
  }
}

export class PrivasysDrive {
  readonly baseUrl: string;
  readonly token: string;
  private readonly fetcher: typeof fetch;

  constructor(opts: ConnectOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.token = opts.token;
    this.fetcher = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Convenience constructor; mirrors the wallet API from §5.3 of the design. */
  static connect(opts: ConnectOptions): PrivasysDrive {
    return new PrivasysDrive(opts);
  }

  // --- identity + tenants --------------------------------------------

  /** The caller's identity and tenant memberships. */
  async me(): Promise<Me> {
    return this.req<Me>("GET", "/v1/me");
  }

  /**
   * Get or create the caller's personal tenant. Idempotent: the first
   * call after login creates it, later calls return the same tenant.
   * This is the wallet's entry point into the user's drive.
   */
  async ensurePersonalTenant(): Promise<Tenant> {
    return this.req<Tenant>("POST", "/v1/me/tenant");
  }

  /**
   * Provision (or re-arm after a restart) the personal tenant's
   * vault-held MEK. Pass the bundle from the control plane's
   * POST /api/v1/apps/{id}/data-keys/grant response; the enclave
   * generates the key and splits it across the constellation. Later
   * calls just refresh the attestation token and warm the key cache.
   */
  async provisionTenantKey(bundle: {
    grant?: string;
    handle?: string;
    attestation_token?: string;
    constellation?: {
      endpoints: string[];
      mrenclave: string;
      attestation_server: string;
      threshold: number;
    };
  }): Promise<{ status: string; handle: string }> {
    return this.req("POST", "/v1/me/tenant/key", JSON.stringify(bundle), "application/json");
  }

  /**
   * One-call login setup: ensure the personal tenant exists, fetch a
   * data-key grant from the control plane (the caller's own sub becomes
   * the vault key owner), and provision or re-arm the tenant's
   * vault-held MEK on the Drive enclave. The wallet calls this once
   * after each login; it is idempotent.
   */
  async setupPersonalDrive(opts: { mgmtBaseUrl: string; appId: string }): Promise<{
    tenant: Tenant;
    key: { status: string; handle: string };
  }> {
    const tenant = await this.ensurePersonalTenant();
    const res = await this.fetcher(
      `${opts.mgmtBaseUrl.replace(/\/$/, "")}/api/v1/apps/${enc(opts.appId)}/data-keys/grant`,
      { method: "POST", headers: { Authorization: `Bearer ${this.token}` } },
    );
    if (!res.ok) throw await asError(res);
    const bundle = (await res.json()) as {
      grant: string;
      handle_hint: string;
      attestation_token?: string;
      constellation: {
        endpoints: string[];
        mrenclave: string;
        attestation_server: string;
        threshold: number;
      };
    };
    const key = await this.provisionTenantKey({
      grant: bundle.grant,
      handle: bundle.handle_hint,
      attestation_token: bundle.attestation_token,
      constellation: bundle.constellation,
    });
    return { tenant, key };
  }

  async createTenant(input: { kind?: TenantKind; name: string }): Promise<Tenant> {
    return this.req<Tenant>("POST", "/v1/tenants", JSON.stringify({ kind: input.kind ?? "user", name: input.name }), "application/json");
  }

  async addMember(tenantId: string, userSub: string, role: "owner" | "admin" | "contributor" | "reader"): Promise<void> {
    await this.req<void>("POST", `/v1/tenants/${enc(tenantId)}/members`, JSON.stringify({ user_sub: userSub, role }), "application/json");
  }

  // --- folders + files ----------------------------------------------

  async listRoot(tenantId: string): Promise<DriveNode[]> {
    return this.req<DriveNode[]>("GET", `/v1/tenants/${enc(tenantId)}/root`);
  }

  async listFolder(tenantId: string, folderId: string): Promise<DriveNode[]> {
    return this.req<DriveNode[]>("GET", `/v1/tenants/${enc(tenantId)}/folders/${enc(folderId)}`);
  }

  async createFolder(tenantId: string, name: string, parentId?: string): Promise<DriveNode> {
    const body = JSON.stringify({ name, parent_id: parentId ?? "" });
    return this.req<DriveNode>("POST", `/v1/tenants/${enc(tenantId)}/folders`, body, "application/json");
  }

  /** Upload a file. `body` may be a string, ArrayBuffer, Blob, or ReadableStream. */
  async uploadFile(
    tenantId: string,
    name: string,
    body: BodyInit,
    opts: { parentId?: string; mime?: string } = {},
  ): Promise<DriveNode> {
    const qs = new URLSearchParams({ name });
    if (opts.parentId) qs.set("parent_id", opts.parentId);
    if (opts.mime) qs.set("mime", opts.mime);
    return this.req<DriveNode>("POST", `/v1/tenants/${enc(tenantId)}/files?${qs.toString()}`, body, opts.mime ?? "application/octet-stream");
  }

  /** Download a file as bytes. */
  async downloadBytes(tenantId: string, fileId: string): Promise<Uint8Array> {
    const res = await this.raw("GET", `/v1/tenants/${enc(tenantId)}/files/${enc(fileId)}`);
    if (!res.ok) throw await asError(res);
    const buf = await res.arrayBuffer();
    return new Uint8Array(buf);
  }

  /** Download a file as a stream. */
  async downloadStream(tenantId: string, fileId: string): Promise<ReadableStream<Uint8Array>> {
    const res = await this.raw("GET", `/v1/tenants/${enc(tenantId)}/files/${enc(fileId)}`);
    if (!res.ok) throw await asError(res);
    if (!res.body) throw new DriveError(500, "missing response body");
    return res.body as ReadableStream<Uint8Array>;
  }

  async deleteNode(tenantId: string, nodeId: string): Promise<void> {
    await this.req<void>("DELETE", `/v1/tenants/${enc(tenantId)}/nodes/${enc(nodeId)}`);
  }

  // --- sharing -------------------------------------------------------

  async createGrant(tenantId: string, nodeId: string, params: {
    subject: string;
    scope: string[];
    bindingPubkey?: string;
    expiresUnix?: number;
    meta?: string;
  }): Promise<unknown> {
    const body = JSON.stringify({
      subject: params.subject,
      scope: params.scope,
      binding_pubkey: params.bindingPubkey,
      expires_unix: params.expiresUnix,
      meta: params.meta,
    });
    return this.req<unknown>("POST", `/v1/tenants/${enc(tenantId)}/nodes/${enc(nodeId)}/grants`, body, "application/json");
  }

  async revokeGrant(tenantId: string, grantId: string): Promise<void> {
    await this.req<void>("DELETE", `/v1/tenants/${enc(tenantId)}/grants/${enc(grantId)}`);
  }

  // --- attribute-gated share links -----------------------------------

  /**
   * The attributes a sharer may require of a recipient, priced. Read
   * live from the platform marketplace, so an attribute published by a
   * new provider is offerable without an SDK release.
   */
  async attributeCatalogue(): Promise<AttributeCatalogueEntry[]> {
    const res = await this.req<{ attributes: AttributeCatalogueEntry[] }>("GET", "/v1/attributes");
    return res.attributes;
  }

  /**
   * What a chosen set costs, before the share exists. Show this to the
   * sharer: under "the inviter pays" it is their own credits that fund
   * the recipient's disclosure.
   */
  async quoteAttributes(keys: string[]): Promise<AttributeQuote> {
    return this.req<AttributeQuote>("POST", "/v1/attributes/quote", JSON.stringify({ attributes: keys }), "application/json");
  }

  /**
   * Mint a share link. `requiredAttributes` takes catalogue keys
   * (`privasys:document_valid`) or bare names; the priced ones come back
   * in `paid_attributes` with a billing grant charged to the caller.
   */
  async createShareLink(tenantId: string, nodeId: string, params: {
    mode?: "open" | "restricted";
    scope?: string[];
    requiredAttributes?: string[];
    expiresUnix?: number;
    label?: string;
  } = {}): Promise<ShareLink> {
    const body = JSON.stringify({
      mode: params.mode ?? "open",
      scope: params.scope ?? ["read"],
      required_attributes: params.requiredAttributes ?? [],
      expires_unix: params.expiresUnix,
      label: params.label,
    });
    return this.req<ShareLink>("POST", `/v1/tenants/${enc(tenantId)}/nodes/${enc(nodeId)}/links`, body, "application/json");
  }

  /**
   * Fund the NEXT recipient of a link. A billing grant is single-use, so
   * a link handed to a second person needs a second grant, charged to
   * the caller like the first.
   */
  async rearmShareLinkBilling(tenantId: string, linkId: string): Promise<ShareLinkBilling> {
    return this.req<ShareLinkBilling>("POST", `/v1/tenants/${enc(tenantId)}/links/${enc(linkId)}/billing-grant`);
  }

  /**
   * What a visitor must prove to open a link, and the billing grant that
   * pays for proving it. Static and token-less on purpose: the caller
   * needs `billing_grant` to build the sign-in that would authenticate
   * them, and the answer is gated on the link secret alone.
   *
   * Pass `billing_grant` to the IdP as the `billing_grant` query
   * parameter on `/authorize`. That is what moves the charge from the
   * OAuth client's owner to the person who shared the document. A
   * `billing_state` other than `"funded"` means no grant is armed and
   * the sharer has to re-arm the link.
   */
  static async previewShareLink(opts: {
    baseUrl: string;
    linkId: string;
    secret: string;
    fetch?: typeof fetch;
  }): Promise<ShareLinkPreview> {
    const fetcher = opts.fetch ?? globalThis.fetch.bind(globalThis);
    const res = await fetcher(`${opts.baseUrl.replace(/\/$/, "")}/v1/links/${enc(opts.linkId)}/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: opts.secret }),
    });
    if (!res.ok) throw await asError(res);
    return (await res.json()) as ShareLinkPreview;
  }

  // --- change feed + GDPR export ------------------------------------

  async listChanges(tenantId: string, since = 0, limit = 100): Promise<DriveChange[]> {
    const qs = new URLSearchParams({ since: String(since), limit: String(limit) });
    return this.req<DriveChange[]>("GET", `/v1/tenants/${enc(tenantId)}/changes?${qs.toString()}`);
  }

  async exportZip(tenantId: string, mode: "plaintext" | "ciphertext" = "plaintext"): Promise<Uint8Array> {
    const res = await this.raw("POST", `/v1/tenants/${enc(tenantId)}/exports`, JSON.stringify({ mode }), "application/json");
    if (!res.ok) throw await asError(res);
    return new Uint8Array(await res.arrayBuffer());
  }

  // --- internal ------------------------------------------------------

  private async raw(method: string, path: string, body?: BodyInit, contentType?: string): Promise<Response> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    if (contentType) headers["Content-Type"] = contentType;
    return await this.fetcher(`${this.baseUrl}${path}`, { method, headers, body });
  }

  private async req<T>(method: string, path: string, body?: BodyInit, contentType?: string): Promise<T> {
    const res = await this.raw(method, path, body, contentType);
    if (!res.ok) throw await asError(res);
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }
}

function enc(s: string): string { return encodeURIComponent(s); }

async function asError(res: Response): Promise<DriveError> {
  let msg = res.statusText;
  try { msg = (await res.text()) || msg; } catch { /* ignore */ }
  return new DriveError(res.status, msg);
}
