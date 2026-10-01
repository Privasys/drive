// Client for the Privasys Drive enclave backend.
//
// The browser reaches Drive over a DEDICATED SEALED SESSION (PrivasysSession
// from @privasys/auth) - never plain fetch. File bytes and metadata are
// sealed browser->enclave (CBOR-AES-GCM); the gateway only ever sees
// ciphertext. Drive authenticates the sealed session itself: the enclave
// relay asserts the wallet-vouched sub (X-Privasys-Sub) toward the app, so
// no bearer travels in the clear. Mirrors chat's lib/chat-service-api.ts.

import type { SealedSession } from '@privasys/auth';
import {
    DriveError,
    driveHostFromEnv,
    json,
    ok,
    decodeError,
    timed,
    uploadFile,
    uploadFileStreaming,
    STREAM_THRESHOLD,
    REQUEST_TIMEOUT_MS,
    TRANSFER_TIMEOUT_MS
} from '@privasys/drive-client';
import { RUNTIME } from './runtime-config';

// The sealed-transport core and the file-upload helpers live in the shared
// @privasys/drive-client lib, consumed by chat.privasys.org too so they never
// drift. Re-exported here so this app's components keep importing them from
// `../lib/drive-api` unchanged.
export { DriveError, uploadFile, uploadFileStreaming, STREAM_THRESHOLD };

/** Bare host of the Drive enclave backend (no scheme), or '' when unset. */
export function driveHost(): string {
    return driveHostFromEnv(RUNTIME.appHost);
}

/** The Drive backend's operating status, including the build it is running. */
export interface DriveStatus {
    state: string; // 'ready' | 'awaiting_config' | ...
    activity?: string;
    message?: string;
    mode?: string; // 'sovereign' | 'escrowed'
    version?: string; // backend commit / build id
}

/** Read the backend's /status over the sealed session (build id + mode). */
export function getStatus(session: SealedSession): Promise<DriveStatus> {
    return json<DriveStatus>(session, 'GET', '/status');
}

export type NodeKind = 'folder' | 'file';

export interface DriveNode {
    id: string;
    tenant_id: string;
    parent_id?: string;
    kind: NodeKind;
    name: string;
    mime_hint?: string;
    size_bytes: number;
    merkle_root_hex?: string;
    manifest_ref?: string;
    /** Semantic-index state: '' | pending | processing | indexed | skipped | failed | excluded. */
    index_status?: string;
    /** Embedding progress while `processing`: chunks embedded of the total
     *  (0/0 until known). Drives the per-file progress indicator. */
    index_chunks_done?: number;
    index_chunks_total?: number;
    /** Creator's sub (Owner column). */
    created_by?: string;
    /** RFC3339 (Modified column). */
    updated_at?: string;
    /** The node's revision: what to send back as the If-Match fence on a
     *  conditional write, so a save cannot clobber a concurrent writer. */
    rev?: number;
    /** Set on a folder that holds a workspace snapshot (`.workspace.json`
     *  beside `.blobs/`): the manifest file id. Rendered as one item. */
    workspace_manifest_id?: string;
    /**
     * Somebody else can currently reach this node: an active grant sits on
     * it (a share link, a named recipient, an app). Counts grants on the
     * node ITSELF, so the mark says "this is the thing that was shared"
     * rather than "something above this was".
     */
    shared?: boolean;
}

export type TenantKind = 'user' | 'enterprise';
export type MemberRole = 'owner' | 'admin' | 'contributor' | 'reader' | string;

export interface Tenant {
    id: string;
    kind: TenantKind;
    name: string;
    role?: MemberRole;
}

export interface Me {
    sub: string;
    email?: string;
    tenants: Tenant[];
}

export type Scope = 'read' | 'write' | 'share' | 'delete';

export interface GrantView {
    id: string;
    subject: string; // "subject:<sub>" | "link" | "app:<mrtd>"
    scope: Scope[];
    created_by: string;
    expires_at?: string;
    revoked: boolean;
}

export interface NodePermissions {
    node: { id: string; name: string; kind: NodeKind; parent_id: string };
    grants: GrantView[];
    acl_override: string[] | null; // this node's own folder ACL, or null (inherits)
    effective_acl: string[] | null; // nearest-ancestor override in force, or null
}

export interface SharedItem {
    grant_id: string;
    tenant_id: string;
    node_id: string;
    name: string;
    kind: NodeKind;
    scope: string;
    shared_by: string;
    size_bytes: number;
}

// ---- Identity + workspace --------------------------------------------

export function getMe(session: SealedSession): Promise<Me> {
    return json<Me>(session, 'GET', '/v1/me');
}

/** Get-or-create the caller's personal drive (User tenant). Idempotent. */
export function ensurePersonalTenant(session: SealedSession): Promise<Tenant> {
    return json<Tenant>(session, 'POST', '/v1/me/tenant');
}

// ---- Workspaces (enterprise tenants) ---------------------------------

export interface Member {
    sub: string;
    role: MemberRole;
}

/** Create an enterprise workspace; the caller becomes its owner. */
export function createWorkspace(session: SealedSession, name: string): Promise<Tenant> {
    return json<Tenant>(session, 'POST', '/v1/tenants', { kind: 'enterprise', name });
}

export async function listMembers(session: SealedSession, tenantID: string): Promise<Member[]> {
    const data = await json<{ members: Member[] }>(
        session,
        'GET',
        `/v1/tenants/${tenantID}/members`
    );
    return data.members ?? [];
}

/** Add a member by their Privasys ID sub (upserts the role). */
export async function addMember(
    session: SealedSession,
    tenantID: string,
    sub: string,
    role: MemberRole
): Promise<void> {
    const res = await timed(
        session,
        'POST',
        `/v1/tenants/${tenantID}/members`,
        { user_sub: sub, role },
        REQUEST_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
}

export async function setMemberRole(
    session: SealedSession,
    tenantID: string,
    sub: string,
    role: MemberRole
): Promise<void> {
    const res = await timed(
        session,
        'PATCH',
        `/v1/tenants/${tenantID}/members/${encodeURIComponent(sub)}`,
        { role },
        REQUEST_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
}

export async function removeMember(
    session: SealedSession,
    tenantID: string,
    sub: string
): Promise<void> {
    const res = await timed(
        session,
        'DELETE',
        `/v1/tenants/${tenantID}/members/${encodeURIComponent(sub)}`,
        undefined,
        REQUEST_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
}

// ---- Browse ----------------------------------------------------------

/** List a folder's children; pass null/'' for the tenant root. */
export function listChildren(
    session: SealedSession,
    tenantID: string,
    folderID: string | null
): Promise<DriveNode[]> {
    const path = folderID
        ? `/v1/tenants/${tenantID}/folders/${folderID}`
        : `/v1/tenants/${tenantID}/root`;
    return json<DriveNode[]>(session, 'GET', path);
}

export function createFolder(
    session: SealedSession,
    tenantID: string,
    parentID: string | null,
    name: string
): Promise<DriveNode> {
    return json<DriveNode>(session, 'POST', `/v1/tenants/${tenantID}/folders`, {
        parent_id: parentID ?? '',
        name
    });
}

/** Download a file's plaintext bytes (decrypted inside the enclave). */
export async function downloadFile(
    session: SealedSession,
    tenantID: string,
    fileID: string
): Promise<Uint8Array> {
    const res = await timed(
        session,
        'GET',
        `/v1/tenants/${tenantID}/files/${fileID}`,
        undefined,
        TRANSFER_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
    return res.body ?? new Uint8Array(0);
}

/**
 * Delete a node, and for a folder everything beneath it.
 *
 * This runs on the transfer timeout, not the request one: deleting a folder
 * is a single call inside which the service reclaims the sealed blobs of
 * every file in the subtree, so a large folder takes transfer-scale time.
 * On the shorter budget the browser gave up at 30s and reported a failure
 * while the enclave went on to finish the delete.
 */
export async function deleteNode(
    session: SealedSession,
    tenantID: string,
    nodeID: string
): Promise<void> {
    const res = await timed(session, 'DELETE', `/v1/tenants/${tenantID}/nodes/${nodeID}`, undefined, TRANSFER_TIMEOUT_MS);
    if (!ok(res)) throw decodeError(res);
}

/** What a node holds, the node itself included: a file is one file. */
export interface SubtreeStats {
    files: number;
    folders: number;
    bytes: number;
}

/**
 * Ask what a node holds before acting on it. Used to say how big a delete
 * is before starting it, the file count being what predicts the wait: the
 * service reclaims a sealed blob per file, so a thousand small files take
 * far longer than one large one.
 */
export function subtreeStats(
    session: SealedSession,
    tenantID: string,
    nodeID: string
): Promise<SubtreeStats> {
    return json<SubtreeStats>(session, 'GET', `/v1/tenants/${tenantID}/nodes/${nodeID}/subtree`);
}

// ---- Semantic search ---------------------------------------------------

export interface SearchHit {
    node_id: string;
    name: string;
    mime_hint?: string;
    /** Stable content-derived section anchor, safe to store in a citation. */
    section_id?: string;
    /** Title chain from the document root ("Report" › "Results" › …). */
    section_path?: string[];
    chunk_index: number;
    char_start?: number;
    char_end?: number;
    snippet: string;
    score: number;
}

/** Semantic search over the tenant's indexed files. */
export async function searchTenant(
    session: SealedSession,
    tenantID: string,
    query: string,
    topK = 10
): Promise<SearchHit[]> {
    const data = await json<{ hits: SearchHit[] }>(
        session,
        'GET',
        `/v1/tenants/${tenantID}/search?q=${encodeURIComponent(query)}&k=${topK}`
    );
    return data.hits ?? [];
}

/** Mark a node (typically a folder) searchable or non-searchable. */
export async function setNodeIndexing(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    enabled: boolean
): Promise<void> {
    const res = await timed(
        session,
        'PUT',
        `/v1/tenants/${tenantID}/nodes/${nodeID}/indexing`,
        { enabled },
        REQUEST_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
}

/** Reparent a node under parentID (null/'' moves it to the tenant root). */
export async function moveNode(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    parentID: string | null
): Promise<void> {
    const res = await timed(session, 'POST', `/v1/tenants/${tenantID}/nodes/${nodeID}/move`, {
        parent_id: parentID ?? ''
    }, REQUEST_TIMEOUT_MS);
    if (!ok(res)) throw decodeError(res);
}

// ---- Permissioning ---------------------------------------------------

export function getPermissions(
    session: SealedSession,
    tenantID: string,
    nodeID: string
): Promise<NodePermissions> {
    return json<NodePermissions>(
        session,
        'GET',
        `/v1/tenants/${tenantID}/nodes/${nodeID}/permissions`
    );
}

/** Share a node with a person (Google-Drive style). scope e.g. ['read'] or ['read','write']. */
export function shareWithUser(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    granteeSub: string,
    scope: Scope[],
    expiresUnix?: number
): Promise<GrantView> {
    return json<GrantView>(session, 'POST', `/v1/tenants/${tenantID}/nodes/${nodeID}/grants`, {
        subject: `subject:${granteeSub}`,
        scope,
        expires_unix: expiresUnix
    });
}

export async function revokeGrant(
    session: SealedSession,
    tenantID: string,
    grantID: string
): Promise<void> {
    const res = await timed(session, 'DELETE', `/v1/tenants/${tenantID}/grants/${grantID}`, undefined, REQUEST_TIMEOUT_MS);
    if (!ok(res)) throw decodeError(res);
}

/** Set/clear a folder's ACL override (SharePoint-style). Empty roles clears it (inherit). */
export function setNodeACL(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    roles: string[]
): Promise<{ node_id: string; roles: string[] }> {
    return json(session, 'PUT', `/v1/tenants/${tenantID}/nodes/${nodeID}/acl`, { roles });
}

/** The caller's inbound shares across all tenants ("Shared with me"). */
export async function listShared(session: SealedSession): Promise<SharedItem[]> {
    const data = await json<{ shared: SharedItem[] }>(session, 'GET', '/v1/shared');
    return data.shared ?? [];
}

// ---- Share links -----------------------------------------------------

export type LinkMode = 'open' | 'restricted';

export interface ShareLink {
    id: string;
    mode: LinkMode;
    scope: string[];
    label?: string;
    required_attributes?: string[];
    created_at: string;
    expires_at?: string;
    revoked: boolean;
    /** Owner-only: lets the link be re-copied. Absent on pre-existing links. */
    secret?: string;
}

export interface CreatedLink {
    id: string;
    secret: string; // returned exactly once
    mode: LinkMode;
    scope: string[];
    node_id: string;
    required_attributes?: string[];
    expires_at?: string;
}

export interface ResolvedLink {
    link_id: string;
    mode: LinkMode;
    scope: string[];
    required_attributes?: string[];
    /**
     * The required attributes that must be PROVEN, in the same spelling as
     * `required_attributes`. They come off the visitor's verified token, so
     * nothing typed into this page can satisfy one and the enclave, not the
     * browser, decides whether they are present.
     */
    paid_attributes?: string[];
    /**
     * Per required attribute, the canonical claim the link is checked against,
     * which is what a step-up has to ask the wallet to disclose. A link stores
     * the registry spelling (`privasys:birthdate`), which the IdP does not
     * accept and which is not the key it mints under (`birthdate_id`). Absent
     * on links created before the service recorded it; `requestKeyFor` covers
     * those.
     */
    attribute_claims?: Record<string, string>;
    tenant_id: string;
    owner_name: string;
    already_granted: boolean;
    request_status: string; // '' | 'pending' | 'approved' | 'denied'
    node: { id: string; name: string; kind: NodeKind; size_bytes: number };
}

export interface RedeemResult {
    status: 'granted' | 'pending';
    tenant_id: string;
    node_id: string;
    name: string;
    kind: NodeKind;
    request_id?: string;
}

export interface LinkRequest {
    id: string;
    node_id: string;
    node_name: string;
    requester_sub: string;
    attributes: Record<string, string>;
    scope: string[];
    status: string;
    created_at: string;
}

/** Owner: mint a share link on a node. Secret is returned once. */
export function createLink(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    opts: {
        mode: LinkMode;
        scope?: string[];
        requiredAttributes?: string[];
        expiresUnix?: number;
        label?: string;
    }
): Promise<CreatedLink> {
    return json<CreatedLink>(session, 'POST', `/v1/tenants/${tenantID}/nodes/${nodeID}/links`, {
        mode: opts.mode,
        scope: opts.scope ?? ['read'],
        required_attributes: opts.requiredAttributes,
        expires_unix: opts.expiresUnix,
        label: opts.label
    });
}

/** Owner: list a node's active links (no secrets). */
export async function listLinks(
    session: SealedSession,
    tenantID: string,
    nodeID: string
): Promise<ShareLink[]> {
    const data = await json<{ links: ShareLink[] }>(
        session,
        'GET',
        `/v1/tenants/${tenantID}/nodes/${nodeID}/links`
    );
    return (data.links ?? []).filter((l) => !l.revoked);
}

/** Recipient: fetch a link's target metadata (requires the secret). */
export function resolveLink(
    session: SealedSession,
    linkID: string,
    secret: string
): Promise<ResolvedLink> {
    return json<ResolvedLink>(session, 'POST', `/v1/links/${linkID}/resolve`, { secret });
}

/** Recipient: redeem a link. Open -> granted; restricted -> pending request. */
export function redeemLink(
    session: SealedSession,
    linkID: string,
    secret: string,
    attributes?: Record<string, string>
): Promise<RedeemResult> {
    return json<RedeemResult>(session, 'POST', `/v1/links/${linkID}/redeem`, { secret, attributes });
}

/** Owner: list restricted-link access requests (default pending). */
export async function listLinkRequests(
    session: SealedSession,
    tenantID: string,
    status = 'pending'
): Promise<LinkRequest[]> {
    const data = await json<{ requests: LinkRequest[] }>(
        session,
        'GET',
        `/v1/tenants/${tenantID}/link-requests?status=${encodeURIComponent(status)}`
    );
    return data.requests ?? [];
}

// ---- Access metrics (Insights) ---------------------------------------

/** One day of tenant activity (series is ascending and sparse). */
export interface MetricsPoint {
    date: string; // YYYY-MM-DD
    views: number;
    downloads: number;
    unique_subs: number;
}

export interface MetricsTopNode {
    node_id: string;
    name: string;
    views: number;
    last_at: string; // RFC3339
}

/** Per-visitor aggregates; subs are opaque pairwise IDs, never names. */
export interface MetricsVisitor {
    sub: string;
    views: number;
    downloads: number;
    bytes: number;
    total_ms: number;
    first_at: string; // RFC3339
    last_at: string; // RFC3339
}

export interface TenantMetrics {
    days: number;
    series: MetricsPoint[];
    top_nodes: MetricsTopNode[]; // max 20
    subs: MetricsVisitor[]; // max 100
    /** Distinct visitors across the whole window (not capped). */
    unique_subs: number;
}

/** Owner/admin: access metrics for the tenant over the last N days. */
export async function getTenantMetrics(
    session: SealedSession,
    tenantID: string,
    days = 30
): Promise<TenantMetrics> {
    const data = await json<TenantMetrics>(
        session,
        'GET',
        `/v1/tenants/${tenantID}/metrics?days=${days}`
    );
    return {
        days: data.days ?? days,
        series: data.series ?? [],
        top_nodes: data.top_nodes ?? [],
        subs: data.subs ?? [],
        unique_subs: data.unique_subs ?? (data.subs ?? []).length
    };
}

/** Owner: approve or deny a restricted-link request. */
export function decideLinkRequest(
    session: SealedSession,
    tenantID: string,
    requestID: string,
    decision: 'approve' | 'deny'
): Promise<{ status: string }> {
    return json(session, 'POST', `/v1/tenants/${tenantID}/link-requests/${requestID}/${decision}`);
}

// ---- Knowledge graph -------------------------------------------------

/** Colour class for a node: drives the graph hue. Kept open for forwards
 *  compatibility with classes the enclave may add. */
export type NodeClass = 'memory' | 'conversation' | 'document' | string;

/** A typed knowledge edge: the folder tree plus the links between files. */
export type GraphEdgeKind = 'citation' | 'wikilink' | 'containment' | string;

export interface GraphNode {
    node_id: string;
    name: string;
    kind: NodeKind;
    class: NodeClass;
    /** Containing folder, or '' at the tenant root. */
    parent_id?: string;
}

export interface GraphEdge {
    from_node: string;
    /** Target node; '' for a dangling wikilink (see to_name). */
    to_node: string;
    /** The written link target; the label for a dangling wikilink. */
    to_name: string;
    kind: GraphEdgeKind;
}

export interface DriveGraph {
    nodes: GraphNode[];
    edges: GraphEdge[];
}

/** The tenant's knowledge graph: nodes plus containment and typed links. */
export async function getGraph(session: SealedSession, tenantID: string): Promise<DriveGraph> {
    const data = await json<DriveGraph>(session, 'GET', `/v1/tenants/${tenantID}/graph`);
    return {
        nodes: data.nodes ?? [],
        edges: data.edges ?? []
    };
}

export interface DanglingLink {
    from_node: string;
    to_name: string;
    kind: GraphEdgeKind;
}

export interface GraphLint {
    dangling_links: DanglingLink[];
    /** Node IDs with no incoming or outgoing typed links. */
    orphan_nodes: string[];
}

/** Graph hygiene: links that point nowhere and nodes nothing links to. */
export async function getLint(session: SealedSession, tenantID: string): Promise<GraphLint> {
    const data = await json<GraphLint>(session, 'GET', `/v1/tenants/${tenantID}/lint`);
    return {
        dangling_links: data.dangling_links ?? [],
        orphan_nodes: data.orphan_nodes ?? []
    };
}

// ---- Storage gauge, apps with access, workspace snapshots ----------------
// The user model of plans/drive-as-remote-disk.md: one gauge with a
// by-folder breakdown, the list of apps holding a grant, and workspace
// snapshots as a single item with an export.

export interface UsageEntry {
    node_id: string;
    name: string;
    kind: NodeKind;
    bytes: number;
}

export interface Quota {
    used_bytes: number;
    limit_bytes: number;
    unlimited: boolean;
    remaining_bytes?: number;
    /** Top-level entries, largest first. */
    breakdown?: UsageEntry[];
    /** Per-app entries under AppData, largest first. */
    apps?: UsageEntry[];
}

export function getQuota(session: SealedSession, tenantID: string): Promise<Quota> {
    return json<Quota>(session, 'GET', `/v1/tenants/${tenantID}/quota`);
}

export interface AppAccess {
    grant_id: string;
    app_id: string;
    app_name?: string;
    node_id: string;
    folder: string;
    scope: string[];
    created_at: string;
    expires_at?: string;
    via?: string;
}

export async function listAppsWithAccess(session: SealedSession, tenantID: string): Promise<AppAccess[]> {
    const res = await json<{ apps: AppAccess[] }>(session, 'GET', `/v1/tenants/${tenantID}/apps`);
    return res.apps ?? [];
}

/** The working tree of a workspace snapshot, rebuilt from its manifest as a ZIP. */
// ---- Editing ------------------------------------------------------------

/** Raised when a save lost a race: someone else wrote first. */
export class StaleWriteError extends Error {
    /** The revision the file is at now, to re-read and retry against. */
    rev: number;
    constructor(rev: number) {
        super('This file changed while you were editing it.');
        this.name = 'StaleWriteError';
        this.rev = rev;
    }
}

/**
 * Replace a text file's contents, refusing to clobber a concurrent writer.
 *
 * `ifRev` is the revision the editor loaded. The enclave compares it before
 * touching storage and answers 412 with the current revision if another
 * writer got there first, which surfaces here as StaleWriteError rather
 * than a silent overwrite.
 */
export async function writeTextContent(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    text: string,
    ifRev: number
): Promise<number> {
    const res = await timed(
        session,
        'PUT',
        `/v1/tenants/${tenantID}/nodes/${nodeID}/content`,
        new TextEncoder().encode(text),
        TRANSFER_TIMEOUT_MS,
        { headers: { 'If-Match': `"${ifRev}"` } }
    );
    if (res.status === 412) {
        let rev = ifRev;
        try {
            const body = JSON.parse(new TextDecoder().decode(res.body ?? new Uint8Array())) as {
                rev?: number;
            };
            if (typeof body.rev === 'number') rev = body.rev;
        } catch {
            /* the status is the signal; the body is a convenience */
        }
        throw new StaleWriteError(rev);
    }
    if (!ok(res)) throw decodeError(res);
    const out = JSON.parse(new TextDecoder().decode(res.body ?? new Uint8Array())) as { rev: number };
    return out.rev;
}

// ---- File history -------------------------------------------------------

/** One retained revision of a file. */
export interface FileVersion {
    rev: number;
    size_bytes: number;
    mime_hint?: string;
    /** Who wrote this revision; empty for content that predates history. */
    actor?: string;
    created_at: string;
    /** True for the revision the file is at now. */
    current?: boolean;
}

/** A file's retained revisions, newest first. */
export async function listVersions(
    session: SealedSession,
    tenantID: string,
    nodeID: string
): Promise<{ node_id: string; rev: number; versions: FileVersion[] }> {
    return json(session, 'GET', `/v1/tenants/${tenantID}/nodes/${nodeID}/versions`);
}

/** The bytes a file held at one revision. */
export async function readVersion(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    rev: number
): Promise<Uint8Array> {
    const res = await timed(
        session,
        'GET',
        `/v1/tenants/${tenantID}/nodes/${nodeID}/versions/${rev}`,
        undefined,
        TRANSFER_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
    return res.body ?? new Uint8Array(0);
}

/**
 * Put an older revision back. The enclave writes it as a NEW revision, so
 * restoring is itself undoable and the history stays in order.
 */
export async function restoreVersion(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    rev: number
): Promise<{ rev: number; restored_from: number; restored: boolean }> {
    return json(session, 'POST', `/v1/tenants/${tenantID}/nodes/${nodeID}/versions/${rev}/restore`);
}

/** One line of a comparison: unchanged, removed or added. */
export interface DiffLine {
    op: ' ' | '-' | '+';
    text: string;
}

/** A run of changed lines with its surrounding context. */
export interface DiffHunk {
    old_start: number;
    old_lines: number;
    new_start: number;
    new_lines: number;
    lines: DiffLine[];
}

export interface DiffResult {
    node_id: string;
    from_rev: number;
    to_rev: number;
    identical: boolean;
    /** The revisions share too little to compare line by line. */
    truncated: boolean;
    hunks: DiffHunk[];
}

/**
 * What changed between two revisions, compared inside the enclave (both
 * revisions are decryptable there and nowhere else). With no bounds it
 * answers what the last save changed. Text files only.
 */
export async function diffVersions(
    session: SealedSession,
    tenantID: string,
    nodeID: string,
    opts: { from?: number; to?: number; context?: number } = {}
): Promise<DiffResult> {
    const qs = new URLSearchParams();
    if (opts.from !== undefined) qs.set('from', String(opts.from));
    if (opts.to !== undefined) qs.set('to', String(opts.to));
    if (opts.context !== undefined) qs.set('context', String(opts.context));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return json(session, 'GET', `/v1/tenants/${tenantID}/nodes/${nodeID}/diff${suffix}`);
}

/**
 * Download a selection of files and folders as one ZIP, assembled inside
 * the enclave. A browser can save a file but cannot lay out a folder tree,
 * and zipping in the page would hold every byte in memory.
 */
export async function downloadZip(
    session: SealedSession,
    tenantID: string,
    nodeIDs: string[],
    name?: string
): Promise<Uint8Array> {
    const res = await timed(
        session,
        'POST',
        `/v1/tenants/${tenantID}/download.zip`,
        { node_ids: nodeIDs, name: name ?? '' },
        TRANSFER_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
    return res.body ?? new Uint8Array(0);
}

export async function exportWorkspaceZip(
    session: SealedSession,
    tenantID: string,
    folderID: string
): Promise<Uint8Array> {
    const res = await timed(
        session,
        'GET',
        `/v1/tenants/${tenantID}/nodes/${folderID}/workspace.zip`,
        undefined,
        TRANSFER_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
    return res.body ?? new Uint8Array(0);
}

// ---- App folders --------------------------------------------------------
// The holder's window onto the working files an app keeps for them in its
// own storage (the enclave OS's holder folders). Nothing is copied into
// Drive: each call forwards the holder's own token to the app, which
// authenticates it exactly as it does the wallet's. The token travels in
// X-Holder-Token because the sealed envelope keeps Authorization for the
// session itself; Drive verifies it and binds it to the session's subject
// before forwarding.

export interface AppFolder {
    app_id: string;
    name: string;
    display_name: string;
    hostname: string;
    label: string;
    used_bytes: number;
}

export interface AppFolderEntry {
    name: string;
    dir: boolean;
    size: number;
    modified: string;
}

export interface AppFolderListing {
    label: string;
    path: string;
    entries: AppFolderEntry[];
    used_bytes: number;
}

function holderHeaders(token: string): RequestInit {
    return { headers: { 'X-Holder-Token': token } };
}

export async function listAppFolders(session: SealedSession, token: string): Promise<AppFolder[]> {
    const res = await json<{ app_folders: AppFolder[] }>(
        session,
        'GET',
        '/v1/app-folders',
        undefined,
        TRANSFER_TIMEOUT_MS,
        holderHeaders(token)
    );
    return res.app_folders ?? [];
}

export function listAppFolder(
    session: SealedSession,
    token: string,
    appID: string,
    path: string
): Promise<AppFolderListing> {
    return json<AppFolderListing>(
        session,
        'GET',
        `/v1/app-folders/${encodeURIComponent(appID)}/files?path=${encodeURIComponent(path)}`,
        undefined,
        REQUEST_TIMEOUT_MS,
        holderHeaders(token)
    );
}

export async function downloadAppFolderFile(
    session: SealedSession,
    token: string,
    appID: string,
    path: string
): Promise<Uint8Array> {
    const res = await timed(
        session,
        'GET',
        `/v1/app-folders/${encodeURIComponent(appID)}/files?path=${encodeURIComponent(path)}`,
        undefined,
        TRANSFER_TIMEOUT_MS,
        holderHeaders(token)
    );
    if (!ok(res)) throw decodeError(res);
    return res.body ?? new Uint8Array(0);
}

export async function deleteAppFolderPath(
    session: SealedSession,
    token: string,
    appID: string,
    path: string
): Promise<void> {
    const res = await timed(
        session,
        'DELETE',
        `/v1/app-folders/${encodeURIComponent(appID)}/files?path=${encodeURIComponent(path)}`,
        undefined,
        TRANSFER_TIMEOUT_MS,
        holderHeaders(token)
    );
    if (!ok(res)) throw decodeError(res);
}
