'use client';

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    createLink,
    getPermissions,
    listLinks,
    revokeGrant,
    setNodeACL,
    type CreatedLink,
    type DriveNode,
    type LinkMode,
    type NodePermissions,
    type ShareLink,
    type TenantKind
} from '~/lib/drive-api';
import { avatarColor, granteeLabel, initials } from '~/lib/format';
import { fetchAttributePrices, type AttributeSectionCopy, type AttributeSectionId, type CanonicalAttribute } from '@privasys/auth';
import { PrivasysAttributePicker } from '@privasys/auth/react';
import {
    loadReferential,
    loadShareAttributes,
    requestKeyFor,
    type ShareAttribute
} from '~/lib/share-attributes';
import { buildLinkURL } from '~/lib/share-link-url';
import { API_BASE_URL } from '~/lib/me-api';
import { useDrive } from '~/lib/use-drive';
import { CloseIcon, FolderIcon, FileIcon, LinkIcon, LockIcon, TrashIcon } from './icons';

// Drive's wording for the shared picker's sections. The holder here is the
// visitor opening the link, and a paid attribute is charged each time one
// presents it. The copy stops short of naming who is billed until the sharer is
// the one who genuinely is.
const PICKER_COPY: Partial<Record<AttributeSectionId, AttributeSectionCopy>> = {
    holder: { title: 'Provided by the visitor' },
    gov: { title: 'Verified from their government ID' },
    paid: {
        title: 'Paid attributes',
        hint:
            'Certified from the visitor’s government ID, so each one is charged every time a visitor ' +
            'presents it. Prices are per visitor.'
    }
};

// Tenant member roles an enterprise folder ACL can narrow to.
const ROLE_OPTIONS = ['owner', 'admin', 'contributor', 'reader'] as const;

// The address a visitor opens. A restricted link names what it requires, as
// the key the wallet must be asked for rather than the marketplace spelling it
// is stored under, so the visitor's first approval already shows it. See
// lib/share-link-url for why this is a hint the enclave does not rely on.
function linkURL(
    link: { id: string; mode: LinkMode; required_attributes?: string[] },
    secret: string,
    attrs: ShareAttribute[]
): string {
    const origin = typeof window !== 'undefined' ? window.location.origin : 'https://drive.privasys.org';
    const ask =
        link.mode === 'restricted'
            ? (link.required_attributes ?? []).map((k) => requestKeyFor(attrs, k))
            : undefined;
    return buildLinkURL(origin, link.id, secret, ask);
}

export function ShareDialog({
    session,
    tenantID,
    tenantKind = 'user',
    node,
    mySub,
    onClose
}: {
    session: SealedSession;
    tenantID: string;
    tenantKind?: TenantKind;
    node: DriveNode;
    mySub: string;
    onClose: () => void;
}) {
    const [perms, setPerms] = useState<NodePermissions | null>(null);
    const [links, setLinks] = useState<ShareLink[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    // Link builder
    const [mode, setMode] = useState<LinkMode>('open');
    const [reqAttrs, setReqAttrs] = useState<string[]>(['name']);
    const [generated, setGenerated] = useState<CreatedLink | null>(null);
    const [copied, setCopied] = useState<string | null>(null); // link id last copied

    // What a visitor can be asked to present, read from the canonical
    // referential rather than listed here. Null while it loads: the create
    // button already refuses an empty selection, so a referential the browser
    // cannot reach blocks a restricted link instead of offering keys the wallet
    // might no longer honour.
    const [shareAttrs, setShareAttrs] = useState<ShareAttribute[] | null>(null);
    useEffect(() => {
        let live = true;
        loadShareAttributes()
            .then((a) => live && setShareAttrs(a))
            .catch(() => live && setShareAttrs([]));
        return () => {
            live = false;
        };
    }, []);

    // What each paid attribute costs, from the marketplace catalogue. The
    // catalogue needs the holder's platform token; without one, or if it
    // cannot be reached, the chips fall back to saying "Paid" rather than
    // showing a price nobody confirmed.
    const { holderToken } = useDrive();
    const [prices, setPrices] = useState<Map<string, number> | null>(null);
    useEffect(() => {
        if (!holderToken) return;
        const ctrl = new AbortController();
        fetchAttributePrices(API_BASE_URL, holderToken, ctrl.signal)
            .then(setPrices)
            .catch(() => undefined);
        return () => ctrl.abort();
    }, [holderToken]);

    // The live referential, as the picker takes it. Null while it loads; an
    // empty list means the IdP could not be reached, and the dialog says so
    // rather than offering keys the wallet might no longer honour.
    const [referential, setReferential] = useState<CanonicalAttribute[] | null>(null);
    useEffect(() => {
        let live = true;
        loadReferential()
            .then((a) => live && setReferential(a))
            .catch(() => live && setReferential([]));
        return () => {
            live = false;
        };
    }, []);

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const [p, ls] = await Promise.all([
                getPermissions(session, tenantID, node.id),
                listLinks(session, tenantID, node.id).catch(() => [])
            ]);
            setPerms(p);
            setLinks(ls);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not load permissions.');
        } finally {
            setLoading(false);
        }
    }, [session, tenantID, node.id]);

    useEffect(() => {
        void load();
    }, [load]);

    // Create the link and put it straight on the clipboard: the user's
    // intent behind "Copy link" is to paste it somewhere next.
    const generate = async () => {
        setBusy(true);
        setError(null);
        setGenerated(null);
        setCopied(null);
        try {
            const created = await createLink(session, tenantID, node.id, {
                mode,
                scope: ['read'],
                requiredAttributes: mode === 'restricted' ? reqAttrs : undefined
            });
            setGenerated(created);
            await copyLink(created, created.secret);
            await load();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not create the link.');
        } finally {
            setBusy(false);
        }
    };

    const copyLink = async (link: { id: string; mode: LinkMode; required_attributes?: string[] }, secret: string) => {
        const id = link.id;
        try {
            await navigator.clipboard.writeText(linkURL(link, secret, shareAttrs ?? []));
            setCopied(id);
            setTimeout(() => setCopied((cur) => (cur === id ? null : cur)), 5000);
        } catch {
            /* clipboard blocked; the fallback field stays selectable */
        }
    };

    const activeGrants = (perms?.grants ?? []).filter(
        (g) => !g.revoked && g.subject.startsWith('subject:')
    );

    const revoke = async (grantID: string) => {
        setBusy(true);
        try {
            await revokeGrant(session, tenantID, grantID);
            await load();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not revoke access.');
        } finally {
            setBusy(false);
        }
    };

    const saveACL = async (roles: string[]) => {
        setBusy(true);
        setError(null);
        try {
            await setNodeACL(session, tenantID, node.id, roles);
            await load();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not update folder permissions.');
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
            <div
                className="w-full max-w-lg overflow-hidden rounded-2xl shadow-2xl"
                style={{ background: 'var(--drv-surface)' }}
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div className="flex items-center gap-3 border-b px-5 py-4" style={{ borderColor: 'var(--drv-border)' }}>
                    {node.kind === 'folder' ? (
                        <FolderIcon width={22} height={22} style={{ color: 'var(--drv-accent)' }} />
                    ) : (
                        <FileIcon width={22} height={22} style={{ color: 'var(--drv-text-muted)' }} />
                    )}
                    <div className="min-w-0 flex-1">
                        <div className="truncate text-[15px] font-semibold">Share “{node.name}”</div>
                        <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                            {node.kind === 'folder'
                                ? 'People you add can access this folder and everything inside it.'
                                : 'People you add can access this file.'}
                        </div>
                    </div>
                    <button onClick={onClose} className="rounded-lg p-1 hover:bg-[var(--drv-hover)]">
                        <CloseIcon />
                    </button>
                </div>

                <div className="max-h-[70vh] overflow-auto p-5">
                    {error && (
                        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                            {error}
                        </div>
                    )}

                    {/* Share with a link. Privasys holds no names or email
                        addresses, so there is nobody to "add" by identity;
                        sharing is by link instead. */}
                    <div className="rounded-xl border p-4" style={{ borderColor: 'var(--drv-border)' }}>
                        <div className="flex items-center gap-2 text-sm font-medium">
                            <LinkIcon width={18} height={18} style={{ color: 'var(--drv-accent)' }} />
                            Share with a link
                        </div>
                        <p className="mt-1.5 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                            A link keeps this {node.kind === 'folder' ? 'folder' : 'file'} sealed
                            inside the enclave. The recipient opens it with the Privasys Wallet,
                            or is invited to install it (a passkey works once available).
                        </p>

                        <div className="mt-3 space-y-2">
                            <LinkModeChoice
                                selected={mode === 'open'}
                                onSelect={() => setMode('open')}
                                title="Anyone with the link"
                                body="Whoever holds the link can open it after signing in."
                            />
                            <LinkModeChoice
                                selected={mode === 'restricted'}
                                onSelect={() => setMode('restricted')}
                                title="Restricted to people you approve"
                                body="The visitor presents the attributes you choose; you approve each request."
                            />
                        </div>

                        {mode === 'restricted' && (
                            <div className="mt-3">
                                <div className="mb-2 text-xs font-medium" style={{ color: 'var(--drv-text-muted)' }}>
                                    Require the visitor to present
                                </div>
                                {referential !== null && referential.length === 0 && (
                                    <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                        Could not reach the attribute referential. Reopen this dialog to retry.
                                    </div>
                                )}
                                {/* The SDK's picker, the one every Privasys surface uses, so
                                    a sharer meets the same sections and trust markers here
                                    as a developer registering an app. Drive only words its
                                    sections for a visitor and hands it Drive's colours. */}
                                {referential !== null && referential.length > 0 && (
                                    <PrivasysAttributePicker
                                        className="drv-attribute-picker"
                                        layout="chips"
                                        attributes={referential}
                                        selected={reqAttrs}
                                        onChange={setReqAttrs}
                                        prices={prices}
                                        copy={PICKER_COPY}
                                        totalTemplate="Each visitor who presents what you have chosen costs {price}."
                                    />
                                )}
                            </div>
                        )}

                        <button
                            onClick={() => void generate()}
                            disabled={busy || (mode === 'restricted' && reqAttrs.length === 0)}
                            className="drv-btn-primary mt-3 flex items-center gap-2 rounded-full px-4 py-2 text-sm disabled:opacity-50"
                        >
                            <LinkIcon width={16} height={16} /> Copy link
                        </button>

                        {generated && copied === generated.id && (
                            <div
                                className="mt-3 rounded-lg border px-3 py-2 text-xs font-medium"
                                style={{ borderColor: 'var(--drv-accent)', background: 'var(--drv-accent-weak)', color: 'var(--drv-accent)' }}
                            >
                                Link copied to your clipboard.
                            </div>
                        )}
                        {generated && copied !== generated.id && (
                            // Clipboard blocked (permissions): fall back to a
                            // selectable field so the link is not lost.
                            <input
                                readOnly
                                value={linkURL(generated, generated.secret, shareAttrs ?? [])}
                                onFocus={(e) => e.currentTarget.select()}
                                className="mt-3 w-full rounded-lg border px-3 py-2 text-xs outline-none"
                                style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                            />
                        )}

                        {links.length > 0 && (
                            <div className="mt-4">
                                <div className="mb-1.5 text-xs font-medium" style={{ color: 'var(--drv-text-muted)' }}>
                                    Active links
                                </div>
                                <div className="space-y-1">
                                    {links.map((l) => (
                                        <div key={l.id} className="flex items-center gap-2 rounded-lg px-1 py-1.5 text-sm">
                                            <LinkIcon width={16} height={16} style={{ color: 'var(--drv-text-muted)' }} />
                                            <span className="flex-1 truncate">
                                                {l.mode === 'restricted'
                                                    ? `Restricted (${(l.required_attributes ?? []).join(', ') || 'attributes'})`
                                                    : 'Anyone with the link'}
                                            </span>
                                            {l.secret && (
                                                <button
                                                    onClick={() => void copyLink(l, l.secret!)}
                                                    disabled={busy}
                                                    className="rounded-full border px-2.5 py-1 text-xs font-medium hover:bg-[var(--drv-hover)]"
                                                    style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text)' }}
                                                >
                                                    {copied === l.id ? 'Copied' : 'Copy'}
                                                </button>
                                            )}
                                            <button
                                                title="Revoke link"
                                                onClick={() => void revoke(l.id)}
                                                disabled={busy}
                                                className="rounded-lg p-1 hover:bg-[var(--drv-hover)]"
                                                style={{ color: 'var(--drv-text-muted)' }}
                                            >
                                                <TrashIcon width={16} height={16} />
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* People with access */}
                    <div className="mt-6">
                        <div className="mb-2 text-sm font-medium">People with access</div>
                        {loading ? (
                            <div className="py-4 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                Loading…
                            </div>
                        ) : (
                            <div className="space-y-1">
                                {/* Owner (implicit) */}
                                <PersonRow
                                    label={mySub}
                                    sublabel="Owner"
                                    right={<span className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>Owner</span>}
                                />
                                {activeGrants.length === 0 && (
                                    <div className="px-1 py-2 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                        Not shared with anyone yet.
                                    </div>
                                )}
                                {activeGrants.map((g) => (
                                    <PersonRow
                                        key={g.id}
                                        label={granteeLabel(g.subject)}
                                        sublabel={g.scope.includes('write') ? 'Editor' : 'Viewer'}
                                        right={
                                            <div className="flex items-center gap-2">
                                                <span
                                                    className="rounded-full px-2 py-0.5 text-xs"
                                                    style={{ background: 'var(--drv-accent-weak)', color: 'var(--drv-accent)' }}
                                                >
                                                    {g.scope.includes('write') ? 'Can edit' : 'Can view'}
                                                    {g.expires_at ? ' · expires' : ''}
                                                </span>
                                                <button
                                                    title="Remove access"
                                                    onClick={() => void revoke(g.id)}
                                                    disabled={busy}
                                                    className="rounded-lg p-1 hover:bg-[var(--drv-hover)]"
                                                    style={{ color: 'var(--drv-text-muted)' }}
                                                >
                                                    <TrashIcon width={16} height={16} />
                                                </button>
                                            </div>
                                        }
                                    />
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Folder ACL (enterprise / SharePoint-style role narrowing) */}
                    {node.kind === 'folder' && tenantKind === 'enterprise' && (
                        <FolderACL
                            override={perms?.acl_override ?? null}
                            effective={perms?.effective_acl ?? null}
                            busy={busy}
                            onSave={saveACL}
                        />
                    )}
                </div>

                <div
                    className="flex items-center justify-between gap-2 border-t px-5 py-3 text-xs"
                    style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
                >
                    <span className="flex items-center gap-1.5">
                        <LockIcon /> Shared files stay end-to-end encrypted inside the enclave.
                    </span>
                    <button onClick={onClose} className="rounded-full px-4 py-1.5 font-medium hover:bg-[var(--drv-hover)]" style={{ color: 'var(--drv-text)' }}>
                        Done
                    </button>
                </div>
            </div>
        </div>
    );
}

function LinkModeChoice({
    selected,
    onSelect,
    title,
    body
}: {
    selected: boolean;
    onSelect: () => void;
    title: string;
    body: string;
}) {
    return (
        <button
            onClick={onSelect}
            className="flex w-full items-start gap-2.5 rounded-lg border px-3 py-2.5 text-left"
            style={{
                borderColor: selected ? 'var(--drv-accent)' : 'var(--drv-border)',
                background: selected ? 'var(--drv-accent-weak)' : 'var(--drv-surface-2)'
            }}
        >
            <span
                className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border"
                style={{ borderColor: selected ? 'var(--drv-accent)' : 'var(--drv-border)' }}
            >
                {selected && (
                    <span className="h-2 w-2 rounded-full" style={{ background: 'var(--drv-accent)' }} />
                )}
            </span>
            <span className="min-w-0">
                <span className="block text-[13px] font-medium">{title}</span>
                <span className="mt-0.5 block text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                    {body}
                </span>
            </span>
        </button>
    );
}

function PersonRow({
    label,
    sublabel,
    right
}: {
    label: string;
    sublabel: string;
    right: React.ReactNode;
}) {
    return (
        <div className="flex items-center gap-3 rounded-lg px-1 py-1.5">
            <div
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-semibold text-white"
                style={{ background: avatarColor(label) }}
            >
                {initials(label)}
            </div>
            <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{label}</div>
                <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>{sublabel}</div>
            </div>
            {right}
        </div>
    );
}

function FolderACL({
    override,
    effective,
    busy,
    onSave
}: {
    override: string[] | null;
    effective: string[] | null;
    busy: boolean;
    onSave: (roles: string[]) => void;
}) {
    const [roles, setRoles] = useState<string[]>(override ?? []);
    useEffect(() => setRoles(override ?? []), [override]);

    const toggle = (r: string) =>
        setRoles((cur) => (cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r]));

    return (
        <div className="mt-6 rounded-xl border p-4" style={{ borderColor: 'var(--drv-border)' }}>
            <div className="text-sm font-medium">Restrict this folder by role</div>
            <p className="mt-1 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                Only members with one of the selected roles can open this folder and its
                contents (SharePoint-style). Leave all unchecked to inherit the parent’s
                permissions. The owner is never locked out.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
                {ROLE_OPTIONS.map((r) => (
                    <button
                        key={r}
                        onClick={() => toggle(r)}
                        className="rounded-full border px-3 py-1.5 text-sm capitalize"
                        style={{
                            borderColor: roles.includes(r) ? 'var(--drv-accent)' : 'var(--drv-border)',
                            background: roles.includes(r) ? 'var(--drv-accent-weak)' : 'transparent',
                            color: roles.includes(r) ? 'var(--drv-accent)' : 'var(--drv-text)'
                        }}
                    >
                        {r}
                    </button>
                ))}
            </div>
            {effective && !override && (
                <div className="mt-3 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                    Currently inheriting: {effective.join(', ') || 'everyone in the workspace'}
                </div>
            )}
            <button
                onClick={() => onSave(roles)}
                disabled={busy}
                className="drv-btn-primary mt-3 rounded-full px-4 py-1.5 text-sm disabled:opacity-50"
            >
                {roles.length ? 'Save restriction' : 'Clear restriction'}
            </button>
        </div>
    );
}
