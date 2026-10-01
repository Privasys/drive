'use client';

// Share-link landing page: /l?id=<linkID>#<secret>
//
// The recipient opens this after receiving a link. The whole Drive channel
// is a wallet-attested sealed session, so the visitor signs in first (the
// wallet, or an invitation to install it). Once a sealed session exists we
// resolve the link and redeem it immediately: clicking the link,
// authenticating and consenting to the requested attributes IS the request,
// so no extra button stands between the visitor and the content. Open links
// grant on the spot; restricted links file the access request and this page
// polls until the owner decides. The link secret rides in the URL fragment
// and never reaches a server log.

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Navbar, Footer } from '@privasys/ui';
import { useDrive } from '~/lib/use-drive';
import { claimString, decodeTokenClaims } from '~/lib/token-claims';
import { parseLinkURL, type LinkParams } from '~/lib/share-link-url';
import {
    DriveError,
    downloadFile,
    redeemLink,
    resolveLink,
    type DriveNode,
    type ResolvedLink
} from '~/lib/drive-api';
import { FileViewer, canPreview } from '~/components/file-viewer';
import { SharedBrowser } from '~/components/shared-browser';
import {
    attributeLabel,
    loadShareAttributes,
    requestKeyFor,
    type ShareAttribute
} from '~/lib/share-attributes';
import { formatBytes } from '~/lib/format';
import { FileIcon, FolderIcon, DownloadIcon, LockIcon, ShieldCheck } from '~/components/icons';

const FOOTER_LINKS = [{ label: 'Legal', href: 'https://privasys.org/legal/', external: true }];

function readParams(): LinkParams {
    if (typeof window === 'undefined') return { id: '', secret: '', attrs: [] };
    return parseLinkURL(window.location.search, window.location.hash);
}

export default function LinkPage() {
    return (
        <Suspense fallback={null}>
            <LinkLanding />
        </Suspense>
    );
}

function LinkLanding() {
    const { status, session, signInInto, holderToken } = useDrive();
    const [params] = useState(readParams);
    const [resolved, setResolved] = useState<ResolvedLink | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [state, setState] = useState<'resolving' | 'granted' | 'pending' | 'denied' | 'missing-attrs'>('resolving');
    const [missingAttrs, setMissingAttrs] = useState<string[]>([]);
    // Labels for the keys the link demands, from the canonical referential.
    // Until it arrives the raw key is shown, which is worse prose but never
    // wrong; a hardcoded table here would go stale against the wallet's.
    const [shareAttrs, setShareAttrs] = useState<ShareAttribute[]>([]);
    const [viewing, setViewing] = useState(false);
    // A restricted link asked for attributes the minimal sign-in did not
    // request; `stepUp` re-shows the ceremony to request exactly those.
    const [stepUp, setStepUp] = useState(false);
    const ceremonyRef = useRef<HTMLDivElement>(null);
    const started = useRef(false);
    const stepUpStarted = useRef(false);
    const redeemed = useRef(false);

    useEffect(() => {
        let live = true;
        loadShareAttributes()
            .then((a) => live && setShareAttrs(a))
            .catch(() => undefined);
        return () => {
            live = false;
        };
    }, []);

    // Mount the sign-in ceremony when signed out. An open link is a minimal
    // identity flow (a wallet sub, no PII) and asks for nothing, so it never
    // prompts the visitor for their name or email. A restricted link's address
    // names what it requires, and the ceremony asks for exactly that, so the
    // visitor approves the connection and the disclosure on one screen instead
    // of approving a bare connection and then being sent round again. An
    // address without the hint (made before it existed, or trimmed on the way)
    // falls through to the step-up below, which is what the enclave's own
    // check would demand anyway.
    // A ceremony can die without completing (the wallet went through an
    // install or attribute-import detour and the session expired, the
    // network dropped): surface a retry instead of a dead blank frame.
    const [ceremonyError, setCeremonyError] = useState<string | null>(null);
    useEffect(() => {
        if (status !== 'signed-out' || ceremonyError || started.current || !ceremonyRef.current) return;
        started.current = true;
        signInInto(ceremonyRef.current, params.attrs.length > 0 ? params.attrs : undefined).catch(() => {
            started.current = false;
            setCeremonyError('The sign-in did not complete. Scan the code again to open the link.');
        });
    }, [status, signInInto, ceremonyError, params.attrs]);

    // Restricted-link step-up: re-run the ceremony requesting exactly the
    // attributes the link requires, then resolve + redeem again.
    useEffect(() => {
        if (!stepUp || ceremonyError || stepUpStarted.current || !ceremonyRef.current) return;
        stepUpStarted.current = true;
        void (async () => {
            // Ask for the claim the link is checked against, not the spelling
            // it stores: the IdP drops a namespaced key, and the certified
            // reading of a field is a different key from the bare name. The
            // link states that mapping; the referential answers for links
            // created before it did.
            const claims = resolved?.attribute_claims ?? {};
            try {
                await signInInto(
                    ceremonyRef.current!,
                    missingAttrs.map((k) => claims[k] ?? requestKeyFor(shareAttrs, k))
                );
            } catch {
                stepUpStarted.current = false;
                setCeremonyError('The sign-in did not complete. Scan the code again to open the link.');
                return;
            }
            redeemed.current = false;
            setStepUp(false);
            stepUpStarted.current = false;
            setState('resolving');
        })();
    }, [stepUp, ceremonyError, missingAttrs, shareAttrs, resolved, signInInto]);

    // The attributes the visitor already consented to share at sign-in,
    // matched against what the link requires.
    // What the visitor's own token says they have disclosed. This is the only
    // sound source for answering a restricted link, and it used to be their
    // stored profile from the control plane: that answers whether the platform
    // knows a name and email for the account, which is true whether or not
    // they ever agreed to give either to this sharer, and true even for the
    // minimal sign-in that opens a link and deliberately asks for neither.
    // Reading it satisfied the link without asking anybody, so a visitor
    // approved a connection and watched their details go out with it, while
    // the sharer was told attributes had been presented.
    //
    // A claim is in the token because a sign-in asked for that disclosure and
    // the wallet put it to the holder; absent means they were never asked,
    // which is reported missing and runs the step-up that does ask.
    const disclosed = useMemo(() => decodeTokenClaims(holderToken), [holderToken]);

    const presentedAttributes = useCallback(
        (r: ResolvedLink): Record<string, string> | undefined => {
            if (r.mode !== 'restricted') return undefined;
            const available: Record<string, string | undefined> = {
                name: claimString(disclosed, 'name'),
                email: claimString(disclosed, 'email')
            };
            const out: Record<string, string> = {};
            for (const key of r.required_attributes ?? []) {
                const v = available[key];
                if (v) out[key] = v;
            }
            return out;
        },
        [disclosed]
    );

    // Resolve, then redeem in the same breath: authenticating with the
    // requested attributes already expressed the visitor's intent.
    const resolveAndRedeem = useCallback(async () => {
        if (!session || !params.id || !params.secret) return;
        setError(null);
        try {
            const r = await resolveLink(session, params.id, params.secret);
            setResolved(r);
            if (r.already_granted) {
                setState('granted');
                if (r.node.kind === 'file' && canPreview(asNode(r))) setViewing(true);
                return;
            }
            if (r.request_status === 'pending') {
                setState('pending');
                return;
            }
            if (redeemed.current) return;
            // Restricted links need every required attribute: without them
            // no request is filed (the server enforces this too) and the
            // visitor is told what to share instead.
            //
            // Only the attributes this page can actually supply are checked
            // here. A PROVEN one lives in the sealed token and is invisible
            // to the browser, so treating it as absent would send a visitor
            // who has already disclosed it back round the consent screen for
            // ever; the enclave answers for those.
            const attrs = presentedAttributes(r);
            const proven = new Set(r.paid_attributes ?? []);
            if (r.mode === 'restricted') {
                const missing = (r.required_attributes ?? []).filter((k) => !proven.has(k) && !attrs?.[k]);
                if (missing.length > 0) {
                    setMissingAttrs(missing);
                    setState('missing-attrs');
                    return;
                }
            }
            redeemed.current = true;
            let res;
            try {
                res = await redeemLink(session, params.id, params.secret, attrs);
            } catch (e) {
                // The enclave refuses a redeem that proves less than the link
                // requires, and it is the only party that can tell: ask for
                // the proven set again rather than reporting a dead end.
                if (e instanceof DriveError && e.status === 403 && proven.size > 0) {
                    redeemed.current = false;
                    setMissingAttrs([...proven]);
                    setState('missing-attrs');
                    return;
                }
                throw e;
            }
            if (res.status === 'granted') {
                setState('granted');
                if (r.node.kind === 'file' && canPreview(asNode(r))) setViewing(true);
            } else {
                setState('pending');
            }
        } catch (e) {
            setError(e instanceof Error ? e.message : 'This link is invalid or has expired.');
        }
    }, [session, params, presentedAttributes]);

    useEffect(() => {
        void resolveAndRedeem();
    }, [resolveAndRedeem]);

    // While the owner's decision is pending, poll so approval flips this
    // page to the content without a manual reload.
    useEffect(() => {
        if (state !== 'pending' || !session) return;
        const t = setInterval(async () => {
            try {
                const r = await resolveLink(session, params.id, params.secret);
                if (r.already_granted) {
                    setResolved(r);
                    setState('granted');
                    if (r.node.kind === 'file' && canPreview(asNode(r))) setViewing(true);
                } else if (r.request_status === 'denied') {
                    setState('denied');
                }
            } catch {
                /* keep polling */
            }
        }, 8000);
        return () => clearInterval(t);
    }, [state, session, params]);

    const download = async () => {
        if (!session || !resolved) return;
        try {
            const bytes = await downloadFile(session, resolved.tenant_id, resolved.node.id);
            const blob = new Blob([bytes as BlobPart], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = resolved.node.name;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Download failed.');
        }
    };

    const grantedFolder = state === 'granted' && resolved?.node.kind === 'folder';

    return (
        <div className="flex min-h-screen flex-col" style={{ background: 'var(--drv-surface-2)' }}>
            <Navbar brandSuffix="Drive" fullWidth />

            <main className="flex flex-1 justify-center px-6 pt-14">
                <div className={`w-full py-10 ${grantedFolder ? 'max-w-3xl' : 'max-w-md self-center'}`}>
                    {!params.id || !params.secret ? (
                        <Card>
                            <p className="text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                This link is incomplete. Ask the sender for the full link.
                            </p>
                        </Card>
                    ) : status === 'signed-out' || stepUp ? (
                        <Card>
                            <div className="mb-3 text-center">
                                <div className="text-lg font-semibold">
                                    {stepUp ? 'Share to request access' : 'Something was shared with you'}
                                </div>
                                <div className="mt-1 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                    {stepUp
                                        ? `This private link asks you to share ${missingAttrs.map((k) => attributeLabel(shareAttrs, k)).join(', ')}.`
                                        : 'Sign in with the Privasys Wallet, or install it, to open it securely.'}
                                </div>
                            </div>
                            {ceremonyError ? (
                                <div className="py-10 text-center">
                                    <p className="text-sm" style={{ color: 'var(--drv-text-muted)' }}>{ceremonyError}</p>
                                    <button
                                        onClick={() => setCeremonyError(null)}
                                        className="drv-btn-primary mt-5 rounded-full px-5 py-2 text-sm"
                                    >
                                        Try again
                                    </button>
                                </div>
                            ) : (
                                <div ref={ceremonyRef} className="h-[560px] w-full overflow-hidden rounded-xl" />
                            )}
                        </Card>
                    ) : !resolved ? (
                        <Card>
                            <p className="py-6 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                {error ?? 'Opening the link…'}
                            </p>
                        </Card>
                    ) : grantedFolder ? (
                        <>
                            <div className="mb-4">
                                <div className="text-lg font-semibold">{resolved.node.name}</div>
                                <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                    {resolved.owner_name ? `Shared by ${resolved.owner_name}` : 'Shared with you'}
                                    {' · sealed end-to-end inside the enclave'}
                                </div>
                            </div>
                            {session && (
                                <SharedBrowser
                                    session={session}
                                    tenantID={resolved.tenant_id}
                                    rootID={resolved.node.id}
                                    rootName={resolved.node.name}
                                />
                            )}
                        </>
                    ) : (
                        <Card>
                            <div className="flex items-center gap-3">
                                {resolved.node.kind === 'folder' ? (
                                    <FolderIcon width={28} height={28} style={{ color: 'var(--drv-accent)' }} />
                                ) : (
                                    <FileIcon width={28} height={28} style={{ color: 'var(--drv-text-muted)' }} />
                                )}
                                <div className="min-w-0 flex-1">
                                    <div className="truncate text-[15px] font-semibold">{resolved.node.name}</div>
                                    <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                        {resolved.owner_name ? `Shared by ${resolved.owner_name}` : 'Shared with you'}
                                        {resolved.node.kind === 'file' ? ` · ${formatBytes(resolved.node.size_bytes)}` : ''}
                                    </div>
                                </div>
                            </div>

                            {state === 'granted' ? (
                                <div className="mt-5 flex flex-wrap gap-2">
                                    {resolved.node.kind === 'file' && canPreview(asNode(resolved)) && (
                                        <button onClick={() => setViewing(true)} className="drv-btn-primary flex items-center gap-2 rounded-full px-4 py-2 text-sm">
                                            Open
                                        </button>
                                    )}
                                    {resolved.node.kind === 'file' && (
                                        <button
                                            onClick={() => void download()}
                                            className="flex items-center gap-2 rounded-full border px-4 py-2 text-sm"
                                            style={{ borderColor: 'var(--drv-border)' }}
                                        >
                                            <DownloadIcon width={16} height={16} /> Download
                                        </button>
                                    )}
                                </div>
                            ) : state === 'denied' ? (
                                <div className="mt-5 rounded-lg border px-3 py-3 text-sm" style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}>
                                    The owner declined this request.
                                </div>
                            ) : state === 'missing-attrs' ? (
                                <div className="mt-5 rounded-lg border px-3 py-3 text-sm" style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}>
                                    <p>
                                        The owner asks visitors to share{' '}
                                        <span style={{ color: 'var(--drv-text)' }}>
                                            {missingAttrs.map((k) => attributeLabel(shareAttrs, k)).join(', ')}
                                        </span>{' '}
                                        to request access.
                                    </p>
                                    <button
                                        type="button"
                                        onClick={() => setStepUp(true)}
                                        className="mt-3 w-full rounded-lg px-3 py-2 text-sm font-semibold text-white transition-opacity hover:opacity-90"
                                        style={{ background: 'var(--drv-accent)' }}
                                    >
                                        Share {missingAttrs.length === 1 ? 'it' : 'them'} and continue
                                    </button>
                                </div>
                            ) : (
                                <div className="mt-5 rounded-lg border px-3 py-3 text-sm" style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}>
                                    Waiting for the owner to approve your access. This page updates
                                    automatically; you can also come back to the link later.
                                </div>
                            )}

                            {error && <p className="mt-3 text-center text-sm text-red-500">{error}</p>}

                            <div className="mt-4 flex items-center gap-1.5 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                <LockIcon width={13} height={13} /> Sealed end-to-end inside the enclave.
                            </div>
                        </Card>
                    )}

                    <div className="mt-4 flex items-center justify-center gap-1.5 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                        <ShieldCheck width={13} height={13} /> Attestation-verified confidential computing
                    </div>
                </div>
            </main>

            {viewing && resolved && session && (
                <FileViewer
                    session={session}
                    tenantID={resolved.tenant_id}
                    node={asNode(resolved)}
                    onClose={() => setViewing(false)}
                    onDownload={() => void download()}
                />
            )}

            <Footer
                className="!mt-0"
                companyLine="Every file is sealed inside a hardware-protected enclave. Verify its attestation yourself; you don't have to trust us."
                links={FOOTER_LINKS}
            />
        </div>
    );
}

function asNode(r: ResolvedLink): DriveNode {
    return {
        id: r.node.id,
        tenant_id: r.tenant_id,
        kind: r.node.kind,
        name: r.node.name,
        size_bytes: r.node.size_bytes
    };
}

function Card({ children }: { children: React.ReactNode }) {
    return (
        <div
            className="rounded-2xl border p-5 shadow-sm"
            style={{ background: 'var(--drv-surface)', borderColor: 'var(--drv-border)' }}
        >
            {children}
        </div>
    );
}
