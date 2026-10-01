'use client';

// Owner view for restricted-link access requests. Each row shows the
// attributes the visitor presented (name, verified email, government-ID
// name); the owner approves or denies. Approval mints the recipient a
// per-file grant. No email lists, no stored identities.

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    decideLinkRequest,
    listLinkRequests,
    type LinkRequest,
    type Tenant
} from '~/lib/drive-api';
import { FileIcon, PeopleIcon } from './icons';

export function RequestsView({ session, tenant }: { session: SealedSession; tenant: Tenant }) {
    const [requests, setRequests] = useState<LinkRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            setRequests(await listLinkRequests(session, tenant.id, 'pending'));
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not load requests.');
        } finally {
            setLoading(false);
        }
    }, [session, tenant.id]);

    useEffect(() => {
        void load();
    }, [load]);

    const decide = async (id: string, decision: 'approve' | 'deny') => {
        setBusy(id);
        try {
            await decideLinkRequest(session, tenant.id, id, decision);
            await load();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not update the request.');
        } finally {
            setBusy(null);
        }
    };

    return (
        <div className="p-4 sm:p-6">
            <div className="mb-4">
                <h1 className="text-lg font-semibold">Access requests</h1>
                <p className="mt-0.5 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    People who opened a restricted link and are waiting for your approval.
                </p>
            </div>

            {error && (
                <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    {error}
                </div>
            )}

            {loading ? (
                <div className="py-16 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    Loading…
                </div>
            ) : requests.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 text-center">
                    <PeopleIcon width={48} height={48} style={{ color: 'var(--drv-border)' }} />
                    <p className="mt-4 text-sm font-medium">No pending requests</p>
                    <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Restricted-link requests will appear here for you to approve.
                    </p>
                </div>
            ) : (
                <div className="space-y-3">
                    {requests.map((r) => (
                        <div
                            key={r.id}
                            className="rounded-xl border p-4"
                            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                        >
                            <div className="flex items-center gap-2 text-sm font-medium">
                                <FileIcon width={18} height={18} style={{ color: 'var(--drv-text-muted)' }} />
                                <span className="truncate">{r.node_name || 'A file'}</span>
                            </div>
                            <div className="mt-2 flex flex-wrap gap-2">
                                {Object.entries(r.attributes ?? {}).length === 0 ? (
                                    <span className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                        No attributes presented.
                                    </span>
                                ) : (
                                    Object.entries(r.attributes).map(([k, v]) => (
                                        <span
                                            key={k}
                                            className="rounded-full px-2.5 py-1 text-xs"
                                            style={{ background: 'var(--drv-surface-2)', color: 'var(--drv-text)' }}
                                        >
                                            <span style={{ color: 'var(--drv-text-muted)' }}>{k}:</span> {v}
                                        </span>
                                    ))
                                )}
                            </div>
                            <div className="mt-3 flex gap-2">
                                <button
                                    onClick={() => void decide(r.id, 'approve')}
                                    disabled={busy === r.id}
                                    className="drv-btn-primary rounded-full px-4 py-1.5 text-sm disabled:opacity-50"
                                >
                                    Approve
                                </button>
                                <button
                                    onClick={() => void decide(r.id, 'deny')}
                                    disabled={busy === r.id}
                                    className="rounded-full border px-4 py-1.5 text-sm disabled:opacity-50"
                                    style={{ borderColor: 'var(--drv-border)' }}
                                >
                                    Deny
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
