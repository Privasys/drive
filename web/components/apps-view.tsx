'use client';

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import { listAppsWithAccess, revokeGrant, type AppAccess, type Tenant } from '~/lib/drive-api';
import { formatDate, relativeTime } from '~/lib/format';
import { AppsIcon } from './icons';

// "Apps with access": which apps hold a grant on this Drive, the folder each
// one reaches, what it may do, when it expires, and Revoke. Fed by
// GET /v1/tenants/{t}/apps; Revoke is the ordinary grant DELETE, after which
// the app's next write fails and it asks again through the wallet.

export function AppsView({ session, tenant }: { session: SealedSession; tenant: Tenant }) {
    const [apps, setApps] = useState<AppAccess[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [confirm, setConfirm] = useState<AppAccess | null>(null);

    const load = useCallback(async () => {
        try {
            setApps(await listAppsWithAccess(session, tenant.id));
            setError(null);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            setApps([]);
        }
    }, [session, tenant.id]);

    useEffect(() => {
        void load();
    }, [load]);

    const revoke = async (a: AppAccess) => {
        setBusy(a.grant_id);
        try {
            await revokeGrant(session, tenant.id, a.grant_id);
            setConfirm(null);
            await load();
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        } finally {
            setBusy(null);
        }
    };

    return (
        <div className="flex flex-1 flex-col overflow-y-auto">
            <div className="mx-auto w-full max-w-4xl px-6 py-8">
                <header className="mb-6 flex items-center gap-3">
                    <AppsIcon width={22} height={22} style={{ color: 'var(--drv-accent)' }} />
                    <div>
                        <h1 className="text-xl font-semibold">Apps with access</h1>
                        <p className="text-sm" style={{ color: 'var(--drv-text-secondary)' }}>
                            Apps you approved on your wallet write inside their own folder under AppData. Revoking
                            keeps the files; the app can no longer read or write them until you approve it again.
                        </p>
                    </div>
                </header>

                {error && (
                    <div className="mb-4 rounded-md px-3 py-2 text-sm" style={{ background: '#fce8e6', color: '#c5221f' }}>
                        {error}
                    </div>
                )}

                {apps === null ? (
                    <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Loading…
                    </div>
                ) : apps.length === 0 ? (
                    <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        No app has access to this Drive.
                    </div>
                ) : (
                    <div className="overflow-hidden rounded-lg border" style={{ borderColor: 'var(--drv-border)' }}>
                        <div
                            className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1.6fr)_110px_130px_90px] items-center gap-3 px-4 py-2 text-xs font-medium uppercase tracking-wide"
                            style={{ background: 'var(--drv-surface-2)', color: 'var(--drv-text-muted)' }}
                        >
                            <span>App</span>
                            <span>Folder</span>
                            <span>Permissions</span>
                            <span>Expires</span>
                            <span />
                        </div>
                        {apps.map((a) => (
                            <div
                                key={a.grant_id}
                                className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1.6fr)_110px_130px_90px] items-center gap-3 px-4 py-3 text-sm"
                                style={{ borderTop: '1px solid var(--drv-border)' }}
                            >
                                <div className="min-w-0">
                                    <div className="truncate font-medium">{a.app_name || `App ${a.app_id.slice(0, 8)}`}</div>
                                    <div className="truncate text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                        Approved {relativeTime(a.created_at)}
                                        {a.via === 'wallet-capability' ? ' on your wallet' : ''}
                                    </div>
                                </div>
                                <div className="truncate" title={a.folder} style={{ color: 'var(--drv-text-secondary)' }}>
                                    {a.folder || '—'}
                                </div>
                                <div className="flex flex-wrap gap-1">
                                    {a.scope.map((s) => (
                                        <span
                                            key={s}
                                            className="rounded px-1.5 py-0.5 text-xs"
                                            style={{ background: 'var(--drv-accent-weak)', color: 'var(--drv-text)' }}
                                        >
                                            {s}
                                        </span>
                                    ))}
                                </div>
                                <div style={{ color: 'var(--drv-text-secondary)' }}>
                                    {a.expires_at ? formatDate(a.expires_at) : 'Never'}
                                </div>
                                <div className="text-right">
                                    <button
                                        type="button"
                                        onClick={() => setConfirm(a)}
                                        disabled={busy === a.grant_id}
                                        className="rounded-md border px-2.5 py-1 text-xs font-medium transition-colors hover:bg-[var(--drv-surface-2)]"
                                        style={{ borderColor: 'var(--drv-border)', color: '#c5221f' }}
                                    >
                                        Revoke
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {confirm && (
                <div
                    className="fixed inset-0 z-40 flex items-center justify-center bg-black/30 p-4"
                    role="dialog"
                    aria-modal="true"
                    onClick={() => setConfirm(null)}
                >
                    <div
                        className="w-full max-w-md rounded-lg p-5 shadow-xl"
                        style={{ background: 'var(--drv-surface)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <h2 className="mb-2 text-base font-semibold">
                            Revoke {confirm.app_name || 'this app'}?
                        </h2>
                        <p className="mb-4 text-sm" style={{ color: 'var(--drv-text-secondary)' }}>
                            The app loses access to <span className="font-medium">{confirm.folder || 'its folder'}</span>.
                            Your files stay where they are. The app will ask for your approval again the next time it
                            needs storage.
                        </p>
                        <div className="flex justify-end gap-2">
                            <button
                                type="button"
                                onClick={() => setConfirm(null)}
                                className="rounded-md px-3 py-1.5 text-sm"
                                style={{ color: 'var(--drv-text-secondary)' }}
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={() => void revoke(confirm)}
                                disabled={busy === confirm.grant_id}
                                className="rounded-md px-3 py-1.5 text-sm font-medium text-white"
                                style={{ background: '#c5221f' }}
                            >
                                {busy === confirm.grant_id ? 'Revoking…' : 'Revoke access'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
