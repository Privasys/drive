'use client';

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import { getQuota, type Quota, type Tenant } from '~/lib/drive-api';
import { formatBytes } from '~/lib/format';
import { StorageIcon } from './icons';

// The one storage gauge of the user model: "412 MB of 1 GB", with a
// by-folder breakdown on demand so the user sees what each app costs them
// (plans/drive-as-remote-disk.md). Fed by GET /v1/tenants/{t}/quota.

export function StorageGauge({
    session,
    tenant,
    onOpenFolder
}: {
    session: SealedSession;
    tenant: Tenant;
    /** Jump to a folder from the breakdown (optional). */
    onOpenFolder?: (nodeID: string, name: string) => void;
}) {
    const [quota, setQuota] = useState<Quota | null>(null);
    const [open, setOpen] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async () => {
        try {
            setQuota(await getQuota(session, tenant.id));
            setError(null);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        }
    }, [session, tenant.id]);

    useEffect(() => {
        void load();
        // Refresh while the panel is mounted: uploads and app writes move it.
        const t = setInterval(() => void load(), 60_000);
        return () => clearInterval(t);
    }, [load]);

    if (!quota && !error) return null;

    const used = quota?.used_bytes ?? 0;
    const limit = quota?.limit_bytes ?? 0;
    const unlimited = quota?.unlimited ?? true;
    const pct = unlimited || limit <= 0 ? 0 : Math.min(100, Math.round((used / limit) * 100));
    const warn = pct >= 90;
    const label = unlimited ? `${formatBytes(used)} used` : `${formatBytes(used)} of ${formatBytes(limit)}`;

    return (
        <div className="border-t px-3 py-3" style={{ borderColor: 'var(--drv-border)' }}>
            <button
                type="button"
                onClick={() => setOpen((o) => !o)}
                className="flex w-full items-center gap-2 rounded-md text-left text-sm transition-colors hover:opacity-80"
                aria-expanded={open}
                title="Storage"
            >
                <StorageIcon width={16} height={16} style={{ color: 'var(--drv-text-secondary)' }} />
                <span className="flex-1 truncate" style={{ color: 'var(--drv-text-secondary)' }}>
                    {error ? 'Storage unavailable' : label}
                </span>
            </button>
            {!unlimited && (
                <div
                    className="mt-2 h-1.5 w-full overflow-hidden rounded-full"
                    style={{ background: 'var(--drv-border)' }}
                    role="progressbar"
                    aria-valuenow={pct}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-label={label}
                >
                    <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${pct}%`, background: warn ? '#d93025' : 'var(--drv-accent)' }}
                    />
                </div>
            )}
            {open && quota && (
                <div className="mt-3 space-y-2 text-xs" style={{ color: 'var(--drv-text-secondary)' }}>
                    <Breakdown
                        title="By folder"
                        rows={quota.breakdown ?? []}
                        total={used}
                        onOpenFolder={onOpenFolder}
                    />
                    {quota.apps && quota.apps.length > 0 && (
                        <Breakdown title="By app" rows={quota.apps} total={used} onOpenFolder={onOpenFolder} />
                    )}
                </div>
            )}
        </div>
    );
}

function Breakdown({
    title,
    rows,
    total,
    onOpenFolder
}: {
    title: string;
    rows: Quota['breakdown'] & {};
    total: number;
    onOpenFolder?: (nodeID: string, name: string) => void;
}) {
    if (rows.length === 0) {
        return (
            <div>
                <div className="mb-1 font-medium">{title}</div>
                <div style={{ color: 'var(--drv-text-muted)' }}>Nothing stored yet.</div>
            </div>
        );
    }
    return (
        <div>
            <div className="mb-1 font-medium">{title}</div>
            <ul className="space-y-1">
                {rows.slice(0, 12).map((r) => {
                    const share = total > 0 ? Math.round((r.bytes / total) * 100) : 0;
                    const clickable = r.kind === 'folder' && !!onOpenFolder;
                    return (
                        <li key={r.node_id} className="flex items-center gap-2">
                            <button
                                type="button"
                                disabled={!clickable}
                                onClick={() => clickable && onOpenFolder?.(r.node_id, r.name)}
                                className={`min-w-0 flex-1 truncate text-left ${clickable ? 'hover:underline' : 'cursor-default'}`}
                                title={r.name}
                            >
                                {r.name}
                            </button>
                            <span className="shrink-0 tabular-nums" style={{ color: 'var(--drv-text-muted)' }}>
                                {formatBytes(r.bytes)}
                                {share > 0 ? ` · ${share}%` : ''}
                            </span>
                        </li>
                    );
                })}
            </ul>
        </div>
    );
}
