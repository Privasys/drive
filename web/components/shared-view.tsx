'use client';

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import { downloadFile, listShared, type SharedItem } from '~/lib/drive-api';
import { avatarColor, formatBytes, granteeLabel, initials } from '~/lib/format';
import { SharedBrowser } from './shared-browser';
import { ChevronRight, DownloadIcon, FileIcon, FolderIcon, PeopleIcon } from './icons';

export function SharedView({ session }: { session: SealedSession }) {
    const [items, setItems] = useState<SharedItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [browsing, setBrowsing] = useState<SharedItem | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            setItems(await listShared(session));
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not load shared items.');
        } finally {
            setLoading(false);
        }
    }, [session]);

    useEffect(() => {
        void load();
    }, [load]);

    const download = async (it: SharedItem) => {
        try {
            const bytes = await downloadFile(session, it.tenant_id, it.node_id);
            const blob = new Blob([bytes as BlobPart]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = it.name;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Download failed.');
        }
    };

    if (browsing) {
        return (
            <div className="flex h-full flex-col">
                <div className="flex items-center gap-1 border-b px-5 py-3.5" style={{ borderColor: 'var(--drv-border)' }}>
                    <button
                        onClick={() => setBrowsing(null)}
                        className="rounded px-1.5 py-0.5 text-[15px] font-medium hover:bg-[var(--drv-hover)]"
                        style={{ color: 'var(--drv-text-muted)' }}
                    >
                        Shared with me
                    </button>
                    <ChevronRight style={{ color: 'var(--drv-text-muted)' }} />
                    <span className="truncate text-[15px] font-medium">{browsing.name}</span>
                </div>
                <div className="drv-scroll min-h-0 flex-1 overflow-auto p-4">
                    <SharedBrowser
                        session={session}
                        tenantID={browsing.tenant_id}
                        rootID={browsing.node_id}
                        rootName={browsing.name}
                    />
                </div>
            </div>
        );
    }

    return (
        <div className="flex h-full flex-col">
            <div className="border-b px-5 py-3.5" style={{ borderColor: 'var(--drv-border)' }}>
                <h2 className="text-[15px] font-medium">Shared with me</h2>
            </div>
            <div className="drv-scroll min-h-0 flex-1 overflow-auto p-4">
                {error && (
                    <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                        {error}
                    </div>
                )}
                {loading ? (
                    <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Loading…
                    </div>
                ) : items.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-24 text-center">
                        <PeopleIcon width={52} height={52} style={{ color: 'var(--drv-border)' }} />
                        <p className="mt-4 text-sm font-medium">Nothing shared with you yet</p>
                        <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                            Files and folders others share with you will appear here.
                        </p>
                    </div>
                ) : (
                    <div
                        className="overflow-hidden rounded-xl border"
                        style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                    >
                        {items.map((it) => (
                            <div
                                key={it.grant_id}
                                className={`group flex items-center gap-3 px-4 py-3 hover:bg-[var(--drv-hover)]${it.kind === 'folder' ? ' cursor-pointer' : ''}`}
                                style={{ borderBottom: '1px solid var(--drv-border)' }}
                                onClick={it.kind === 'folder' ? () => setBrowsing(it) : undefined}
                            >
                                {it.kind === 'folder' ? (
                                    <FolderIcon width={22} height={22} style={{ color: 'var(--drv-accent)' }} />
                                ) : (
                                    <FileIcon width={22} height={22} style={{ color: 'var(--drv-text-muted)' }} />
                                )}
                                <div className="min-w-0 flex-1">
                                    <div className="truncate text-sm font-medium">{it.name}</div>
                                    <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                        <span
                                            className="flex h-4 w-4 items-center justify-center rounded-full text-[8px] font-semibold text-white"
                                            style={{ background: avatarColor(it.shared_by) }}
                                        >
                                            {initials(granteeLabel(`subject:${it.shared_by}`))}
                                        </span>
                                        Shared by {granteeLabel(`subject:${it.shared_by}`)}
                                        {it.kind === 'file' && <> · {formatBytes(it.size_bytes)}</>}
                                    </div>
                                </div>
                                <span
                                    className="rounded-full px-2 py-0.5 text-xs"
                                    style={{ background: 'var(--drv-accent-weak)', color: 'var(--drv-accent)' }}
                                >
                                    {it.scope === 'write' ? 'Can edit' : 'Can view'}
                                </span>
                                {it.kind === 'file' && (
                                    <button
                                        title="Download"
                                        onClick={() => void download(it)}
                                        className="flex h-8 w-8 items-center justify-center rounded-lg opacity-0 transition-opacity hover:bg-[var(--drv-selected)] group-hover:opacity-100"
                                        style={{ color: 'var(--drv-text-muted)' }}
                                    >
                                        <DownloadIcon width={18} height={18} />
                                    </button>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
