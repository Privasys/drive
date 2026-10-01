'use client';

// Read-only browser for a folder shared with the caller (via a grant or a
// redeemed link). The backend authorises each listing/download through the
// grant cascade, so this works without tenant membership. Click a folder to
// open it, a file to preview (or download when not previewable).

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import { downloadFile, listChildren, type DriveNode } from '~/lib/drive-api';
import { formatBytes, kindLabel } from '~/lib/format';
import { FileViewer, canPreview } from './file-viewer';
import { ChevronRight, DownloadIcon, FileIcon, FolderIcon } from './icons';

interface Crumb {
    id: string;
    name: string;
}

export function SharedBrowser({
    session,
    tenantID,
    rootID,
    rootName
}: {
    session: SealedSession;
    tenantID: string;
    rootID: string;
    rootName: string;
}) {
    const [path, setPath] = useState<Crumb[]>([{ id: rootID, name: rootName }]);
    const [nodes, setNodes] = useState<DriveNode[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [viewNode, setViewNode] = useState<DriveNode | null>(null);
    const current = path[path.length - 1];

    const reload = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const kids = await listChildren(session, tenantID, current.id);
            kids.sort((a, b) =>
                a.kind !== b.kind ? (a.kind === 'folder' ? -1 : 1) : a.name.localeCompare(b.name)
            );
            setNodes(kids);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not open this folder.');
        } finally {
            setLoading(false);
        }
    }, [session, tenantID, current.id]);

    useEffect(() => {
        void reload();
    }, [reload]);

    const download = async (n: DriveNode) => {
        try {
            const bytes = await downloadFile(session, tenantID, n.id);
            const blob = new Blob([bytes as BlobPart], { type: n.mime_hint || 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = n.name;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Download failed.');
        }
    };

    const open = (n: DriveNode) => {
        if (n.kind === 'folder') setPath((p) => [...p, { id: n.id, name: n.name }]);
        else if (canPreview(n)) setViewNode(n);
        else void download(n);
    };

    return (
        <div>
            {/* Breadcrumbs */}
            <nav className="mb-3 flex min-w-0 items-center gap-1 text-[15px]">
                {path.map((c, i) => (
                    <span key={`${c.id}-${i}`} className="flex min-w-0 items-center gap-1">
                        {i > 0 && <ChevronRight className="shrink-0" style={{ color: 'var(--drv-text-muted)' }} />}
                        <button
                            onClick={() => setPath((p) => p.slice(0, i + 1))}
                            className="truncate rounded px-1.5 py-0.5 font-medium hover:bg-[var(--drv-hover)]"
                            style={{ color: i === path.length - 1 ? 'var(--drv-text)' : 'var(--drv-text-muted)' }}
                        >
                            {c.name}
                        </button>
                    </span>
                ))}
            </nav>

            {error && (
                <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    {error}
                </div>
            )}

            <div
                className="overflow-hidden rounded-xl border"
                style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
            >
                {loading ? (
                    <div className="py-14 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Loading…
                    </div>
                ) : nodes.length === 0 ? (
                    <div className="py-14 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        This folder is empty.
                    </div>
                ) : (
                    nodes.map((n) => (
                        <div
                            key={n.id}
                            className="group flex cursor-pointer items-center gap-3 px-4 py-2.5 hover:bg-[var(--drv-hover)]"
                            style={{ borderBottom: '1px solid var(--drv-border)' }}
                            onClick={() => open(n)}
                        >
                            {n.kind === 'folder' ? (
                                <FolderIcon width={22} height={22} style={{ color: 'var(--drv-accent)' }} />
                            ) : (
                                <FileIcon width={22} height={22} style={{ color: 'var(--drv-text-muted)' }} />
                            )}
                            <span className="min-w-0 flex-1 truncate text-sm font-medium">{n.name}</span>
                            <span className="hidden text-sm sm:block" style={{ color: 'var(--drv-text-muted)' }}>
                                {n.kind === 'folder' ? 'Folder' : kindLabel(n.name, n.mime_hint)}
                            </span>
                            <span className="hidden w-20 text-right text-sm sm:block" style={{ color: 'var(--drv-text-muted)' }}>
                                {n.kind === 'folder' ? '' : formatBytes(n.size_bytes)}
                            </span>
                            {n.kind === 'file' && (
                                <button
                                    title="Download"
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        void download(n);
                                    }}
                                    className="flex h-8 w-8 items-center justify-center rounded-lg opacity-0 transition-opacity hover:bg-[var(--drv-selected)] group-hover:opacity-100"
                                    style={{ color: 'var(--drv-text-muted)' }}
                                >
                                    <DownloadIcon width={18} height={18} />
                                </button>
                            )}
                        </div>
                    ))
                )}
            </div>

            {viewNode && (
                <FileViewer
                    session={session}
                    tenantID={tenantID}
                    node={viewNode}
                    onClose={() => setViewNode(null)}
                    onDownload={(n) => void download(n)}
                />
            )}
        </div>
    );
}
