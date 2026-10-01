'use client';

// Destination picker for the "Move" action: browse the drive's folders and
// drop the selection into the chosen one (or the root). Folders that are
// part of the selection are not offerable as targets.

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import { listChildren, type DriveNode } from '~/lib/drive-api';
import { ChevronRight, CloseIcon, FolderIcon } from './icons';

interface Crumb {
    id: string | null;
    name: string;
}

export function MoveDialog({
    session,
    tenantID,
    moving,
    onCancel,
    onMove
}: {
    session: SealedSession;
    tenantID: string;
    moving: Set<string>;
    onCancel: () => void;
    onMove: (destParentID: string | null) => void;
}) {
    const [path, setPath] = useState<Crumb[]>([{ id: null, name: 'My Drive' }]);
    const [folders, setFolders] = useState<DriveNode[]>([]);
    const [loading, setLoading] = useState(true);
    const current = path[path.length - 1];

    const load = useCallback(async () => {
        setLoading(true);
        try {
            const kids = await listChildren(session, tenantID, current.id);
            setFolders(kids.filter((n) => n.kind === 'folder' && !moving.has(n.id)));
        } finally {
            setLoading(false);
        }
    }, [session, tenantID, current.id, moving]);

    useEffect(() => {
        void load();
    }, [load]);

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onCancel}>
            <div
                className="w-full max-w-md overflow-hidden rounded-2xl shadow-2xl"
                style={{ background: 'var(--drv-surface)' }}
                onClick={(e) => e.stopPropagation()}
            >
                <div className="flex items-center gap-3 border-b px-5 py-4" style={{ borderColor: 'var(--drv-border)' }}>
                    <div className="min-w-0 flex-1 text-[15px] font-semibold">
                        Move {moving.size} item{moving.size === 1 ? '' : 's'}
                    </div>
                    <button onClick={onCancel} className="rounded-lg p-1 hover:bg-[var(--drv-hover)]">
                        <CloseIcon />
                    </button>
                </div>

                {/* Breadcrumbs */}
                <div className="flex items-center gap-1 border-b px-5 py-2 text-sm" style={{ borderColor: 'var(--drv-border)' }}>
                    {path.map((c, i) => (
                        <span key={`${c.id ?? 'root'}-${i}`} className="flex items-center gap-1">
                            {i > 0 && <ChevronRight style={{ color: 'var(--drv-text-muted)' }} />}
                            <button
                                onClick={() => setPath((p) => p.slice(0, i + 1))}
                                className="rounded px-1 py-0.5 hover:bg-[var(--drv-hover)]"
                                style={{ color: i === path.length - 1 ? 'var(--drv-text)' : 'var(--drv-text-muted)' }}
                            >
                                {c.name}
                            </button>
                        </span>
                    ))}
                </div>

                <div className="max-h-[46vh] min-h-[160px] overflow-auto p-2">
                    {loading ? (
                        <div className="py-10 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                            Loading…
                        </div>
                    ) : folders.length === 0 ? (
                        <div className="py-10 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                            No subfolders here.
                        </div>
                    ) : (
                        folders.map((f) => (
                            <button
                                key={f.id}
                                onClick={() => setPath((p) => [...p, { id: f.id, name: f.name }])}
                                className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm hover:bg-[var(--drv-hover)]"
                            >
                                <FolderIcon width={20} height={20} style={{ color: 'var(--drv-accent)' }} />
                                <span className="flex-1 truncate">{f.name}</span>
                                <ChevronRight style={{ color: 'var(--drv-text-muted)' }} />
                            </button>
                        ))
                    )}
                </div>

                <div className="flex items-center justify-between gap-2 border-t px-5 py-3" style={{ borderColor: 'var(--drv-border)' }}>
                    <span className="truncate text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                        Destination: {current.name}
                    </span>
                    <div className="flex gap-2">
                        <button onClick={onCancel} className="rounded-full px-4 py-1.5 text-sm hover:bg-[var(--drv-hover)]">
                            Cancel
                        </button>
                        <button
                            onClick={() => onMove(current.id)}
                            className="drv-btn-primary rounded-full px-4 py-1.5 text-sm"
                        >
                            Move here
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
