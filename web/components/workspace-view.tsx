'use client';

import { useEffect, useMemo, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import { deleteNode, downloadFile, exportWorkspaceZip, type DriveNode, type Tenant } from '~/lib/drive-api';
import { formatBytes, relativeTime } from '~/lib/format';
import { buildTree, parseWorkspaceManifest, summarise, type TreeDir, type WorkspaceManifest } from '~/lib/workspace-manifest';
import { DownloadIcon, FileIcon, FolderIcon, TrashIcon, WorkspaceIcon } from './icons';

// A workspace snapshot as one item (plans/drive-as-remote-disk.md, user
// model): "Harness workspace · 340 MB · saved 2 min ago", browsable
// read-only from its manifest, with Export as ZIP and Delete. The tree is
// never exploded into the file list.

export function WorkspaceView({
    session,
    tenant,
    node,
    onBack,
    onDeleted
}: {
    session: SealedSession;
    tenant: Tenant;
    node: DriveNode;
    onBack: () => void;
    onDeleted: () => void;
}) {
    const [manifest, setManifest] = useState<WorkspaceManifest | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState<'export' | 'delete' | null>(null);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [cwd, setCwd] = useState<string[]>([]);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                if (!node.workspace_manifest_id) throw new Error('not a workspace');
                const bytes = await downloadFile(session, tenant.id, node.workspace_manifest_id);
                if (!cancelled) setManifest(parseWorkspaceManifest(bytes));
            } catch (e) {
                if (!cancelled) setError(e instanceof Error ? e.message : String(e));
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [session, tenant.id, node.workspace_manifest_id]);

    const summary = useMemo(() => (manifest ? summarise(manifest) : null), [manifest]);
    const tree = useMemo(() => (manifest ? buildTree(manifest) : null), [manifest]);
    const dir: TreeDir | null = useMemo(() => {
        if (!tree) return null;
        let d: TreeDir | undefined = tree;
        for (const p of cwd) {
            d = d?.dirs.get(p);
            if (!d) return tree;
        }
        return d ?? tree;
    }, [tree, cwd]);

    const exportZip = async () => {
        setBusy('export');
        try {
            const bytes = await exportWorkspaceZip(session, tenant.id, node.id);
            const blob = new Blob([bytes as BlobPart], { type: 'application/zip' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${node.name || 'workspace'}.zip`;
            a.click();
            setTimeout(() => URL.revokeObjectURL(url), 10_000);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        } finally {
            setBusy(null);
        }
    };

    const remove = async () => {
        setBusy('delete');
        try {
            await deleteNode(session, tenant.id, node.id);
            onDeleted();
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            setBusy(null);
        }
    };

    const dirs = dir ? [...dir.dirs.values()].sort((a, b) => a.name.localeCompare(b.name)) : [];
    const files = dir ? [...dir.files].sort((a, b) => a.path.localeCompare(b.path)) : [];

    return (
        <div className="flex flex-1 flex-col overflow-y-auto">
            <div className="mx-auto w-full max-w-4xl px-6 py-6">
                <button
                    type="button"
                    onClick={onBack}
                    className="mb-3 inline-flex items-center gap-1 rounded-md text-sm transition-colors hover:opacity-80"
                    style={{ color: 'var(--drv-text-secondary)' }}
                >
                    ← Back
                </button>
                <header className="mb-5 flex flex-wrap items-center gap-3">
                    <WorkspaceIcon width={28} height={28} style={{ color: 'var(--drv-accent)' }} />
                    <div className="min-w-0 flex-1">
                        <h1 className="truncate text-lg font-semibold">{node.name}</h1>
                        <p className="text-sm" style={{ color: 'var(--drv-text-secondary)' }}>
                            Workspace snapshot
                            {summary && (
                                <>
                                    {' · '}
                                    {formatBytes(summary.bytes)} · {summary.fileCount.toLocaleString()} files
                                    {summary.savedAt ? ` · saved ${relativeTime(summary.savedAt)}` : ''}
                                </>
                            )}
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            onClick={() => void exportZip()}
                            disabled={!manifest || busy !== null}
                            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors hover:bg-[var(--drv-surface-2)] disabled:opacity-50"
                            style={{ borderColor: 'var(--drv-border)' }}
                        >
                            <DownloadIcon width={16} height={16} />
                            {busy === 'export' ? 'Preparing…' : 'Export as ZIP'}
                        </button>
                        <button
                            type="button"
                            onClick={() => setConfirmDelete(true)}
                            disabled={busy !== null}
                            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors hover:bg-[var(--drv-surface-2)] disabled:opacity-50"
                            style={{ borderColor: 'var(--drv-border)', color: '#c5221f' }}
                        >
                            <TrashIcon width={16} height={16} />
                            Delete
                        </button>
                    </div>
                </header>

                {error && (
                    <div className="mb-4 rounded-md px-3 py-2 text-sm" style={{ background: '#fce8e6', color: '#c5221f' }}>
                        {error}
                    </div>
                )}

                {!manifest && !error ? (
                    <div className="py-16 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Reading the snapshot…
                    </div>
                ) : manifest ? (
                    <div className="overflow-hidden rounded-lg border" style={{ borderColor: 'var(--drv-border)' }}>
                        <div
                            className="flex items-center gap-1 px-4 py-2 text-sm"
                            style={{ background: 'var(--drv-surface-2)', color: 'var(--drv-text-secondary)' }}
                        >
                            <button type="button" className="hover:underline" onClick={() => setCwd([])}>
                                {node.name}
                            </button>
                            {cwd.map((p, i) => (
                                <span key={i} className="flex items-center gap-1">
                                    <span>/</span>
                                    <button type="button" className="hover:underline" onClick={() => setCwd(cwd.slice(0, i + 1))}>
                                        {p}
                                    </button>
                                </span>
                            ))}
                            <span className="ml-auto text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                read-only
                            </span>
                        </div>
                        {dirs.length === 0 && files.length === 0 ? (
                            <div className="px-4 py-10 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                Empty snapshot.
                            </div>
                        ) : (
                            <ul>
                                {dirs.map((d) => (
                                    <li
                                        key={`d:${d.name}`}
                                        className="flex cursor-pointer items-center gap-3 px-4 py-2 text-sm hover:bg-[var(--drv-surface-2)]"
                                        style={{ borderTop: '1px solid var(--drv-border)' }}
                                        onClick={() => setCwd([...cwd, d.name])}
                                    >
                                        <FolderIcon width={20} height={20} style={{ color: 'var(--drv-accent)' }} />
                                        <span className="truncate font-medium">{d.name}</span>
                                    </li>
                                ))}
                                {files.map((f) => (
                                    <li
                                        key={`f:${f.path}`}
                                        className="flex items-center gap-3 px-4 py-2 text-sm"
                                        style={{ borderTop: '1px solid var(--drv-border)' }}
                                    >
                                        <FileIcon width={20} height={20} style={{ color: 'var(--drv-text-muted)' }} />
                                        <span className="min-w-0 flex-1 truncate">{f.path}</span>
                                        <span className="shrink-0 text-xs tabular-nums" style={{ color: 'var(--drv-text-muted)' }}>
                                            {formatBytes(f.size)}
                                        </span>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                ) : null}
            </div>

            {confirmDelete && (
                <div
                    className="fixed inset-0 z-40 flex items-center justify-center bg-black/30 p-4"
                    role="dialog"
                    aria-modal="true"
                    onClick={() => setConfirmDelete(false)}
                >
                    <div
                        className="w-full max-w-md rounded-lg p-5 shadow-xl"
                        style={{ background: 'var(--drv-surface)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <h2 className="mb-2 text-base font-semibold">Delete this snapshot?</h2>
                        <p className="mb-4 text-sm" style={{ color: 'var(--drv-text-secondary)' }}>
                            &ldquo;{node.name}&rdquo; and everything in it will be removed from your Drive. The app that
                            wrote it keeps only what is still in its own cache.
                        </p>
                        <div className="flex justify-end gap-2">
                            <button
                                type="button"
                                onClick={() => setConfirmDelete(false)}
                                className="rounded-md px-3 py-1.5 text-sm"
                                style={{ color: 'var(--drv-text-secondary)' }}
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={() => void remove()}
                                disabled={busy === 'delete'}
                                className="rounded-md px-3 py-1.5 text-sm font-medium text-white"
                                style={{ background: '#c5221f' }}
                            >
                                {busy === 'delete' ? 'Deleting…' : 'Delete'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
