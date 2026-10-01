'use client';

import { useCallback, useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    deleteAppFolderPath,
    downloadAppFolderFile,
    listAppFolder,
    listAppFolders,
    type AppFolder,
    type AppFolderEntry,
    type AppFolderListing
} from '~/lib/drive-api';
import { formatBytes, relativeTime } from '~/lib/format';
import { AppsIcon, DownloadIcon, FileIcon, FolderIcon, TrashIcon } from './icons';

// "App folders": the working files an app keeps for you in its own storage,
// shown here without a copy. Each app you approved on your wallet holds one
// folder for you, under your own key; Drive opens it with your own session
// token, forwarded to the app's enclave, and shows what is there. You can
// read, take a copy, and delete. Nothing here is written by Drive: what the
// app writes is its work; ending the app's access altogether is done in
// your wallet, under Access.

const encoder = new TextDecoder();

export function AppFoldersView({ session, token }: { session: SealedSession; token: string | undefined }) {
    const [apps, setApps] = useState<AppFolder[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [open, setOpen] = useState<AppFolder | null>(null);
    const [path, setPath] = useState('');
    const [listing, setListing] = useState<AppFolderListing | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [confirm, setConfirm] = useState<AppFolderEntry | null>(null);
    const [preview, setPreview] = useState<{ name: string; text: string } | null>(null);

    const loadApps = useCallback(async () => {
        if (!token) {
            setApps([]);
            setError('Sign in again to see your app folders: this needs your own session token.');
            return;
        }
        try {
            setApps(await listAppFolders(session, token));
            setError(null);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            setApps([]);
        }
    }, [session, token]);

    const loadListing = useCallback(
        async (app: AppFolder, p: string) => {
            if (!token) return;
            setListing(null);
            try {
                setListing(await listAppFolder(session, token, app.app_id, p));
                setError(null);
            } catch (e) {
                setError(e instanceof Error ? e.message : String(e));
                setListing({ label: app.label, path: p, entries: [], used_bytes: 0 });
            }
        },
        [session, token]
    );

    useEffect(() => {
        void loadApps();
    }, [loadApps]);

    useEffect(() => {
        if (open) void loadListing(open, path);
    }, [open, path, loadListing]);

    const enter = (app: AppFolder) => {
        setOpen(app);
        setPath('');
        setPreview(null);
    };

    const into = (e: AppFolderEntry) => {
        const next = path ? `${path}/${e.name}` : e.name;
        if (e.dir) {
            setPath(next);
            setPreview(null);
            return;
        }
        void (async () => {
            if (!open || !token) return;
            setBusy(next);
            try {
                const bytes = await downloadAppFolderFile(session, token, open.app_id, next);
                if (isTextName(e.name) && bytes.byteLength <= 512 * 1024) {
                    setPreview({ name: e.name, text: encoder.decode(bytes) });
                } else {
                    saveAs(e.name, bytes);
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : String(err));
            } finally {
                setBusy(null);
            }
        })();
    };

    const download = async (e: AppFolderEntry) => {
        if (!open || !token) return;
        const next = path ? `${path}/${e.name}` : e.name;
        setBusy(next);
        try {
            saveAs(e.name, await downloadAppFolderFile(session, token, open.app_id, next));
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setBusy(null);
        }
    };

    const remove = async (e: AppFolderEntry) => {
        if (!open || !token) return;
        const next = path ? `${path}/${e.name}` : e.name;
        setBusy(next);
        try {
            await deleteAppFolderPath(session, token, open.app_id, next);
            setConfirm(null);
            await loadListing(open, path);
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setBusy(null);
        }
    };

    const crumbs = path ? path.split('/') : [];

    return (
        <div className="flex flex-1 flex-col overflow-y-auto">
            <div className="mx-auto w-full max-w-4xl px-6 py-8">
                <header className="mb-6 flex items-center gap-3">
                    <AppsIcon width={22} height={22} style={{ color: 'var(--drv-accent)' }} />
                    <div>
                        <h1 className="text-xl font-semibold">App folders</h1>
                        <p className="text-sm" style={{ color: 'var(--drv-text-secondary)' }}>
                            The working files an app keeps for you in its own storage, under your own key. Nothing is
                            copied here: Drive opens the folder with your session and shows what is there. You can read,
                            take a copy and delete; the app&apos;s access itself ends in your wallet, under Access.
                        </p>
                    </div>
                </header>

                {error && (
                    <div className="mb-4 rounded-md px-3 py-2 text-sm" style={{ background: '#fce8e6', color: '#c5221f' }}>
                        {error}
                    </div>
                )}

                {!open ? (
                    apps === null ? (
                        <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                            Asking your apps…
                        </div>
                    ) : apps.length === 0 ? (
                        <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                            No app keeps a folder for you yet.
                        </div>
                    ) : (
                        <div className="overflow-hidden rounded-lg border" style={{ borderColor: 'var(--drv-border)' }}>
                            {apps.map((a) => (
                                <button
                                    key={a.app_id}
                                    type="button"
                                    onClick={() => enter(a)}
                                    className="flex w-full items-center gap-3 px-4 py-3 text-left text-sm hover:bg-[var(--drv-surface-2)]"
                                    style={{ borderBottom: '1px solid var(--drv-border)' }}
                                >
                                    <FolderIcon width={18} height={18} style={{ color: 'var(--drv-accent)' }} />
                                    <span className="flex-1">
                                        <span className="font-medium">{a.display_name || a.name}</span>
                                        <span className="ml-2" style={{ color: 'var(--drv-text-muted)' }}>
                                            {a.label}
                                        </span>
                                    </span>
                                    <span style={{ color: 'var(--drv-text-muted)' }}>{formatBytes(a.used_bytes)}</span>
                                </button>
                            ))}
                        </div>
                    )
                ) : (
                    <>
                        <nav className="mb-3 flex flex-wrap items-center gap-1 text-sm">
                            <button type="button" className="hover:underline" onClick={() => setOpen(null)}>
                                App folders
                            </button>
                            <span style={{ color: 'var(--drv-text-muted)' }}>›</span>
                            <button type="button" className="hover:underline" onClick={() => setPath('')}>
                                {open.display_name || open.name}
                            </button>
                            {crumbs.map((c, i) => (
                                <span key={`${i}-${c}`} className="flex items-center gap-1">
                                    <span style={{ color: 'var(--drv-text-muted)' }}>›</span>
                                    <button
                                        type="button"
                                        className="hover:underline"
                                        onClick={() => setPath(crumbs.slice(0, i + 1).join('/'))}
                                    >
                                        {c}
                                    </button>
                                </span>
                            ))}
                        </nav>
                        {preview ? (
                            <div className="rounded-lg border" style={{ borderColor: 'var(--drv-border)' }}>
                                <div
                                    className="flex items-center justify-between px-4 py-2 text-xs"
                                    style={{ background: 'var(--drv-surface-2)', color: 'var(--drv-text-muted)' }}
                                >
                                    <span>{preview.name}</span>
                                    <button type="button" className="hover:underline" onClick={() => setPreview(null)}>
                                        Close
                                    </button>
                                </div>
                                <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap px-4 py-3 text-xs">{preview.text}</pre>
                            </div>
                        ) : listing === null ? (
                            <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                Loading…
                            </div>
                        ) : listing.entries.length === 0 ? (
                            <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                Empty.
                            </div>
                        ) : (
                            <div className="overflow-hidden rounded-lg border" style={{ borderColor: 'var(--drv-border)' }}>
                                <div
                                    className="grid grid-cols-[minmax(0,1fr)_110px_130px_90px] items-center gap-3 px-4 py-2 text-xs font-medium"
                                    style={{ background: 'var(--drv-surface-2)', color: 'var(--drv-text-muted)' }}
                                >
                                    <span>Name</span>
                                    <span>Size</span>
                                    <span>Modified</span>
                                    <span />
                                </div>
                                {listing.entries.map((e) => {
                                    const full = path ? `${path}/${e.name}` : e.name;
                                    return (
                                        <div
                                            key={e.name}
                                            className="grid grid-cols-[minmax(0,1fr)_110px_130px_90px] items-center gap-3 px-4 py-2 text-sm"
                                            style={{ borderTop: '1px solid var(--drv-border)' }}
                                        >
                                            <button
                                                type="button"
                                                className="flex min-w-0 items-center gap-2 text-left hover:underline"
                                                onClick={() => into(e)}
                                                disabled={busy === full}
                                            >
                                                {e.dir ? (
                                                    <FolderIcon width={16} height={16} style={{ color: 'var(--drv-accent)' }} />
                                                ) : (
                                                    <FileIcon width={16} height={16} style={{ color: 'var(--drv-text-muted)' }} />
                                                )}
                                                <span className="truncate">{e.name}</span>
                                            </button>
                                            <span style={{ color: 'var(--drv-text-muted)' }}>{e.dir ? '—' : formatBytes(e.size)}</span>
                                            <span style={{ color: 'var(--drv-text-muted)' }}>{relativeTime(e.modified)}</span>
                                            <span className="flex justify-end gap-2">
                                                {!e.dir && (
                                                    <button
                                                        type="button"
                                                        title="Download"
                                                        onClick={() => void download(e)}
                                                        disabled={busy === full}
                                                    >
                                                        <DownloadIcon width={16} height={16} />
                                                    </button>
                                                )}
                                                <button
                                                    type="button"
                                                    title="Delete"
                                                    onClick={() => setConfirm(e)}
                                                    disabled={busy === full}
                                                >
                                                    <TrashIcon width={16} height={16} />
                                                </button>
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                        {listing && (
                            <p className="mt-3 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                {formatBytes(listing.used_bytes)} in this folder, kept by {open.display_name || open.name} on{' '}
                                {open.hostname}.
                            </p>
                        )}
                    </>
                )}
            </div>

            {confirm && open && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30" onClick={() => setConfirm(null)}>
                    <div
                        className="w-full max-w-md rounded-lg p-5 shadow-lg"
                        style={{ background: 'var(--drv-surface)' }}
                        onClick={(ev) => ev.stopPropagation()}
                    >
                        <h2 className="mb-2 text-base font-semibold">Delete {confirm.dir ? 'folder' : 'file'}?</h2>
                        <p className="mb-4 text-sm" style={{ color: 'var(--drv-text-secondary)' }}>
                            “{confirm.name}” is removed from the folder {open.display_name || open.name} keeps for you. The
                            app will not have it any more, and it cannot be recovered.
                        </p>
                        <div className="flex justify-end gap-2">
                            <button type="button" className="rounded-md px-3 py-1.5 text-sm" onClick={() => setConfirm(null)}>
                                Cancel
                            </button>
                            <button
                                type="button"
                                className="rounded-md px-3 py-1.5 text-sm text-white"
                                style={{ background: '#c5221f' }}
                                disabled={busy !== null}
                                onClick={() => void remove(confirm)}
                            >
                                {busy ? 'Deleting…' : 'Delete'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function isTextName(name: string): boolean {
    return /\.(md|txt|yaml|yml|json|jsonl|log|csv|toml|ts|tsx|js|py|go|sh|html|css)$/i.test(name) || !/\./.test(name);
}

function saveAs(name: string, bytes: Uint8Array): void {
    const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
