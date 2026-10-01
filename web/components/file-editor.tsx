'use client';

// Editing a text file in the Drive, with its history beside it.
//
// Three views of one file: what it says now and can be changed to, what it
// said before, and what changed between two revisions. Saving carries the
// revision the editor loaded, so a save that would overwrite somebody
// else's is refused by the enclave rather than silently winning.

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    diffVersions,
    downloadFile,
    listVersions,
    readVersion,
    restoreVersion,
    StaleWriteError,
    writeTextContent,
    type DiffResult,
    type DriveNode,
    type FileVersion
} from '~/lib/drive-api';
import { summariseDiff, toDiffRows } from '~/lib/diff-view';
import { formatBytes, formatDate } from '~/lib/format';
import { CloseIcon, FileIcon } from './icons';

type Tab = 'edit' | 'history' | 'changes';

export function FileEditor({
    session,
    tenantID,
    node,
    onClose,
    onSaved
}: {
    session: SealedSession;
    tenantID: string;
    node: DriveNode;
    onClose: () => void;
    /** Told after a save or restore, so the listing behind can refresh. */
    onSaved: () => void;
}) {
    const [tab, setTab] = useState<Tab>('edit');
    const [text, setText] = useState('');
    const [saved, setSaved] = useState('');
    const [rev, setRev] = useState<number>(node.rev ?? 0);
    const [loading, setLoading] = useState(true);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [stale, setStale] = useState<number | null>(null);
    const [versions, setVersions] = useState<FileVersion[] | null>(null);
    const [diff, setDiff] = useState<DiffResult | null>(null);
    const [diffFrom, setDiffFrom] = useState<number | null>(null);

    const dirty = text !== saved;

    // Load the file as it stands, and the revision to write against.
    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        setStale(null);
        try {
            const [bytes, list] = await Promise.all([
                downloadFile(session, tenantID, node.id),
                listVersions(session, tenantID, node.id)
            ]);
            const body = new TextDecoder().decode(bytes);
            setText(body);
            setSaved(body);
            setRev(list.rev);
            setVersions(list.versions);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not open this file.');
        } finally {
            setLoading(false);
        }
    }, [session, tenantID, node.id]);

    useEffect(() => {
        void load();
    }, [load]);

    const save = useCallback(async () => {
        if (!dirty || busy) return;
        setBusy(true);
        setError(null);
        setStale(null);
        try {
            const newRev = await writeTextContent(session, tenantID, node.id, text, rev);
            setRev(newRev);
            setSaved(text);
            setVersions((await listVersions(session, tenantID, node.id)).versions);
            onSaved();
        } catch (e) {
            if (e instanceof StaleWriteError) {
                // Someone else wrote first. Keep what is typed here and let
                // the writer decide, rather than discarding either side.
                setStale(e.rev);
            } else {
                setError(e instanceof Error ? e.message : 'Could not save.');
            }
        } finally {
            setBusy(false);
        }
    }, [dirty, busy, session, tenantID, node.id, text, rev, onSaved]);

    // Ctrl/Cmd+S saves; Escape closes unless there is unsaved work.
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
                e.preventDefault();
                void save();
                return;
            }
            if (e.key === 'Escape' && !dirty) onClose();
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [save, dirty, onClose]);

    const openHistory = useCallback(async () => {
        setTab('history');
        if (versions) return;
        try {
            setVersions((await listVersions(session, tenantID, node.id)).versions);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not load the history.');
        }
    }, [session, tenantID, node.id, versions]);

    const showChanges = useCallback(
        async (bounds: { from?: number; to?: number } = {}) => {
            setTab('changes');
            setBusy(true);
            setError(null);
            try {
                const res = await diffVersions(session, tenantID, node.id, bounds);
                setDiff(res);
                setDiffFrom(res.from_rev);
            } catch (e) {
                setDiff(null);
                setError(e instanceof Error ? e.message : 'Could not compare these revisions.');
            } finally {
                setBusy(false);
            }
        },
        [session, tenantID, node.id]
    );

    const viewRevision = useCallback(
        async (v: FileVersion) => {
            setBusy(true);
            setError(null);
            try {
                const bytes = await readVersion(session, tenantID, node.id, v.rev);
                setText(new TextDecoder().decode(bytes));
                setTab('edit');
                // Loaded text is older than the file: saving it would be a
                // restore, so make that explicit rather than implicit.
                setStale(null);
            } catch (e) {
                setError(e instanceof Error ? e.message : 'Could not open that revision.');
            } finally {
                setBusy(false);
            }
        },
        [session, tenantID, node.id]
    );

    const restore = useCallback(
        async (v: FileVersion) => {
            setBusy(true);
            setError(null);
            try {
                await restoreVersion(session, tenantID, node.id, v.rev);
                await load();
                onSaved();
                setTab('edit');
            } catch (e) {
                setError(e instanceof Error ? e.message : 'Could not restore that revision.');
            } finally {
                setBusy(false);
            }
        },
        [session, tenantID, node.id, load, onSaved]
    );

    const view = useMemo(() => (diff ? toDiffRows(diff.hunks) : null), [diff]);

    return (
        <div className="fixed inset-0 z-50 flex flex-col" style={{ background: 'var(--drv-surface)' }}>
            <div className="flex items-center gap-3 border-b px-5 py-3" style={{ borderColor: 'var(--drv-border)' }}>
                <FileIcon width={20} height={20} style={{ color: 'var(--drv-text-muted)' }} />
                <div className="min-w-0 flex-1">
                    <div className="truncate text-[15px] font-semibold">{node.name}</div>
                    <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                        {formatBytes(node.size_bytes)} · revision {rev}
                        {dirty ? ' · unsaved changes' : ''}
                    </div>
                </div>

                <div className="flex items-center gap-1 rounded-full p-0.5" style={{ background: 'var(--drv-surface-2)' }}>
                    {(
                        [
                            ['edit', 'Edit'],
                            ['history', 'History'],
                            ['changes', 'Changes']
                        ] as [Tab, string][]
                    ).map(([id, label]) => (
                        <button
                            key={id}
                            onClick={() => {
                                if (id === 'history') void openHistory();
                                else if (id === 'changes') void showChanges();
                                else setTab('edit');
                            }}
                            className="rounded-full px-3 py-1 text-sm"
                            style={
                                tab === id
                                    ? { background: 'var(--drv-surface)', fontWeight: 600 }
                                    : { color: 'var(--drv-text-muted)' }
                            }
                        >
                            {label}
                        </button>
                    ))}
                </div>

                <button
                    onClick={() => void save()}
                    disabled={!dirty || busy}
                    className="drv-btn-primary rounded-full px-4 py-1.5 text-sm disabled:opacity-40"
                >
                    {busy ? 'Saving…' : 'Save'}
                </button>
                <button
                    onClick={() => {
                        if (!dirty || confirm('Close without saving your changes?')) onClose();
                    }}
                    className="rounded-lg p-1 hover:bg-[var(--drv-hover)]"
                    title="Close"
                >
                    <CloseIcon />
                </button>
            </div>

            {stale !== null && (
                <div className="mx-5 mt-3 rounded-lg border px-3 py-2 text-sm" style={{ borderColor: 'var(--drv-accent)', background: 'var(--drv-accent-weak)' }}>
                    This file changed elsewhere while you were editing (it is now at revision {stale}).
                    Your text is still here.{' '}
                    <button className="underline" onClick={() => void showChanges({ from: rev })}>
                        See what changed
                    </button>
                    , or{' '}
                    <button className="underline" onClick={() => void load()}>
                        discard yours and load theirs
                    </button>
                    .
                </div>
            )}
            {error && (
                <div className="mx-5 mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    {error}
                </div>
            )}

            <div className="min-h-0 flex-1 overflow-auto" style={{ background: 'var(--drv-surface-2)' }}>
                {loading ? (
                    <div className="py-24 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Opening…
                    </div>
                ) : tab === 'edit' ? (
                    <textarea
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        spellCheck={false}
                        className="h-full w-full resize-none p-5 text-[13px] leading-relaxed outline-none"
                        style={{
                            background: 'var(--drv-surface)',
                            color: 'var(--drv-text)',
                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                            minHeight: '70vh'
                        }}
                    />
                ) : tab === 'history' ? (
                    <div className="mx-auto max-w-3xl p-5">
                        {!versions || versions.length === 0 ? (
                            <p className="py-16 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                This file has no earlier revisions yet. Saving a change keeps the previous one here.
                            </p>
                        ) : (
                            <div className="overflow-hidden rounded-xl border" style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}>
                                {versions.map((v, vi) => (
                                    <div
                                        key={v.rev}
                                        className="flex items-center gap-3 border-b px-4 py-3 last:border-b-0"
                                        style={{ borderColor: 'var(--drv-border)' }}
                                    >
                                        <div className="min-w-0 flex-1">
                                            <div className="text-sm font-medium">
                                                Revision {v.rev}
                                                {v.current ? ' · current' : ''}
                                            </div>
                                            <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                                {formatDate(v.created_at)} · {formatBytes(v.size_bytes)}
                                            </div>
                                        </div>
                                        {/* The oldest revision has nothing before it to compare against. */}
                                        {vi < versions.length - 1 && (
                                            <button
                                                onClick={() => void showChanges({ to: v.rev })}
                                                className="rounded-full px-3 py-1 text-sm hover:bg-[var(--drv-hover)]"
                                            >
                                                Changes
                                            </button>
                                        )}
                                        {!v.current && (
                                            <>
                                                <button
                                                    onClick={() => void viewRevision(v)}
                                                    className="rounded-full px-3 py-1 text-sm hover:bg-[var(--drv-hover)]"
                                                >
                                                    View
                                                </button>
                                                <button
                                                    onClick={() => void restore(v)}
                                                    className="rounded-full border px-3 py-1 text-sm hover:bg-[var(--drv-hover)]"
                                                    style={{ borderColor: 'var(--drv-border)' }}
                                                >
                                                    Restore
                                                </button>
                                            </>
                                        )}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                ) : (
                    <div className="mx-auto max-w-4xl p-5">
                        {!diff || !view ? (
                            <p className="py-16 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                {busy ? 'Comparing…' : 'Nothing to compare yet.'}
                            </p>
                        ) : diff.identical ? (
                            <p className="py-16 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                Revisions {diff.from_rev} and {diff.to_rev} are identical.
                            </p>
                        ) : (
                            <>
                                <div className="mb-3 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                    Revision {diffFrom} to {diff.to_rev} · {summariseDiff(view)}
                                    {diff.truncated ? ' · too different to compare line by line' : ''}
                                </div>
                                <div
                                    className="overflow-x-auto rounded-xl border text-[12.5px]"
                                    style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
                                >
                                    {view.rows.map((row, i) =>
                                        row.kind === 'gap' ? (
                                            <div
                                                key={i}
                                                className="px-3 py-1 text-center text-xs"
                                                style={{ background: 'var(--drv-surface-2)', color: 'var(--drv-text-muted)' }}
                                            >
                                                ⋯
                                            </div>
                                        ) : (
                                            <div
                                                key={i}
                                                className="flex gap-3 px-3 py-0.5"
                                                style={{
                                                    background:
                                                        row.op === '+'
                                                            ? 'rgba(34,197,94,0.16)'
                                                            : row.op === '-'
                                                                ? 'rgba(239,68,68,0.14)'
                                                                : undefined,
                                                    borderLeft:
                                                        row.op === '+'
                                                            ? '3px solid rgba(34,197,94,0.85)'
                                                            : row.op === '-'
                                                                ? '3px solid rgba(239,68,68,0.8)'
                                                                : '3px solid transparent'
                                                }}
                                            >
                                                <span className="w-10 shrink-0 select-none text-right" style={{ color: 'var(--drv-text-muted)' }}>
                                                    {row.oldLine ?? ''}
                                                </span>
                                                <span className="w-10 shrink-0 select-none text-right" style={{ color: 'var(--drv-text-muted)' }}>
                                                    {row.newLine ?? ''}
                                                </span>
                                                <span
                                                    className="w-3 shrink-0 select-none font-semibold"
                                                    style={{
                                                        color:
                                                            row.op === '+'
                                                                ? 'rgb(21,128,61)'
                                                                : row.op === '-'
                                                                    ? 'rgb(185,28,28)'
                                                                    : 'var(--drv-text-muted)'
                                                    }}
                                                >
                                                    {row.op.trim()}
                                                </span>
                                                <span className="min-w-0 whitespace-pre-wrap break-words">
                                                    {row.segments
                                                        ? row.segments.map((seg, k) => (
                                                            <span
                                                                key={k}
                                                                style={
                                                                    seg.changed
                                                                        ? {
                                                                            background:
                                                                                row.op === '+'
                                                                                    ? 'rgba(34,197,94,0.42)'
                                                                                    : 'rgba(239,68,68,0.38)',
                                                                            borderRadius: '2px'
                                                                        }
                                                                        : undefined
                                                                }
                                                            >
                                                                {seg.text}
                                                            </span>
                                                        ))
                                                        : row.text || ' '}
                                                </span>
                                            </div>
                                        )
                                    )}
                                </div>
                            </>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
