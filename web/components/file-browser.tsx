'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    createFolder,
    deleteNode,
    downloadFile,
    downloadZip,
    DriveError,
    listChildren,
    moveNode,
    searchTenant,
    setNodeIndexing,
    subtreeStats,
    uploadFileStreaming,
    type DriveNode,
    type Me,
    type SearchHit,
    type Tenant
} from '~/lib/drive-api';
import { formatBytes, formatDate, ownerLabel } from '~/lib/format';
import { clickSelection } from '~/lib/selection';
import { fileCount, progressLabel, type TaskProgress } from '~/lib/task-progress';
import { copyName, type ConflictChoice } from '~/lib/upload-conflict';
import { useDrive } from '~/lib/use-drive';
import { collectDroppedFiles, snapshotEntries } from '~/lib/drop-entries';
import { ShareDialog } from './share-dialog';
import { MoveDialog } from './move-dialog';
import { ConflictDialog } from './conflict-dialog';
import { FileViewer, canPreview } from './file-viewer';
import { FileEditor } from './file-editor';
import { WorkspaceView } from './workspace-view';
import { FolderMenu } from './folder-menu';
import {
    ChevronRight,
    DownloadIcon,
    FileIcon,
    FolderIcon,
    GridIcon,
    ListIcon,
    MoveIcon,
    IndexedIcon,
    ProcessingIcon,
    NewFolderIcon,
    SearchIcon,
    SearchOffIcon,
    ShareIcon,
    SharedFolderIcon,
    TrashIcon,
    UploadIcon,
    EyeIcon,
    CloseIcon,
    WorkspaceIcon
} from './icons';

interface Crumb {
    id: string | null;
    name: string;
    /**
     * The folder this crumb stands for, kept so the trail can act on the
     * folder you are inside without going back out to select it. Absent on
     * the root, which is the tenant rather than a node, and so has nothing
     * to share.
     */
    node?: DriveNode;
}

// Custom drag type carrying the ids being moved within the drive.
const DRAG_TYPE = 'application/x-drive-nodes';

export function FileBrowser({
    session,
    tenant,
    me
}: {
    session: SealedSession;
    tenant: Tenant;
    me: Me | null;
}) {
    const { reconnect } = useDrive();
    const rootName = tenant.kind === 'user' ? 'My Drive' : tenant.name;
    const [path, setPath] = useState<Crumb[]>([{ id: null, name: rootName }]);

    // Reset to the root when the active tenant (workspace) changes.
    useEffect(() => {
        setPath([{ id: null, name: rootName }]);

    }, [tenant.id]);
    const [nodes, setNodes] = useState<DriveNode[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [view, setView] = useState<'grid' | 'list'>('list');
    const [busy, setBusy] = useState(false);
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [shareNode, setShareNode] = useState<DriveNode | null>(null);
    const [viewNode, setViewNode] = useState<DriveNode | null>(null);
    // The file open in the editor, with its history and changes beside it.
    const [editNode, setEditNode] = useState<DriveNode | null>(null);
    const [wsNode, setWsNode] = useState<DriveNode | null>(null);
    const [moveOpen, setMoveOpen] = useState(false);
    // An upload onto a taken name waits here while the user decides.
    const [conflict, setConflict] = useState<{
        name: string;
        remaining: number;
        decide: (choice: ConflictChoice | null) => void;
    } | null>(null);
    const [newFolder, setNewFolder] = useState(false);
    const [pageDrag, setPageDrag] = useState(false);
    const [dropTarget, setDropTarget] = useState<string | null>(null);
    const [progress, setProgress] = useState<TaskProgress | null>(null);
    // A step that cannot report a percentage shows how long it has been
    // running instead. A number that visibly moves is what separates "still
    // working" from "stuck", which is the whole question during a long wait.
    const [elapsed, setElapsed] = useState(0);
    // Semantic search: the input value, the submitted query, its hits.
    const [searchQ, setSearchQ] = useState('');
    const [activeSearch, setActiveSearch] = useState('');
    const [hits, setHits] = useState<SearchHit[]>([]);
    const [searching, setSearching] = useState(false);
    const dragDepth = useRef(0);
    const fileInput = useRef<HTMLInputElement>(null);

    // Restart the count whenever the step changes, so each item in a batch
    // is timed on its own rather than the clock running across the lot.
    const opaqueStep = progress && progress.pct === null ? progressLabel(progress) : null;
    useEffect(() => {
        setElapsed(0);
        if (!opaqueStep) return;
        const started = Date.now();
        const id = setInterval(() => setElapsed(Math.round((Date.now() - started) / 1000)), 1000);
        return () => clearInterval(id);
    }, [opaqueStep]);

    const current = path[path.length - 1];
    const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
    const selectedNodes = useMemo(
        () => [...selected].map((id) => byId.get(id)).filter(Boolean) as DriveNode[],
        [selected, byId]
    );

    const reload = useCallback(async () => {
        setLoading(true);
        setError(null);
        setSelected(new Set());
        setAnchor(null);
        try {
            const kids = await listChildren(session, tenant.id, current.id);
            kids.sort((a, b) =>
                a.kind !== b.kind ? (a.kind === 'folder' ? -1 : 1) : a.name.localeCompare(b.name)
            );
            setNodes(kids);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not load this folder.');
        } finally {
            setLoading(false);
        }
    }, [session, tenant.id, current.id]);

    useEffect(() => {
        void reload();
    }, [reload]);

    // While anything in view is still indexing, refresh quietly so the
    // grey processing icon flips to green without user action.
    useEffect(() => {
        if (!nodes.some((n) => n.index_status === 'pending' || n.index_status === 'processing'))
            return;
        const t = setInterval(async () => {
            try {
                const kids = await listChildren(session, tenant.id, current.id);
                kids.sort((a, b) =>
                    a.kind !== b.kind ? (a.kind === 'folder' ? -1 : 1) : a.name.localeCompare(b.name)
                );
                setNodes(kids);
            } catch {
                /* transient; the next tick retries */
            }
        }, 5000);
        return () => clearInterval(t);
    }, [nodes, session, tenant.id, current.id]);

    // ---- semantic search ----
    const runSearch = async () => {
        const q = searchQ.trim();
        if (!q) return;
        setActiveSearch(q);
        setSearching(true);
        setError(null);
        try {
            setHits(await searchTenant(session, tenant.id, q, 20));
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Search failed.');
            setActiveSearch('');
        } finally {
            setSearching(false);
        }
    };
    const clearSearch = () => {
        setSearchQ('');
        setActiveSearch('');
        setHits([]);
    };
    const openHit = (h: SearchHit) => {
        const n: DriveNode = {
            id: h.node_id,
            tenant_id: tenant.id,
            kind: 'file',
            name: h.name,
            mime_hint: h.mime_hint,
            size_bytes: 0
        };
        if (canPreview(n)) setViewNode(n);
        else void download(n);
    };

    // ---- selection ----
    // The anchor a shift-click extends from: the row the last plain or
    // ctrl/cmd click landed on. `lib/selection` owns the rules.
    const [anchor, setAnchor] = useState<string | null>(null);
    const clearSelection = () => {
        setSelected(new Set());
        setAnchor(null);
    };
    /** Resolve a click on a row against the rows in display order. */
    const applyClick = (id: string, mods: { shift: boolean; toggle: boolean }) => {
        const next = clickSelection(
            nodes.map((n) => n.id),
            { selected, anchor },
            id,
            mods
        );
        setSelected(next.selected);
        setAnchor(next.anchor);
    };
    const toggle = (id: string) => applyClick(id, { shift: false, toggle: true });
    const onRowClick = (e: React.MouseEvent, id: string) =>
        applyClick(id, { shift: e.shiftKey, toggle: e.metaKey || e.ctrlKey });

    const openNode = (n: DriveNode) => {
        if (n.kind === 'folder' && n.workspace_manifest_id) {
            // A workspace snapshot is one item: browsed read-only, never as a tree of nodes.
            setWsNode(n);
        } else if (n.kind === 'folder') {
            setPath((p) => [...p, { id: n.id, name: n.name, node: n }]);
        } else if (canPreview(n)) {
            setViewNode(n);
        } else {
            void download(n);
        }
    };

    const navigateTo = (i: number) => setPath((p) => p.slice(0, i + 1));

    const saveBytes = (bytes: Uint8Array, filename: string, mime: string) => {
        const blob = new Blob([bytes as BlobPart], { type: mime });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    };

    const download = async (n: DriveNode) => {
        try {
            const bytes = await downloadFile(session, tenant.id, n.id);
            saveBytes(bytes, n.name, n.mime_hint || 'application/octet-stream');
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Download failed.');
        }
    };

    // One file downloads as itself; a folder, or several items, come back
    // as a ZIP the enclave assembles (the browser cannot write a tree).
    const downloadNodes = async (items: DriveNode[]) => {
        if (items.length === 0) return;
        if (items.length === 1 && items[0].kind === 'file') {
            await download(items[0]);
            return;
        }
        const name = items.length === 1 ? items[0].name : 'drive-download';
        setBusy(true);
        setError(null);
        try {
            const bytes = await downloadZip(
                session,
                tenant.id,
                items.map((n) => n.id),
                name
            );
            saveBytes(bytes, `${name}.zip`, 'application/zip');
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Download failed.');
        } finally {
            setBusy(false);
        }
    };

    const downloadSelected = () => downloadNodes(selectedNodes);

    /** Put the question to the user and wait for the answer. */
    const askConflict = (name: string, remaining: number) =>
        new Promise<ConflictChoice | null>((decide) => setConflict({ name, remaining, decide }));

    /**
     * Upload a queue, asking what to do whenever the Drive refuses a name
     * that is taken (409). "Do this for the rest" is remembered for the
     * remainder of this queue only. Returns false when the user cancelled.
     */
    const uploadQueue = async (items: { file: File; dest: string | null; label: string }[]) => {
        let sticky: ConflictChoice['action'] | null = null;
        for (let i = 0; i < items.length; i++) {
            const { file, dest, label } = items[i];
            const step = { index: i + 1, total: items.length };
            const onProgress = (sent: number, total: number) =>
                setProgress({
                    verb: 'Uploading',
                    name: label,
                    pct: total ? Math.round((sent / total) * 100) : 100,
                    step
                });
            setProgress({ verb: 'Uploading', name: label, pct: 0, step });
            try {
                await uploadFileStreaming(session, tenant.id, dest, file, onProgress);
                continue;
            } catch (e) {
                if (!(e instanceof DriveError) || e.status !== 409) throw e;
            }
            let action = sticky;
            if (!action) {
                const choice = await askConflict(file.name, items.length - i - 1);
                if (!choice) return false;
                action = choice.action;
                if (choice.applyToRest) sticky = choice.action;
            }
            if (action === 'skip') continue;
            if (action === 'replace') {
                await uploadFileStreaming(session, tenant.id, dest, file, onProgress, { overwrite: true });
                continue;
            }
            const siblings = await listChildren(session, tenant.id, dest);
            await uploadFileStreaming(session, tenant.id, dest, file, onProgress, {
                name: copyName(file.name, siblings.map((n) => n.name))
            });
        }
        return true;
    };

    const onUpload = async (files: FileList | File[] | null, parentID?: string | null) => {
        if (!files || !('length' in files) || files.length === 0) return;
        const dest = parentID === undefined ? current.id : parentID;
        setBusy(true);
        setError(null);
        try {
            await uploadQueue(Array.from(files).map((file) => ({ file, dest, label: file.name })));
            await reload();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Upload failed.');
        } finally {
            setBusy(false);
            setProgress(null);
            if (fileInput.current) fileInput.current.value = '';
        }
    };

    // A dropped folder: recreate its tree under the destination, then upload
    // every file into the folder it came from. A folder that already exists
    // (a re-drop of the same tree) is reused rather than failing the drop.
    const onUploadEntries = async (entries: FileSystemEntry[], parentID?: string | null) => {
        const dest = parentID === undefined ? current.id : parentID;
        setBusy(true);
        setError(null);
        try {
            setProgress({ verb: 'Reading the folder…', name: '', pct: null });
            const { files, dirs } = await collectDroppedFiles(entries);
            const folderIDs = new Map<string, string | null>([['', dest]]);
            const ensureDir = async (segs: string[]): Promise<string | null> => {
                const key = segs.join('/');
                const known = folderIDs.get(key);
                if (known !== undefined) return known;
                const parent = await ensureDir(segs.slice(0, -1));
                const name = segs[segs.length - 1];
                let id: string;
                try {
                    id = (await createFolder(session, tenant.id, parent, name)).id;
                } catch (e) {
                    const existing = (await listChildren(session, tenant.id, parent)).find(
                        (n) => n.kind === 'folder' && n.name === name
                    );
                    if (!existing) throw e;
                    id = existing.id;
                }
                folderIDs.set(key, id);
                return id;
            };
            for (const d of dirs) await ensureDir(d);
            const queued: { file: File; dest: string | null; label: string }[] = [];
            for (const { file, dirs: fileDirs } of files) {
                queued.push({
                    file,
                    dest: await ensureDir(fileDirs),
                    label: [...fileDirs, file.name].join('/')
                });
            }
            await uploadQueue(queued);
            await reload();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Upload failed.');
        } finally {
            setBusy(false);
            setProgress(null);
        }
    };

    const onCreateFolder = async (name: string) => {
        setNewFolder(false);
        const trimmed = name.trim();
        if (!trimmed) return;
        setBusy(true);
        try {
            await createFolder(session, tenant.id, current.id, trimmed);
            await reload();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not create the folder.');
        } finally {
            setBusy(false);
        }
    };

    const onDeleteSelected = async () => {
        const items = selectedNodes;
        if (items.length === 0) return;
        const label =
            items.length === 1
                ? `"${items[0].name}"${items[0].kind === 'folder' ? ' and everything in it' : ''}`
                : `${items.length} items`;
        if (!confirm(`Delete ${label}?`)) return;
        setBusy(true);
        setError(null);
        try {
            // Deleting a folder is one call the service answers once it has
            // reclaimed every file beneath it, so there is no percentage to
            // report inside it. Naming what is going and counting position
            // through the selection is what the user can actually use.
            for (let i = 0; i < items.length; i++) {
                const n = items[i];
                const step = { index: i + 1, total: items.length };
                let label = n.name;
                if (n.kind === 'folder') {
                    // Ask what the folder holds, so the wait has a size
                    // attached to it rather than just a name.
                    label = `${n.name} and everything in it`;
                    setProgress({ verb: 'Deleting', name: label, pct: null, step });
                    try {
                        const stats = await subtreeStats(session, tenant.id, n.id);
                        label = `${n.name}, ${fileCount(stats.files)}`;
                    } catch {
                        // A count is a courtesy; never fail a delete for it.
                    }
                }
                setProgress({ verb: 'Deleting', name: label, pct: null, step });
                await deleteNode(session, tenant.id, n.id);
            }
            await reload();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Delete failed.');
        } finally {
            setBusy(false);
            setProgress(null);
        }
    };

    // Toggle a node's searchability: excluding a folder covers its
    // subtree for future uploads.
    const toggleIndexing = async (n: DriveNode) => {
        setBusy(true);
        setError(null);
        try {
            await setNodeIndexing(session, tenant.id, n.id, n.index_status === 'excluded');
            await reload();
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not update search settings.');
        } finally {
            setBusy(false);
        }
    };

    const moveInto = useCallback(
        async (ids: string[], destParentID: string | null) => {
            setBusy(true);
            setError(null);
            try {
                for (const id of ids) await moveNode(session, tenant.id, id, destParentID);
                await reload();
            } catch (e) {
                setError(e instanceof Error ? e.message : 'Move failed.');
            } finally {
                setBusy(false);
            }
        },
        [session, tenant.id, reload]
    );

    // ---- drag and drop ----
    // Page-level: external files dropped anywhere upload into the current folder.
    const onPageDragEnter = (e: React.DragEvent) => {
        if (!e.dataTransfer.types.includes('Files')) return;
        e.preventDefault();
        dragDepth.current += 1;
        setPageDrag(true);
    };
    const onPageDragOver = (e: React.DragEvent) => {
        if (e.dataTransfer.types.includes('Files')) e.preventDefault();
    };
    const onPageDragLeave = (e: React.DragEvent) => {
        e.preventDefault();
        dragDepth.current = Math.max(0, dragDepth.current - 1);
        if (dragDepth.current === 0) setPageDrag(false);
    };
    const onPageDrop = (e: React.DragEvent) => {
        e.preventDefault();
        dragDepth.current = 0;
        setPageDrag(false);
        // Entries must be captured before this handler returns.
        const entries = snapshotEntries(e.dataTransfer);
        if (entries.length) {
            void onUploadEntries(entries);
            return;
        }
        if (e.dataTransfer.files?.length) void onUpload(e.dataTransfer.files);
    };

    // A node row starts an internal move drag.
    const onNodeDragStart = (e: React.DragEvent, id: string) => {
        // Drag the whole selection if the grabbed row is part of it.
        const ids = selected.has(id) ? [...selected] : [id];
        e.dataTransfer.setData(DRAG_TYPE, JSON.stringify(ids));
        e.dataTransfer.effectAllowed = 'move';
    };

    // A folder row is a drop target for both external files (upload into it)
    // and internal nodes (move into it).
    const folderDragOver = (e: React.DragEvent, folderID: string) => {
        const t = e.dataTransfer.types;
        if (!t.includes('Files') && !t.includes(DRAG_TYPE)) return;
        e.preventDefault();
        e.stopPropagation();
        setDropTarget(folderID);
    };
    const folderDrop = (e: React.DragEvent, folder: DriveNode) => {
        e.preventDefault();
        e.stopPropagation();
        setDropTarget(null);
        setPageDrag(false);
        dragDepth.current = 0;
        const entries = snapshotEntries(e.dataTransfer);
        if (entries.length) {
            void onUploadEntries(entries, folder.id);
            return;
        }
        if (e.dataTransfer.files?.length) {
            void onUpload(e.dataTransfer.files, folder.id);
            return;
        }
        const raw = e.dataTransfer.getData(DRAG_TYPE);
        if (raw) {
            const ids = (JSON.parse(raw) as string[]).filter((id) => id !== folder.id);
            if (ids.length) void moveInto(ids, folder.id);
        }
    };

    const rowProps = (n: DriveNode) => ({
        draggable: true,
        onDragStart: (e: React.DragEvent) => onNodeDragStart(e, n.id),
        onDragOver: n.kind === 'folder' ? (e: React.DragEvent) => folderDragOver(e, n.id) : undefined,
        onDragLeave: n.kind === 'folder' ? () => setDropTarget(null) : undefined,
        onDrop: n.kind === 'folder' ? (e: React.DragEvent) => folderDrop(e, n) : undefined,
        isDropTarget: n.kind === 'folder' && dropTarget === n.id
    });

    const soleFile = selectedNodes.length === 1 && selectedNodes[0].kind === 'file' ? selectedNodes[0] : null;
    const soleNode = selectedNodes.length === 1 ? selectedNodes[0] : null;

    if (wsNode) {
        return (
            <WorkspaceView
                session={session}
                tenant={tenant}
                node={wsNode}
                onBack={() => setWsNode(null)}
                onDeleted={() => {
                    setWsNode(null);
                    void reload();
                }}
            />
        );
    }
    return (
        <div
            className="relative flex flex-1 flex-col"
            onDragEnter={onPageDragEnter}
            onDragOver={onPageDragOver}
            onDragLeave={onPageDragLeave}
            onDrop={onPageDrop}
        >
            {/* Google-Drive-style drop affordance: the files area gets a
                translucent tint (rows stay visible so a folder can be
                targeted), and a floating pill names the destination. */}
            {pageDrag && (
                <div
                    className="drv-btn-primary pointer-events-none fixed bottom-8 left-1/2 z-40 flex -translate-x-1/2 items-center gap-2 rounded-full px-5 py-2.5 text-sm shadow-lg"
                >
                    <UploadIcon width={18} height={18} />
                    Drop files to upload to{' '}
                    {dropTarget ? (byId.get(dropTarget)?.name ?? current.name) : current.name}
                </div>
            )}

            {/* Toolbar: one fixed-height row whose content swaps between
                browsing controls and the selection actions, so selecting a
                row never shifts the file list (double-click stays where it
                was clicked). */}
            <div
                className="sticky top-14 z-10 flex h-14 items-center gap-2 border-b px-4"
                style={{
                    borderColor: 'var(--drv-border)',
                    background: selected.size > 0 ? 'var(--drv-accent-weak)' : 'var(--drv-surface-2)'
                }}
            >
                {selected.size > 0 ? (
                    <>
                        <IconButton title="Clear selection" onClick={clearSelection} icon={<CloseIcon width={18} height={18} />} />
                        <span className="mr-1 text-sm font-medium" style={{ color: 'var(--drv-accent)' }}>
                            {selected.size} selected
                        </span>
                        {soleFile && canPreview(soleFile) && (
                            <IconButton title="Preview" onClick={() => setViewNode(soleFile)} icon={<EyeIcon width={18} height={18} />} />
                        )}
                        {soleNode && (
                            <IconButton title="Share" onClick={() => setShareNode(soleNode)} icon={<ShareIcon width={18} height={18} />} />
                        )}
                        <IconButton
                            title={
                                selectedNodes.length === 1 && selectedNodes[0].kind === 'file'
                                    ? 'Download'
                                    : 'Download as ZIP'
                            }
                            onClick={() => void downloadSelected()}
                            icon={<DownloadIcon width={18} height={18} />}
                        />
                        <IconButton title="Move" onClick={() => setMoveOpen(true)} icon={<MoveIcon width={18} height={18} />} />
                        {soleNode && soleNode.kind === 'folder' && (
                            <IconButton
                                title={soleNode.index_status === 'excluded' ? 'Enable search in this folder' : 'Exclude this folder from search'}
                                onClick={() => void toggleIndexing(soleNode)}
                                icon={
                                    soleNode.index_status === 'excluded' ? (
                                        <SearchIcon width={18} height={18} />
                                    ) : (
                                        <SearchOffIcon width={18} height={18} />
                                    )
                                }
                            />
                        )}
                        <IconButton title="Delete" onClick={() => void onDeleteSelected()} icon={<TrashIcon width={18} height={18} />} />
                    </>
                ) : (
                    <>
                        <nav className="flex min-w-0 shrink items-center gap-1 text-[15px]">
                            {path.map((c, i) => (
                                <span key={`${c.id ?? 'root'}-${i}`} className="flex min-w-0 items-center gap-1">
                                    {i > 0 && <ChevronRight className="shrink-0" style={{ color: 'var(--drv-text-muted)' }} />}
                                    <button
                                        onClick={() => navigateTo(i)}
                                        onDragOver={(e) =>
                                            c.id === null
                                                ? undefined
                                                : folderDragOver(e, c.id)
                                        }
                                        onDrop={(e) => {
                                            if (c.id === null) {
                                                // allow dropping onto the root crumb
                                                e.preventDefault();
                                                e.stopPropagation();
                                                const raw = e.dataTransfer.getData(DRAG_TYPE);
                                                if (raw) void moveInto(JSON.parse(raw) as string[], null);
                                            }
                                        }}
                                        className="truncate rounded px-1.5 py-0.5 font-medium hover:bg-[var(--drv-hover)]"
                                        style={{ color: i === path.length - 1 ? 'var(--drv-text)' : 'var(--drv-text-muted)' }}
                                    >
                                        {c.name}
                                    </button>
                                    {/* The folder you are in can be acted on where
                                        you are, rather than back out in its parent. */}
                                    {i === path.length - 1 && c.node && (
                                        <FolderMenu
                                            name={c.name}
                                            onShare={() => setShareNode(c.node!)}
                                            onDownload={() => void downloadNodes([c.node!])}
                                        />
                                    )}
                                </span>
                            ))}
                        </nav>

                        {/* Semantic search over the drive's sealed index. */}
                        <div
                            className="mx-2 flex min-w-0 max-w-md flex-1 items-center gap-2 rounded-full border px-3 py-1.5"
                            style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                        >
                            <SearchIcon width={16} height={16} style={{ color: 'var(--drv-text-muted)' }} />
                            <input
                                value={searchQ}
                                onChange={(e) => setSearchQ(e.target.value)}
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') void runSearch();
                                    if (e.key === 'Escape') clearSearch();
                                }}
                                placeholder="Search in Drive"
                                className="min-w-0 flex-1 bg-transparent text-sm outline-none"
                            />
                            {(searchQ || activeSearch) && (
                                <button title="Clear search" onClick={clearSearch} className="rounded p-0.5 hover:bg-[var(--drv-hover)]">
                                    <CloseIcon width={14} height={14} style={{ color: 'var(--drv-text-muted)' }} />
                                </button>
                            )}
                        </div>

                        <div className="ml-auto flex items-center gap-1">
                            <IconButton title="New folder" onClick={() => setNewFolder(true)} disabled={busy} icon={<NewFolderIcon />} />
                            <button
                                onClick={() => fileInput.current?.click()}
                                disabled={busy}
                                title="Upload files"
                                className="drv-btn-primary flex h-9 w-9 items-center justify-center rounded-full disabled:opacity-50"
                            >
                                <UploadIcon width={18} height={18} />
                            </button>
                            <div className="mx-1 h-6 w-px" style={{ background: 'var(--drv-border)' }} />
                            <IconButton
                                title={view === 'list' ? 'Grid view' : 'List view'}
                                onClick={() => setView((v) => (v === 'list' ? 'grid' : 'list'))}
                                icon={view === 'list' ? <GridIcon /> : <ListIcon />}
                            />
                        </div>
                    </>
                )}
                <input ref={fileInput} type="file" multiple hidden onChange={(e) => void onUpload(e.target.files)} />
            </div>

            {progress && (
                <div
                    className="mx-4 mt-3 rounded-lg border px-3 py-2"
                    style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                >
                    <div className="mb-1.5 flex items-center justify-between text-xs">
                        <span className="truncate" style={{ color: 'var(--drv-text-muted)' }}>
                            {progressLabel(progress)}
                        </span>
                        {progress.pct !== null ? (
                            <span className="ml-2 shrink-0 font-medium" style={{ color: 'var(--drv-accent)' }}>
                                {progress.pct}%
                            </span>
                        ) : (
                            elapsed > 0 && (
                                <span
                                    className="ml-2 shrink-0 font-medium tabular-nums"
                                    style={{ color: 'var(--drv-text-muted)' }}
                                >
                                    {elapsed}s
                                </span>
                            )
                        )}
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full" style={{ background: 'var(--drv-surface-2)' }}>
                        {/* Work that cannot measure itself sends a sliver across
                            the track. A filled bar would read as finished. */}
                        <div
                            className={
                                progress.pct === null
                                    ? 'drv-indeterminate h-full rounded-full'
                                    : 'h-full rounded-full transition-all'
                            }
                            style={{
                                ...(progress.pct === null ? {} : { width: `${progress.pct}%` }),
                                background: 'var(--drv-accent)'
                            }}
                        />
                    </div>
                </div>
            )}

            {error && (
                <div className="mx-4 mt-3 flex flex-wrap items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                    <span className="min-w-0 flex-1">{error}</span>
                    <button
                        onClick={() => void reconnect()}
                        className="shrink-0 rounded-full border border-red-500/40 px-3 py-1 text-xs font-medium hover:bg-red-500/10"
                    >
                        Reconnect
                    </button>
                </div>
            )}
            {newFolder && <NewFolderRow onSubmit={onCreateFolder} onCancel={() => setNewFolder(false)} />}

            {/* Body */}
            <div
                className="flex-1 rounded-xl p-4"
                onClick={(e) => e.target === e.currentTarget && clearSelection()}
                style={
                    pageDrag && dropTarget === null
                        ? {
                            // Tint, do not cover: folder rows must stay
                            // visible (and targetable) during the drag.
                            outline: '2px dashed var(--drv-accent)',
                            outlineOffset: '-6px',
                            background: 'var(--drv-hover)'
                        }
                        : undefined
                }
            >
                {activeSearch ? (
                    <SearchResults
                        query={activeSearch}
                        hits={hits}
                        searching={searching}
                        onOpen={openHit}
                        onClear={clearSearch}
                    />
                ) : loading ? (
                    <div className="py-20 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Loading…
                    </div>
                ) : nodes.length === 0 ? (
                    <EmptyState onUpload={() => fileInput.current?.click()} />
                ) : view === 'list' ? (
                    <ListLayout
                        nodes={nodes}
                        selected={selected}
                        mySub={me?.sub ?? ''}
                        onRowClick={onRowClick}
                        onToggle={toggle}
                        onOpen={openNode}
                        rowProps={rowProps}
                    />
                ) : (
                    <GridLayout
                        nodes={nodes}
                        selected={selected}
                        onRowClick={onRowClick}
                        onOpen={openNode}
                        rowProps={rowProps}
                    />
                )}
            </div>

            {shareNode && (
                <ShareDialog
                    session={session}
                    tenantID={tenant.id}
                    tenantKind={tenant.kind}
                    node={shareNode}
                    mySub={me?.sub ?? ''}
                    onClose={() => setShareNode(null)}
                />
            )}

            {viewNode && (
                <FileViewer
                    session={session}
                    tenantID={tenant.id}
                    node={viewNode}
                    onClose={() => setViewNode(null)}
                    onDownload={(n) => void download(n)}
                    onEdit={(n) => {
                        setViewNode(null);
                        setEditNode(n);
                    }}
                />
            )}

            {editNode && (
                <FileEditor
                    session={session}
                    tenantID={tenant.id}
                    node={editNode}
                    onClose={() => setEditNode(null)}
                    onSaved={() => void reload()}
                />
            )}

            {conflict && (
                <ConflictDialog
                    name={conflict.name}
                    remaining={conflict.remaining}
                    onChoose={(choice) => {
                        const decide = conflict.decide;
                        setConflict(null);
                        decide(choice);
                    }}
                    onCancel={() => {
                        const decide = conflict.decide;
                        setConflict(null);
                        decide(null);
                    }}
                />
            )}

            {moveOpen && (
                <MoveDialog
                    session={session}
                    tenantID={tenant.id}
                    moving={selected}
                    onCancel={() => setMoveOpen(false)}
                    onMove={(dest) => {
                        setMoveOpen(false);
                        void moveInto([...selected], dest);
                    }}
                />
            )}
        </div>
    );
}

// Icon-only toolbar button; the label lives in the tooltip.
function IconButton({
    title,
    onClick,
    icon,
    disabled
}: {
    title: string;
    onClick: () => void;
    icon: React.ReactNode;
    disabled?: boolean;
}) {
    return (
        <button
            title={title}
            aria-label={title}
            onClick={onClick}
            disabled={disabled}
            className="flex h-9 w-9 items-center justify-center rounded-full hover:bg-[var(--drv-hover)] disabled:opacity-50"
            style={{ color: 'var(--drv-text)' }}
        >
            {icon}
        </button>
    );
}

// Searchability column: grey clock while indexing, green check when
// searchable, muted search-off when excluded / not indexed.
function StatusIcon({ node }: { node: DriveNode }) {
    const s = node.index_status;
    if (s === 'pending' || s === 'processing') {
        const done = node.index_chunks_done ?? 0;
        const total = node.index_chunks_total ?? 0;
        const pct = total > 0 ? Math.round((done / total) * 100) : 0;
        const label =
            s === 'pending'
                ? 'Queued for indexing'
                : total > 0
                    ? `Indexing… ${done}/${total} chunks (${pct}%)`
                    : 'Indexing for search…';
        return (
            <span
                title={label}
                aria-label={label}
                className="inline-flex items-center gap-1"
            >
                <ProcessingIcon width={16} height={16} style={{ color: 'var(--drv-text-muted)' }} />
                {s === 'processing' && total > 0 && (
                    <span style={{ fontSize: 11, color: 'var(--drv-text-muted)' }}>{pct}%</span>
                )}
            </span>
        );
    }
    if (s === 'indexed') {
        return (
            <span title="Searchable" aria-label="Searchable">
                <IndexedIcon width={16} height={16} style={{ color: '#16a34a' }} />
            </span>
        );
    }
    if (s === 'excluded') {
        return (
            <span title="Excluded from search" aria-label="Excluded from search">
                <SearchOffIcon width={16} height={16} style={{ color: 'var(--drv-text-muted)' }} />
            </span>
        );
    }
    if (s === 'skipped' || s === 'failed') {
        return (
            <span
                title={s === 'failed' ? 'Indexing failed' : 'Not indexed (type not supported yet)'}
                aria-label="Not indexed"
            >
                <SearchOffIcon width={16} height={16} style={{ color: 'var(--drv-border)' }} />
            </span>
        );
    }
    return null;
}

function NodeIcon({ node }: { node: DriveNode }) {
    if (node.kind === 'folder' && node.workspace_manifest_id) {
        return <WorkspaceIcon width={22} height={22} style={{ color: 'var(--drv-accent)' }} />;
    }
    if (node.kind === 'folder') {
        // A folder somebody else can reach says so on its own icon, so an
        // owner can see what has left the drive by looking down the list
        // rather than opening each folder's sharing panel in turn.
        const Icon = node.shared ? SharedFolderIcon : FolderIcon;
        return (
            <Icon
                width={22}
                height={22}
                style={{ color: 'var(--drv-accent)' }}
                aria-label={node.shared ? 'Shared folder' : undefined}
            />
        );
    }
    return <FileIcon width={22} height={22} style={{ color: 'var(--drv-text-muted)' }} />;
}

interface RowExtra {
    draggable: boolean;
    onDragStart: (e: React.DragEvent) => void;
    onDragOver?: (e: React.DragEvent) => void;
    onDragLeave?: () => void;
    onDrop?: (e: React.DragEvent) => void;
    isDropTarget: boolean;
}

// The Owner / Modified / Size columns are hidden below `sm`, but their grid
// tracks are still reserved by grid-template-columns — on a phone that fixed
// 90+110+90px overflows the viewport and collapses the Name column
// (minmax(0,1fr)) to ~0px, clipping the file name and icon to nothing. Match
// the tracks to the columns actually rendered at each breakpoint: name + status
// on mobile, the full set from `sm` up.
const LIST_COLS =
    'grid-cols-[28px_minmax(0,1fr)_44px] sm:grid-cols-[28px_minmax(0,1fr)_90px_110px_90px_44px]';

function ListLayout({
    nodes,
    selected,
    mySub,
    onRowClick,
    onToggle,
    onOpen,
    rowProps
}: {
    nodes: DriveNode[];
    selected: Set<string>;
    mySub: string;
    onRowClick: (e: React.MouseEvent, id: string) => void;
    onToggle: (id: string) => void;
    onOpen: (n: DriveNode) => void;
    rowProps: (n: DriveNode) => RowExtra;
}) {
    return (
        <div className="overflow-hidden rounded-xl border" style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}>
            <div
                className={`grid ${LIST_COLS} items-center px-4 py-2 text-xs font-medium`}
                style={{ color: 'var(--drv-text-muted)', borderBottom: '1px solid var(--drv-border)' }}
            >
                <span />
                <span>Name</span>
                <span className="hidden sm:block">Owner</span>
                <span className="hidden sm:block">Modified</span>
                <span className="hidden sm:block">Size</span>
                <span className="text-center" title="Searchability">
                    <SearchIcon width={14} height={14} className="inline" />
                </span>
            </div>
            {nodes.map((n) => {
                const rp = rowProps(n);
                const isSel = selected.has(n.id);
                // select-none: a shift-click over a range must not leave a blue
                // text highlight dragged across the rows it spans.
                return (
                    <div
                        key={n.id}
                        draggable={rp.draggable}
                        onDragStart={rp.onDragStart}
                        onDragOver={rp.onDragOver}
                        onDragLeave={rp.onDragLeave}
                        onDrop={rp.onDrop}
                        onClick={(e) => onRowClick(e, n.id)}
                        onDoubleClick={() => onOpen(n)}
                        className={`group grid cursor-pointer select-none ${LIST_COLS} items-center px-4 py-2.5`}
                        style={{
                            borderBottom: '1px solid var(--drv-border)',
                            background: rp.isDropTarget
                                ? 'var(--drv-selected)'
                                : isSel
                                    ? 'var(--drv-accent-weak)'
                                    : undefined,
                            outline: rp.isDropTarget ? '2px dashed var(--drv-accent)' : undefined,
                            outlineOffset: '-2px'
                        }}
                    >
                        <input
                            type="checkbox"
                            checked={isSel}
                            onClick={(e) => {
                                e.stopPropagation();
                                // Shift on the box means what it means on the row:
                                // a range from the anchor, not a toggle of this one.
                                if (e.shiftKey) {
                                    e.preventDefault();
                                    onRowClick(e, n.id);
                                }
                            }}
                            onChange={() => onToggle(n.id)}
                            className={`h-4 w-4 accent-[var(--drv-accent)] ${isSel ? '' : 'opacity-0 group-hover:opacity-100'}`}
                        />
                        <div className="flex min-w-0 items-center gap-3">
                            <NodeIcon node={n} />
                            <span className="truncate text-sm font-medium">{n.name}</span>
                        </div>
                        <span className="hidden truncate text-sm sm:block" style={{ color: 'var(--drv-text-muted)' }}>
                            {ownerLabel(n.created_by, mySub)}
                        </span>
                        <span className="hidden text-sm sm:block" style={{ color: 'var(--drv-text-muted)' }}>
                            {formatDate(n.updated_at)}
                        </span>
                        <span className="hidden text-sm sm:block" style={{ color: 'var(--drv-text-muted)' }}>
                            {n.kind === 'folder' ? (n.workspace_manifest_id ? 'snapshot' : '—') : formatBytes(n.size_bytes)}
                        </span>
                        <span className="flex justify-center">
                            <StatusIcon node={n} />
                        </span>
                    </div>
                );
            })}
        </div>
    );
}

function SearchResults({
    query,
    hits,
    searching,
    onOpen,
    onClear
}: {
    query: string;
    hits: SearchHit[];
    searching: boolean;
    onOpen: (h: SearchHit) => void;
    onClear: () => void;
}) {
    return (
        <div>
            <div className="mb-3 flex items-center gap-2 text-sm">
                <span style={{ color: 'var(--drv-text-muted)' }}>
                    {searching ? 'Searching…' : `Results for "${query}"`}
                </span>
                <button
                    onClick={onClear}
                    className="rounded-full px-2.5 py-0.5 text-xs font-medium hover:bg-[var(--drv-hover)]"
                    style={{ color: 'var(--drv-accent)' }}
                >
                    Back to files
                </button>
            </div>
            {searching ? null : hits.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 text-center">
                    <SearchIcon width={44} height={44} style={{ color: 'var(--drv-border)' }} />
                    <p className="mt-4 text-sm font-medium">No matches</p>
                    <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Only files with the green searchable mark are covered.
                    </p>
                </div>
            ) : (
                <div className="overflow-hidden rounded-xl border" style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}>
                    {hits.map((h, i) => (
                        <button
                            key={`${h.node_id}-${h.chunk_index}-${i}`}
                            onClick={() => onOpen(h)}
                            className="block w-full px-4 py-3 text-left hover:bg-[var(--drv-hover)]"
                            style={{ borderBottom: '1px solid var(--drv-border)' }}
                        >
                            <div className="flex items-center gap-2">
                                <FileIcon width={18} height={18} style={{ color: 'var(--drv-text-muted)' }} />
                                <span className="truncate text-sm font-medium">{h.name}</span>
                                {h.section_path && h.section_path.length > 1 && (
                                    <span
                                        className="truncate rounded-full px-2 py-0.5 text-xs"
                                        style={{ background: 'var(--drv-accent-weak)', color: 'var(--drv-accent)' }}
                                        title={h.section_path.join(' › ')}
                                    >
                                        {h.section_path.slice(1).join(' › ')}
                                    </span>
                                )}
                                <span className="ml-auto shrink-0 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                    {(h.score * 100).toFixed(0)}%
                                </span>
                            </div>
                            <p className="mt-1 line-clamp-2 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                                {h.snippet}
                            </p>
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
}

function GridLayout({
    nodes,
    selected,
    onRowClick,
    onOpen,
    rowProps
}: {
    nodes: DriveNode[];
    selected: Set<string>;
    onRowClick: (e: React.MouseEvent, id: string) => void;
    onOpen: (n: DriveNode) => void;
    rowProps: (n: DriveNode) => RowExtra;
}) {
    return (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(160px,1fr))] gap-3">
            {nodes.map((n) => {
                const rp = rowProps(n);
                const isSel = selected.has(n.id);
                return (
                    <div
                        key={n.id}
                        draggable={rp.draggable}
                        onDragStart={rp.onDragStart}
                        onDragOver={rp.onDragOver}
                        onDragLeave={rp.onDragLeave}
                        onDrop={rp.onDrop}
                        onClick={(e) => onRowClick(e, n.id)}
                        onDoubleClick={() => onOpen(n)}
                        className="group relative cursor-pointer select-none rounded-xl border p-3 transition-shadow hover:shadow-md"
                        style={{
                            borderColor: rp.isDropTarget || isSel ? 'var(--drv-accent)' : 'var(--drv-border)',
                            background: rp.isDropTarget || isSel ? 'var(--drv-accent-weak)' : 'var(--drv-surface)'
                        }}
                    >
                        <div className="mb-3 flex h-20 items-center justify-center rounded-lg" style={{ background: 'var(--drv-surface-2)' }}>
                            {n.kind === 'folder' ? (
                                n.shared ? (
                                    <SharedFolderIcon
                                        width={40}
                                        height={40}
                                        style={{ color: 'var(--drv-accent)' }}
                                        aria-label="Shared folder"
                                    />
                                ) : (
                                    <FolderIcon width={40} height={40} style={{ color: 'var(--drv-accent)' }} />
                                )
                            ) : (
                                <FileIcon width={36} height={36} style={{ color: 'var(--drv-text-muted)' }} />
                            )}
                        </div>
                        <div className="flex items-center gap-1.5">
                            <span className="min-w-0 truncate text-sm font-medium">{n.name}</span>
                            <span className="ml-auto shrink-0">
                                <StatusIcon node={n} />
                            </span>
                        </div>
                        <div className="mt-0.5 text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                            {n.kind === 'folder' ? 'Folder' : formatBytes(n.size_bytes)}
                        </div>
                    </div>
                );
            })}
        </div>
    );
}

function NewFolderRow({ onSubmit, onCancel }: { onSubmit: (name: string) => void; onCancel: () => void }) {
    const [name, setName] = useState('Untitled folder');
    return (
        <div className="mx-4 mt-3 flex items-center gap-2 rounded-lg border p-2" style={{ borderColor: 'var(--drv-border)' }}>
            <FolderIcon width={20} height={20} style={{ color: 'var(--drv-accent)' }} />
            <input
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => {
                    if (e.key === 'Enter') onSubmit(name);
                    if (e.key === 'Escape') onCancel();
                }}
                className="flex-1 rounded border px-2 py-1 text-sm outline-none"
                style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
            />
            <button onClick={() => onSubmit(name)} className="drv-btn-primary rounded-full px-3 py-1 text-sm">
                Create
            </button>
            <button onClick={onCancel} className="rounded-full px-3 py-1 text-sm hover:bg-[var(--drv-hover)]">
                Cancel
            </button>
        </div>
    );
}

function EmptyState({ onUpload }: { onUpload: () => void }) {
    return (
        <div className="flex flex-col items-center justify-center py-24 text-center">
            <FolderIcon width={56} height={56} style={{ color: 'var(--drv-border)' }} />
            <p className="mt-4 text-sm font-medium">This folder is empty</p>
            <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                Upload files, drag them in, or create a folder to get started.
            </p>
            <button onClick={onUpload} className="drv-btn-primary mt-5 rounded-full px-4 py-2 text-sm">
                Upload files
            </button>
        </div>
    );
}
