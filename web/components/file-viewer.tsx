'use client';

// In-app preview for the file types that are cheap and safe to render
// client-side: images, plain text, and Markdown. Bytes are fetched over the
// sealed session (decrypted inside the enclave), turned into an object URL or
// decoded text, and rendered here. Anything we cannot preview falls back to a
// download prompt. Nothing leaves the browser.

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { downloadFile, type DriveNode } from '~/lib/drive-api';
import { formatBytes } from '~/lib/format';
import { CloseIcon, DownloadIcon, FileIcon } from './icons';

type Preview =
    | { kind: 'image'; url: string }
    | { kind: 'pdf'; url: string }
    | { kind: 'markdown'; text: string }
    | { kind: 'text'; text: string }
    | { kind: 'none' };

// Cap in-browser preview to a sane size; larger files download instead.
const MAX_PREVIEW_BYTES = 8 * 1024 * 1024;

function extOf(name: string): string {
    return name.split('.').pop()?.toLowerCase() ?? '';
}

const TEXT_EXT = new Set([
    'txt', 'log', 'csv', 'tsv', 'json', 'xml', 'yaml', 'yml', 'toml', 'ini',
    'js', 'ts', 'tsx', 'jsx', 'go', 'rs', 'py', 'sh', 'css', 'html', 'sql', 'env'
]);
const MD_EXT = new Set(['md', 'markdown', 'mdx']);
const IMG_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico']);

/** Decide how to render a node from its mime hint and extension. */
function classify(node: DriveNode): 'image' | 'pdf' | 'markdown' | 'text' | 'none' {
    const mime = node.mime_hint ?? '';
    const ext = extOf(node.name);
    if (mime.startsWith('image/') || IMG_EXT.has(ext)) return 'image';
    if (mime === 'application/pdf' || ext === 'pdf') return 'pdf';
    if (mime === 'text/markdown' || MD_EXT.has(ext)) return 'markdown';
    if (mime.startsWith('text/') || mime === 'application/json' || TEXT_EXT.has(ext)) return 'text';
    return 'none';
}

export function canPreview(node: DriveNode): boolean {
    return node.kind === 'file' && classify(node) !== 'none';
}

export function FileViewer({
    session,
    tenantID,
    node,
    onClose,
    onDownload,
    onEdit
}: {
    session: SealedSession;
    tenantID: string;
    node: DriveNode;
    onClose: () => void;
    onDownload: (n: DriveNode) => void;
    /** Offered for text files: hand this one to the editor. */
    onEdit?: (n: DriveNode) => void;
}) {
    const [preview, setPreview] = useState<Preview | null>(null);
    const [error, setError] = useState<string | null>(null);
    const kind = useMemo(() => classify(node), [node]);

    const load = useCallback(async () => {
        setError(null);
        setPreview(null);
        if (kind === 'none' || node.size_bytes > MAX_PREVIEW_BYTES) {
            setPreview({ kind: 'none' });
            return;
        }
        try {
            const bytes = await downloadFile(session, tenantID, node.id);
            if (kind === 'image') {
                const blob = new Blob([bytes as BlobPart], {
                    type: node.mime_hint || `image/${extOf(node.name)}`
                });
                setPreview({ kind: 'image', url: URL.createObjectURL(blob) });
            } else if (kind === 'pdf') {
                // The browser's built-in PDF viewer renders the blob URL in an
                // iframe; the bytes never leave the page's origin sandbox.
                const blob = new Blob([bytes as BlobPart], { type: 'application/pdf' });
                setPreview({ kind: 'pdf', url: URL.createObjectURL(blob) });
            } else {
                const text = new TextDecoder().decode(bytes);
                setPreview({ kind: kind === 'markdown' ? 'markdown' : 'text', text });
            }
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not open this file.');
            setPreview({ kind: 'none' });
        }
    }, [session, tenantID, node, kind]);

    useEffect(() => {
        void load();
    }, [load]);

    // Revoke the object URL when the preview changes or unmounts.
    useEffect(() => {
        return () => {
            if (preview?.kind === 'image' || preview?.kind === 'pdf') URL.revokeObjectURL(preview.url);
        };
    }, [preview]);

    // Close on Escape.
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [onClose]);

    return (
        <div className="fixed inset-0 z-50 flex flex-col" style={{ background: 'var(--drv-surface)' }}>
            <div className="flex min-h-0 flex-1 flex-col">
                {/* Header */}
                <div
                    className="flex items-center gap-3 border-b px-5 py-3"
                    style={{ borderColor: 'var(--drv-border)' }}
                >
                    <FileIcon width={20} height={20} style={{ color: 'var(--drv-text-muted)' }} />
                    <div className="min-w-0 flex-1">
                        <div className="truncate text-[15px] font-semibold">{node.name}</div>
                        <div className="text-xs" style={{ color: 'var(--drv-text-muted)' }}>
                            {formatBytes(node.size_bytes)}
                        </div>
                    </div>
                    {onEdit && (kind === 'markdown' || kind === 'text') && (
                        <button
                            onClick={() => onEdit(node)}
                            className="flex items-center gap-1.5 rounded-full px-3 py-1.5 text-sm font-medium hover:bg-[var(--drv-hover)]"
                            style={{ color: 'var(--drv-text)' }}
                        >
                            Edit
                        </button>
                    )}
                    <button
                        onClick={() => onDownload(node)}
                        className="flex items-center gap-1.5 rounded-full px-3 py-1.5 text-sm font-medium hover:bg-[var(--drv-hover)]"
                        style={{ color: 'var(--drv-text)' }}
                    >
                        <DownloadIcon width={16} height={16} /> Download
                    </button>
                    <button onClick={onClose} className="rounded-lg p-1 hover:bg-[var(--drv-hover)]">
                        <CloseIcon />
                    </button>
                </div>

                {/* Body */}
                <div className="min-h-[200px] flex-1 overflow-auto" style={{ background: 'var(--drv-surface-2)' }}>
                    {error && (
                        <div className="m-5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500">
                            {error}
                        </div>
                    )}
                    {!preview ? (
                        <div className="py-24 text-center text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                            Opening…
                        </div>
                    ) : preview.kind === 'image' ? (
                        <div className="flex items-center justify-center p-6">
                            <img
                                src={preview.url}
                                alt={node.name}
                                className="max-h-[82vh] max-w-full rounded-lg object-contain"
                            />
                        </div>
                    ) : preview.kind === 'pdf' ? (
                        <iframe
                            src={preview.url}
                            title={node.name}
                            className="h-full w-full"
                            style={{ border: 'none', minHeight: '100%' }}
                        />
                    ) : preview.kind === 'markdown' ? (
                        <div className="drv-markdown mx-auto max-w-3xl px-6 py-6">
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>{preview.text}</ReactMarkdown>
                        </div>
                    ) : preview.kind === 'text' ? (
                        <pre
                            className="overflow-auto p-5 text-[13px] leading-relaxed"
                            style={{ color: 'var(--drv-text)', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
                        >
                            {preview.text}
                        </pre>
                    ) : (
                        <div className="flex flex-col items-center justify-center py-20 text-center">
                            <FileIcon width={48} height={48} style={{ color: 'var(--drv-border)' }} />
                            <p className="mt-4 text-sm font-medium">No preview available</p>
                            <p className="mt-1 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                                {node.size_bytes > MAX_PREVIEW_BYTES
                                    ? 'This file is too large to preview here.'
                                    : 'This file type cannot be previewed. Download it to open it.'}
                            </p>
                            <button
                                onClick={() => onDownload(node)}
                                className="drv-btn-primary mt-5 flex items-center gap-2 rounded-full px-4 py-2 text-sm"
                            >
                                <DownloadIcon width={16} height={16} /> Download
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
