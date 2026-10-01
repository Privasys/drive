'use client';

// Asked when an upload lands on a name that already exists: replace what
// is there, keep both, or skip this file. Replacing rewrites the existing
// file in place, so its shares and links keep working and its history of
// being shared is not quietly reset by a re-upload.

import { useState } from 'react';
import type { ConflictChoice } from '~/lib/upload-conflict';
import { CloseIcon, FileIcon } from './icons';

export function ConflictDialog({
    name,
    remaining,
    onChoose,
    onCancel
}: {
    /** The name that already exists in the destination. */
    name: string;
    /** How many files of this drop are still waiting behind this one. */
    remaining: number;
    onChoose: (choice: ConflictChoice) => void;
    onCancel: () => void;
}) {
    const [applyToRest, setApplyToRest] = useState(false);
    const choose = (action: ConflictChoice['action']) => onChoose({ action, applyToRest });

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onCancel}>
            <div
                className="w-full max-w-md overflow-hidden rounded-2xl shadow-2xl"
                style={{ background: 'var(--drv-surface)' }}
                onClick={(e) => e.stopPropagation()}
            >
                <div className="flex items-center gap-3 border-b px-5 py-4" style={{ borderColor: 'var(--drv-border)' }}>
                    <div className="min-w-0 flex-1 text-[15px] font-semibold">This file already exists</div>
                    <button onClick={onCancel} className="rounded-lg p-1 hover:bg-[var(--drv-hover)]" title="Cancel">
                        <CloseIcon width={18} height={18} />
                    </button>
                </div>

                <div className="px-5 py-4">
                    <div className="flex items-center gap-3 rounded-lg border p-3" style={{ borderColor: 'var(--drv-border)' }}>
                        <FileIcon width={22} height={22} style={{ color: 'var(--drv-text-muted)' }} />
                        <span className="min-w-0 truncate text-sm font-medium">{name}</span>
                    </div>
                    <p className="mt-3 text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                        Replacing keeps the existing file&apos;s shares and links, and stores your version as its
                        new contents. Keeping both uploads yours under a numbered name.
                    </p>

                    {remaining > 0 && (
                        <label className="mt-4 flex items-center gap-2 text-sm">
                            <input
                                type="checkbox"
                                checked={applyToRest}
                                onChange={(e) => setApplyToRest(e.target.checked)}
                                className="h-4 w-4 accent-[var(--drv-accent)]"
                            />
                            Do this for the {remaining} other file{remaining === 1 ? '' : 's'} in this upload
                        </label>
                    )}
                </div>

                <div className="flex flex-wrap items-center justify-end gap-2 border-t px-5 py-4" style={{ borderColor: 'var(--drv-border)' }}>
                    <button onClick={() => choose('skip')} className="rounded-full px-3 py-1.5 text-sm hover:bg-[var(--drv-hover)]">
                        Skip
                    </button>
                    <button
                        onClick={() => choose('copy')}
                        className="rounded-full border px-3 py-1.5 text-sm hover:bg-[var(--drv-hover)]"
                        style={{ borderColor: 'var(--drv-border)' }}
                    >
                        Keep both
                    </button>
                    <button onClick={() => choose('replace')} className="drv-btn-primary rounded-full px-3 py-1.5 text-sm">
                        Replace
                    </button>
                </div>
            </div>
        </div>
    );
}
