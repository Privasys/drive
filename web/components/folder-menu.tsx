'use client';

// The actions of the folder you are standing IN, hung off its name in the
// trail.
//
// Every action a folder has lived on the selection toolbar, which only
// exists once a folder is ticked in a listing. So sharing the folder on
// screen meant leaving it, finding it again in its parent and selecting it
// there: a walk out and back to act on the thing already in front of you.
//
// Only the actions that leave the folder standing are here. Moving or
// deleting it from the inside would pull the ground out from under the
// browser, which would then be listing something that no longer exists;
// those stay on the selection toolbar, where the folder is a row rather
// than the floor.

import { useEffect, useRef, useState } from 'react';

import { ChevronDown, DownloadIcon, ShareIcon } from './icons';

export function FolderMenu({
    name,
    onShare,
    onDownload
}: {
    name: string;
    onShare: () => void;
    onDownload: () => void;
}) {
    const [open, setOpen] = useState(false);
    const box = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!open) return;
        const away = (e: MouseEvent) => {
            if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
        };
        const key = (e: KeyboardEvent) => {
            if (e.key === 'Escape') setOpen(false);
        };
        document.addEventListener('mousedown', away);
        document.addEventListener('keydown', key);
        return () => {
            document.removeEventListener('mousedown', away);
            document.removeEventListener('keydown', key);
        };
    }, [open]);

    const choose = (run: () => void) => {
        setOpen(false);
        run();
    };

    return (
        <div ref={box} className="relative shrink-0">
            <button
                type="button"
                aria-label={`Actions for ${name}`}
                aria-haspopup="menu"
                aria-expanded={open}
                onClick={() => setOpen((o) => !o)}
                className="flex h-7 w-7 items-center justify-center rounded-full hover:bg-[var(--drv-hover)]"
                style={{ color: 'var(--drv-text-muted)' }}
            >
                <ChevronDown width={16} height={16} />
            </button>
            {open && (
                <div
                    role="menu"
                    className="absolute left-0 z-20 mt-1 min-w-48 overflow-hidden rounded-lg border py-1 shadow-lg"
                    style={{ borderColor: 'var(--drv-border)', background: 'var(--drv-surface)' }}
                >
                    <MenuItem
                        icon={<ShareIcon width={16} height={16} />}
                        label="Share"
                        onClick={() => choose(onShare)}
                    />
                    <MenuItem
                        icon={<DownloadIcon width={16} height={16} />}
                        label="Download"
                        onClick={() => choose(onDownload)}
                    />
                </div>
            )}
        </div>
    );
}

function MenuItem({
    icon,
    label,
    onClick
}: {
    icon: React.ReactNode;
    label: string;
    onClick: () => void;
}) {
    return (
        <button
            type="button"
            role="menuitem"
            onClick={onClick}
            className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm hover:bg-[var(--drv-hover)]"
            style={{ color: 'var(--drv-text)' }}
        >
            <span className="shrink-0" style={{ color: 'var(--drv-text-muted)' }}>
                {icon}
            </span>
            {label}
        </button>
    );
}
