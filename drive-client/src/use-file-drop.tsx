'use client';

// Shared drag-and-drop file affordance for the Privasys fronts.
//
// External files dragged onto the zone are handed to `onFiles`. Both
// drive.privasys.org (upload into the current folder) and chat.privasys.org
// (attach into the conversation) use this so the drop behaviour — the
// dragenter/dragleave depth counter, the "only react to real files" guard,
// the overlay — is written once, not copied.

import { useCallback, useMemo, useRef, useState, type DragEvent, type ReactNode } from 'react';

export interface FileDropHandlers {
    onDragEnter: (_e: DragEvent) => void;
    onDragOver: (_e: DragEvent) => void;
    onDragLeave: (_e: DragEvent) => void;
    onDrop: (_e: DragEvent) => void;
}

/** True when a drag carries external files (not an in-app node move). */
function carriesFiles(e: DragEvent): boolean {
    const t = e.dataTransfer?.types;
    return !!t && Array.prototype.includes.call(t, 'Files');
}

/**
 * Wire external-file drag-and-drop onto any element. Returns the current
 * drag state (for an overlay) and the handlers to spread. dragenter and
 * dragleave fire once per child element, so we track a depth counter and
 * only clear the active flag when it returns to zero.
 */
export function useFileDrop({
    onFiles,
    disabled
}: {
    onFiles: (_files: File[]) => void;
    disabled?: boolean;
}): { dragActive: boolean; dropHandlers: FileDropHandlers } {
    const [dragActive, setDragActive] = useState(false);
    const depth = useRef(0);

    const onDragEnter = useCallback(
        (e: DragEvent) => {
            if (disabled || !carriesFiles(e)) return;
            e.preventDefault();
            depth.current += 1;
            setDragActive(true);
        },
        [disabled]
    );
    const onDragOver = useCallback(
        (e: DragEvent) => {
            if (disabled || !carriesFiles(e)) return;
            // Allowing the drop requires cancelling dragover.
            e.preventDefault();
        },
        [disabled]
    );
    const onDragLeave = useCallback(
        (e: DragEvent) => {
            if (disabled || !carriesFiles(e)) return;
            e.preventDefault();
            depth.current = Math.max(0, depth.current - 1);
            if (depth.current === 0) setDragActive(false);
        },
        [disabled]
    );
    const onDrop = useCallback(
        (e: DragEvent) => {
            if (disabled || !carriesFiles(e)) return;
            e.preventDefault();
            depth.current = 0;
            setDragActive(false);
            const files = e.dataTransfer?.files;
            if (files && files.length) onFiles(Array.from(files));
        },
        [disabled, onFiles]
    );

    const dropHandlers = useMemo(
        () => ({ onDragEnter, onDragOver, onDragLeave, onDrop }),
        [onDragEnter, onDragOver, onDragLeave, onDrop]
    );
    return { dragActive, dropHandlers };
}

/**
 * A ready-made drop zone: wraps its children, wires {@link useFileDrop}, and
 * shows an overlay while a file is being dragged over. Apps that need full
 * control over the overlay can use the hook directly and pass `renderOverlay`.
 */
export function FileDropZone({
    onFiles,
    disabled,
    className,
    overlayLabel = 'Drop to upload',
    renderOverlay,
    children
}: {
    onFiles: (_files: File[]) => void;
    disabled?: boolean;
    className?: string;
    /** Label shown in the default overlay pill. */
    overlayLabel?: string;
    /** Custom overlay; receives the current drag state. Overrides the default. */
    renderOverlay?: (_active: boolean) => ReactNode;
    children: ReactNode;
}) {
    const { dragActive, dropHandlers } = useFileDrop({ onFiles, disabled });
    return (
        <div className={className} style={{ position: 'relative' }} {...dropHandlers}>
            {children}
            {renderOverlay
                ? renderOverlay(dragActive)
                : dragActive && <DefaultDropOverlay label={overlayLabel} />}
        </div>
    );
}

/** Neutral translucent overlay with a centered pill. Themed via CSS vars
 *  when present, with sensible fallbacks so it reads on either front. */
function DefaultDropOverlay({ label }: { label: string }) {
    return (
        <div
            aria-hidden="true"
            style={{
                position: 'absolute',
                inset: 0,
                zIndex: 40,
                pointerEvents: 'none',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: 'inherit',
                background: 'rgba(37, 99, 235, 0.08)',
                outline: '2px dashed rgba(37, 99, 235, 0.5)',
                outlineOffset: '-8px'
            }}
        >
            <span
                style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    borderRadius: '9999px',
                    background: 'rgba(37, 99, 235, 0.95)',
                    color: '#fff',
                    padding: '0.6rem 1.15rem',
                    fontSize: '0.875rem',
                    fontWeight: 600,
                    boxShadow: '0 10px 25px rgba(0,0,0,0.25)'
                }}
            >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 3v12" />
                    <path d="m7 8 5-5 5 5" />
                    <path d="M5 21h14" />
                </svg>
                {label}
            </span>
        </div>
    );
}
