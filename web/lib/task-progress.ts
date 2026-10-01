// What the browser is doing right now, in the words the panel shows.
//
// Some work reports itself as it goes: an upload knows how many bytes it has
// sent. Other work is a single request the enclave answers only once it is
// finished. Deleting a folder is the second kind: one call, inside which the
// service walks the subtree and reclaims every file's sealed blobs. That is
// also the longest wait in the app, so the panel has to be able to say
// "this is running" without inventing a percentage for it.

export interface TaskProgress {
    /** What is happening: "Uploading", "Deleting". */
    verb: string;
    /** The item being worked on; empty when the verb says it all. */
    name: string;
    /** 0-100 where the work reports itself, null where it cannot. */
    pct: number | null;
    /** Position in a batch, when the user selected several items. */
    step?: { index: number; total: number };
}

/** "240 files", "1 file", "no files": how big the thing being done is. */
export function fileCount(n: number): string {
    if (n <= 0) return 'no files';
    return `${n.toLocaleString()} file${n === 1 ? '' : 's'}`;
}

/**
 * "Deleting 3 of 12: notes.md", or "Uploading photo.png". The count appears
 * only for a real batch, so a single item does not read as "1 of 1".
 */
export function progressLabel(p: TaskProgress): string {
    const count = p.step && p.step.total > 1 ? ` ${p.step.index} of ${p.step.total}` : '';
    const name = p.name ? `${count ? ':' : ''} ${p.name}` : '';
    return `${p.verb}${count}${name}`.trim();
}
