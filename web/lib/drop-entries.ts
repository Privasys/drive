// Folder drops. A dropped directory shows up in `dataTransfer.files` as a
// zero-byte pseudo-file whose bytes cannot be read (the browser surfaces
// that as "The operation was aborted"), so a drop is read through the
// File System entries API instead: directories are walked recursively and
// every file keeps the directory path it was dropped under, so the tree can
// be recreated on the Drive. Entries must be snapshotted synchronously in
// the drop handler: the DataTransfer is invalidated once the event returns.

export type DroppedFile = { file: File; dirs: string[] };

/** Files the OS scatters into folders that nobody wants uploaded. */
const JUNK = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini']);

/** Synchronous: capture the drop's entries before the event handler returns. */
export function snapshotEntries(dt: DataTransfer): FileSystemEntry[] {
    const out: FileSystemEntry[] = [];
    const items = dt.items;
    if (!items) return out;
    for (const it of Array.from(items)) {
        if (it.kind !== 'file') continue;
        const entry = it.webkitGetAsEntry?.();
        if (entry) out.push(entry);
    }
    return out;
}

/**
 * Walk the snapshotted entries. Returns every file with its directory path
 * (relative to the drop target) and every directory seen, parents before
 * children, so empty folders are recreated too.
 */
export async function collectDroppedFiles(
    entries: FileSystemEntry[]
): Promise<{ files: DroppedFile[]; dirs: string[][] }> {
    const acc = { files: [] as DroppedFile[], dirs: [] as string[][] };
    for (const e of entries) await walk(e, [], acc);
    return acc;
}

async function walk(entry: FileSystemEntry, dirs: string[], acc: { files: DroppedFile[]; dirs: string[][] }) {
    if (entry.isFile) {
        const file = await new Promise<File>((resolve, reject) =>
            (entry as FileSystemFileEntry).file(resolve, reject)
        );
        if (!JUNK.has(file.name)) acc.files.push({ file, dirs });
        return;
    }
    if (entry.isDirectory) {
        const here = [...dirs, entry.name];
        acc.dirs.push(here);
        const reader = (entry as FileSystemDirectoryEntry).createReader();
        // readEntries returns at most a batch (100 in Chromium) per call and
        // an empty batch once the directory is exhausted.
        for (;;) {
            const batch = await new Promise<FileSystemEntry[]>((resolve, reject) =>
                reader.readEntries(resolve, reject)
            );
            if (batch.length === 0) break;
            for (const child of batch) await walk(child, here, acc);
        }
    }
}
