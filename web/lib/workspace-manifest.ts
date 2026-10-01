// Workspace snapshot manifest (`.workspace.json`), the contract Drive owns
// and the runtime writes: see the Drive service's workspace.go. The front
// only reads it, to render the snapshot as one item and to list its tree
// read-only.

export interface WorkspaceFile {
    path: string;
    size: number;
    mode?: string;
    blob: string;
}

export interface WorkspaceManifest {
    version: number;
    app?: string;
    saved_at?: string;
    files: WorkspaceFile[];
}

export interface WorkspaceSummary {
    fileCount: number;
    bytes: number;
    savedAt?: string;
    app?: string;
}

/** Parse the manifest bytes; throws on anything that is not a v1 manifest. */
export function parseWorkspaceManifest(bytes: Uint8Array): WorkspaceManifest {
    const text = new TextDecoder().decode(bytes);
    const raw = JSON.parse(text) as Partial<WorkspaceManifest>;
    if (!raw || raw.version !== 1 || !Array.isArray(raw.files)) {
        throw new Error('not a workspace manifest');
    }
    const files: WorkspaceFile[] = [];
    for (const f of raw.files) {
        if (!f || typeof f.path !== 'string' || typeof f.blob !== 'string') continue;
        const path = cleanPath(f.path);
        if (!path) continue;
        files.push({
            path,
            size: typeof f.size === 'number' && f.size >= 0 ? f.size : 0,
            mode: typeof f.mode === 'string' ? f.mode : undefined,
            blob: f.blob.toLowerCase()
        });
    }
    return { version: 1, app: raw.app, saved_at: raw.saved_at, files };
}

/** Totals for the one-line rendering ("340 MB · 1,204 files · saved 2 min ago"). */
export function summarise(m: WorkspaceManifest): WorkspaceSummary {
    let bytes = 0;
    for (const f of m.files) bytes += f.size;
    return { fileCount: m.files.length, bytes, savedAt: m.saved_at, app: m.app };
}

/** A tree of directories for read-only browsing. */
export interface TreeDir {
    name: string;
    dirs: Map<string, TreeDir>;
    files: WorkspaceFile[];
}

export function buildTree(m: WorkspaceManifest): TreeDir {
    const root: TreeDir = { name: '', dirs: new Map(), files: [] };
    for (const f of m.files) {
        const parts = f.path.split('/');
        let dir = root;
        for (let i = 0; i < parts.length - 1; i++) {
            let next = dir.dirs.get(parts[i]);
            if (!next) {
                next = { name: parts[i], dirs: new Map(), files: [] };
                dir.dirs.set(parts[i], next);
            }
            dir = next;
        }
        dir.files.push({ ...f, path: parts[parts.length - 1] });
    }
    return root;
}

// Same rule as the service: relative, forward-slash, no parent escapes.
function cleanPath(p: string): string | null {
    let s = p.replace(/\\/g, '/');
    while (s.startsWith('./')) s = s.slice(2);
    if (!s || s.startsWith('/')) return null;
    const parts = s.split('/').filter((x) => x !== '' && x !== '.');
    if (parts.length === 0 || parts.some((x) => x === '..')) return null;
    return parts.join('/');
}
