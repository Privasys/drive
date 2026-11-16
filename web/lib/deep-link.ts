// Deep links into Drive, as notifications and the wallet open it:
//   #files
//   #requests[/<tenant id>]           a drive of mine, to switch to
//   #shared[/<tenant id>/<node id>]   an item shared with me (it lives in
//                                     the sharer's drive), to bring forward
// Anything malformed is ignored rather than half applied.

export type LinkedView = 'files' | 'shared' | 'requests';

export interface SharedFocus {
    tenantID: string;
    nodeID: string;
}

export interface DeepLink {
    view: LinkedView;
    tenantID?: string;
    item?: SharedFocus;
}

const VIEWS: readonly string[] = ['files', 'shared', 'requests'];
const ID = /^[A-Za-z0-9-]{1,64}$/;

export function parseDeepLink(hash: string): DeepLink | null {
    const [v, a, b, ...rest] = hash.replace(/^#\/?/, '').split('/');
    if (!VIEWS.includes(v) || rest.length > 0) return null;
    if ((a !== undefined && !ID.test(a)) || (b !== undefined && !ID.test(b))) return null;
    if (v === 'shared') {
        if (a === undefined) return { view: 'shared' };
        return b === undefined ? null : { view: 'shared', item: { tenantID: a, nodeID: b } };
    }
    if (b !== undefined) return null;
    return a === undefined ? { view: v as LinkedView } : { view: v as LinkedView, tenantID: a };
}
