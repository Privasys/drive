// The address of a share link, and what the landing page reads back out of it.
//
// An address is the link's id in the query and its secret in the fragment,
// nothing else. A fragment never reaches a server, so the secret only ever
// travels inside the sealed session.
//
// The landing page needs to know what a restricted link requires before the
// visitor signs in, so the one ceremony asks for it (and carries the billing
// grant that pays for a proven attribute). It asks Drive's public surface,
// which runs before any session exists, with `linkPreviewKey`: a key derived
// from the secret, so the gateway that terminates that clear leg learns
// enough to preview the link and nothing that opens it.
//
// Addresses made before the public preview existed name the requirements in
// an `a=` query parameter. They are still read, as a hint the page uses only
// when the preview does not answer; the enclave checks every redeem against
// what it stored either way.

/** An attribute key as the referential spells one. Anything else is dropped. */
const KEY = /^[a-z0-9_]+(:[a-z0-9_]+)?$/;

/** More than any real link asks for, so a crafted address cannot pad the request. */
const MAX_KEYS = 24;

export interface LinkParams {
    id: string;
    secret: string;
    /** The requirement hint of an older address; empty for every new one. */
    attrs: string[];
}

export function buildLinkURL(origin: string, id: string, secret: string): string {
    return `${origin}/l?${new URLSearchParams({ id }).toString()}#${secret}`;
}

export function parseLinkURL(search: string, hash: string): LinkParams {
    const q = new URLSearchParams(search);
    return {
        id: q.get('id') ?? '',
        secret: hash.replace(/^#/, ''),
        attrs: clean((q.get('a') ?? '').split(','))
    };
}

/**
 * The key the public preview takes in place of the secret: an HMAC-SHA256
 * keyed by the secret's bytes over a fixed label, base64url without padding.
 * Mirrors linkPreviewKey in the service (internal/api/links.go).
 */
export async function linkPreviewKey(secret: string): Promise<string> {
    const raw = fromBase64Url(secret);
    const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('privasys-drive link preview v1'));
    return toBase64Url(new Uint8Array(mac));
}

function fromBase64Url(s: string): Uint8Array<ArrayBuffer> {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function toBase64Url(b: Uint8Array): string {
    let bin = '';
    for (const c of b) bin += String.fromCharCode(c);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function clean(keys: readonly string[]): string[] {
    const out: string[] = [];
    for (const raw of keys) {
        const k = raw.trim();
        if (KEY.test(k) && !out.includes(k)) out.push(k);
        if (out.length === MAX_KEYS) break;
    }
    return out;
}
