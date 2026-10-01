// The address of a share link, and what the landing page reads back out of it.
//
// A restricted link used to cost the visitor two wallet approvals. The landing
// page signed in asking for nothing, since it could not know the link's
// requirements before a session existed to ask the enclave with; it then
// resolved the link, found attributes missing and ran a second ceremony naming
// them. The visitor approved a connection that showed no attributes, then was
// asked to approve again.
//
// The sharer's page already knows the requirements when it builds the address,
// so the address carries their NAMES and the first ceremony asks for them. It
// is a hint and nothing more. The enclave still checks every redeem against the
// requirement it stored, so a hint that was stripped, stale or edited costs the
// visitor the old second step and never costs the sharer an attribute.
//
// The names go in the query and the secret stays in the fragment. A fragment
// never reaches a server log; the names may, and are no secret, since the
// visitor's wallet shows them to the visitor anyway.

/** An attribute key as the referential spells one. Anything else is dropped. */
const KEY = /^[a-z0-9_]+(:[a-z0-9_]+)?$/;

/** More than any real link asks for, so a crafted address cannot pad the request. */
const MAX_KEYS = 24;

export interface LinkParams {
    id: string;
    secret: string;
    /** Attribute keys to request up front; empty for an open link or an old one. */
    attrs: string[];
}

export function buildLinkURL(origin: string, id: string, secret: string, attrs?: readonly string[]): string {
    const q = new URLSearchParams({ id });
    const keys = clean(attrs ?? []);
    if (keys.length > 0) q.set('a', keys.join(','));
    return `${origin}/l?${q.toString()}#${secret}`;
}

export function parseLinkURL(search: string, hash: string): LinkParams {
    const q = new URLSearchParams(search);
    return {
        id: q.get('id') ?? '',
        secret: hash.replace(/^#/, ''),
        attrs: clean((q.get('a') ?? '').split(','))
    };
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
