// Reading the holder's own token, to know what they have actually disclosed.
//
// A restricted share link is answered with self-asserted values the browser
// carries, so something has to decide which values this page is entitled to
// send. The holder's stored profile cannot: the control plane answers "does
// the platform know a name for this account", which is true whether or not
// they ever agreed to give it to the sharer, and is true even for a sign-in
// that deliberately requested neither name nor email.
//
// Their token can. A claim is in it because the sign-in that minted it asked
// for that disclosure and the wallet showed them a consent screen naming it,
// so a claim present here is a disclosure they made, and one absent is one
// they were never asked for.
//
// Nothing is verified here and nothing needs to be: the signature protects
// the enclave's trust in a token, while this only decides what to offer on
// the holder's behalf from a token their own browser already holds. Anyone
// editing it would only be changing what they claim about themselves, which
// is what a self-asserted attribute means.

/** The claims carried by a JWT, or {} for anything unreadable. */
export function decodeTokenClaims(token: string | undefined): Record<string, unknown> {
    if (!token) return {};
    const parts = token.split('.');
    if (parts.length < 2) return {};
    try {
        const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
        // The payload is UTF-8, so a name outside Latin-1 has to survive the
        // trip: atob yields bytes, which are decoded rather than used as text.
        const bytes = Uint8Array.from(atob(b64 + pad), (c) => c.charCodeAt(0));
        const claims: unknown = JSON.parse(new TextDecoder().decode(bytes));
        if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return {};
        return claims as Record<string, unknown>;
    } catch {
        return {};
    }
}

/** A claim as a non-empty string, or undefined: numbers and objects are not names. */
export function claimString(claims: Record<string, unknown>, key: string): string | undefined {
    const v = claims[key];
    if (typeof v !== 'string') return undefined;
    const trimmed = v.trim();
    return trimmed === '' ? undefined : trimmed;
}
