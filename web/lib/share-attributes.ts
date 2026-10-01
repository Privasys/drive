// Attributes a "restricted" share link can require a visitor to present.
//
// Sourced from the auth SDK, which ships the canonical list and the accessors
// that read it. This module used to fetch the referential and fold it by hand,
// as did the developer portal, as would any integrator: three interpretations of
// what "gov" means and three places for a new attribute to be forgotten. What is
// left here is the Drive-shaped view of the SDK's answer, and nothing that
// re-decides it.
//
// `assurance` is a display concern only, folded from the canonical flags:
//   basic    self-asserted profile attribute
//   verified provider-verified (canonical `verifiable`, e.g. email_verified)
//   gov      government-ID verified via the identity-verifier enclave
//
// Assurance is a property of the KEY: `given_name` is what the holder typed and
// `given_name_id` is what their passport says, two attributes with two prices.
// The picker offers both and says which is which, so a sharer can see that
// requiring "First Name" is not an ID check and that requiring the ID version
// costs them credits.

import {
    fetchAttributeReferential,
    isGovVerified,
    marketplaceKeyOf,
    requestableAttributes,
    type CanonicalAttribute
} from '@privasys/auth';

export type Assurance = 'basic' | 'verified' | 'gov';

export interface ShareAttribute {
    key: string;
    label: string;
    assurance: Assurance;
    /**
     * The `<namespace>:<name>` form the marketplace prices this attribute
     * under, when it sells one at all. The picker looks the displayed price up
     * by it; the service resolves the actual charge against the live
     * catalogue, so what is shown is the price, never the bill of record.
     */
    marketplaceKey?: string;
    /**
     * The self-asserted key that answers the same question without a document,
     * for a gov attribute that has one. Display only, and the reason it is a key
     * rather than a boolean: a sharer told "there is a cheaper version of this"
     * will want to pick it.
     */
    selfKey?: string;
    /** The government-backed twin of a self-asserted key, where one exists. */
    govKey?: string;
}

function toShareAttribute(a: CanonicalAttribute, govToSelf: Map<string, string>): ShareAttribute {
    // gov wins over verified: an attribute can be both (email is provider-
    // verifiable) and the stronger claim is the one worth showing.
    const assurance: Assurance = isGovVerified(a) ? 'gov' : a.verifiable ? 'verified' : 'basic';
    return {
        key: a.key,
        label: a.label,
        assurance,
        marketplaceKey: marketplaceKeyOf(a),
        selfKey: govToSelf.get(a.key),
        govKey: a.govKey
    };
}

// One fetch per page load, shared by every caller. The endpoint is CORS-open
// and sends `Cache-Control: public, max-age=3600`, so the browser cache absorbs
// repeat visits; there is nothing to gain from a copy in local storage that
// would only reintroduce the staleness this module exists to avoid.
let raw: Promise<CanonicalAttribute[]> | null = null;

/**
 * The referential the IdP is serving right now, rather than the copy bundled
 * with whichever SDK version this build pinned. A share link outlives a deploy,
 * and offering an attribute the IdP has since renamed or re-priced is a link
 * nobody can open. The SDK's picker takes it as it comes; the labels and key
 * mappings below are derived from the same fetch.
 */
export function loadReferential(): Promise<CanonicalAttribute[]> {
    if (!raw) {
        raw = fetchAttributeReferential().catch((e: unknown) => {
            // Let the next caller retry rather than caching the failure for the
            // life of the tab.
            raw = null;
            throw e;
        });
    }
    return raw;
}

/** The attributes a link can require, in the shape this module's helpers use. */
export function loadShareAttributes(): Promise<ShareAttribute[]> {
    return loadReferential().then((attrs) => {
        // The referential points from a self-asserted key to its
        // government-backed twin; the helpers need the other direction.
        const govToSelf = new Map<string, string>();
        for (const a of attrs) if (a.govKey) govToSelf.set(a.govKey, a.key);
        return requestableAttributes(attrs).map((a) => toShareAttribute(a, govToSelf));
    });
}

export function assuranceLabel(a: Assurance): string {
    return a === 'gov' ? 'Government ID' : a === 'verified' ? 'Verified' : 'Basic';
}

/**
 * Label for an attribute key as it appears on a stored link.
 *
 * The service rewrites a chosen attribute into the marketplace's namespaced
 * spelling before storing it, so a link created today names `privasys:birthdate`
 * while one created before billing names `birthdate`. Both must read back as
 * "Date of Birth"; an unknown key falls back to itself.
 *
 * The registry spelling is matched BEFORE the bare name, because the two
 * disagree about assurance and the bare one comes first in the referential:
 * `privasys:birthdate` is the passport reading and reading it back as the
 * self-asserted "Date of Birth" tells the sharer their link asks for less than
 * it does.
 *
 * `attrs` is the loaded list rather than the SDK's bundled map because a link
 * can be older than this build and still name an attribute the running IdP
 * knows, which is exactly the case the bundled copy cannot answer.
 */
export function attributeLabel(attrs: ShareAttribute[], key: string): string {
    const exact = attrs.find((a) => a.key === key || a.marketplaceKey === key);
    if (exact) return exact.label;
    const bare = key.includes(':') ? key.slice(key.indexOf(':') + 1) : key;
    return attrs.find((a) => a.key === bare)?.label ?? key;
}

/**
 * The canonical key to ASK the wallet for, given the key a stored link names.
 *
 * A link records the marketplace's namespaced spelling (`privasys:birthdate`),
 * which is the string the reservation is priced against. The IdP does not know
 * that spelling: it takes canonical keys, drops the ones it does not recognise,
 * and mints each disclosure under the key it was asked for. Asking with the
 * stored spelling therefore requests nothing at all.
 *
 * The translation must land on the GOVERNMENT-BACKED key, and that is the whole
 * reason it reads the referential instead of stripping the namespace. Assurance
 * is a property of the key: `privasys:birthdate` is sold as `birthdate_id`, while
 * a bare `birthdate` is whatever the holder typed. Asking for the bare one would
 * request a disclosure the enclave then refuses to accept, since the link is
 * checked against the claim it recorded, so the visitor would be sent round the
 * consent screen for nothing.
 *
 * A link created since the service began recording it carries the answer
 * (`attribute_claims` on resolve); this is the fallback for the ones that do
 * not, and for a namespace the referential does not cover.
 */
export function requestKeyFor(attrs: ShareAttribute[], key: string): string {
    if (!key.includes(':')) return key;
    const sold = attrs.find((a) => a.marketplaceKey === key);
    if (sold) return sold.key;
    // Outside the privasys namespace the referential has no row to map back
    // from. Prefer the bare name's government-backed twin where it has one:
    // a namespaced key is a priced disclosure, and no priced disclosure is
    // answered by the reading its holder typed.
    const bare = key.slice(key.indexOf(':') + 1);
    return attrs.find((a) => a.key === bare)?.govKey ?? bare;
}
