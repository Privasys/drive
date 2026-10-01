// The share picker and the link landing page speak two vocabularies: the
// canonical keys the wallet discloses under, and the registry keys a link
// stores. Every bug in this seam has been a bad translation between them,
// and each one let a self-asserted value stand in for a certified one.

import { attributeLabel, requestKeyFor, type ShareAttribute } from './share-attributes';

// The referential as the picker folds it: a pair, the gov half of another
// pair sold under the field the enclave meters, and a plain profile field.
const attrs: ShareAttribute[] = [
    { key: 'name', label: 'Display Name', assurance: 'basic' },
    { key: 'birthdate', label: 'Date of Birth', assurance: 'basic', govKey: 'birthdate_id' },
    { key: 'given_name', label: 'First Name', assurance: 'basic', govKey: 'given_name_id' },
    {
        key: 'birthdate_id',
        label: 'Date of Birth (ID)',
        assurance: 'gov',
        marketplaceKey: 'privasys:birthdate',
        selfKey: 'birthdate'
    },
    {
        key: 'given_name_id',
        label: 'Given Names (ID)',
        assurance: 'gov',
        marketplaceKey: 'privasys:given_name',
        selfKey: 'given_name'
    },
    {
        key: 'document_valid',
        label: 'Valid Government ID',
        assurance: 'gov',
        marketplaceKey: 'privasys:document_valid'
    }
];

describe('attributeLabel', () => {
    it('reads a stored registry key back as the certified attribute', () => {
        // The bare name comes first in the referential and matches the
        // namespace-stripped key, so a fallback that ran before the
        // registry match labelled a passport requirement "Date of Birth"
        // and told the sharer their link asks for less than it does.
        expect(attributeLabel(attrs, 'privasys:birthdate')).toBe('Date of Birth (ID)');
        expect(attributeLabel(attrs, 'privasys:given_name')).toBe('Given Names (ID)');
    });

    it('still reads a self-asserted requirement as itself', () => {
        expect(attributeLabel(attrs, 'birthdate')).toBe('Date of Birth');
        expect(attributeLabel(attrs, 'name')).toBe('Display Name');
    });

    it('falls back to the key it cannot place', () => {
        expect(attributeLabel(attrs, 'acme:loyalty_tier')).toBe('acme:loyalty_tier');
    });
});

describe('requestKeyFor', () => {
    it('asks the wallet for the certified key a stored link means', () => {
        expect(requestKeyFor(attrs, 'privasys:birthdate')).toBe('birthdate_id');
        expect(requestKeyFor(attrs, 'privasys:document_valid')).toBe('document_valid');
    });

    it('never falls back onto the self-asserted twin', () => {
        // A namespace the referential does not cover. Stripping it would
        // request the reading the holder typed, for a link that is priced
        // and checked against the certified one.
        expect(requestKeyFor(attrs, 'acme:birthdate')).toBe('birthdate_id');
        expect(requestKeyFor(attrs, 'acme:loyalty_tier')).toBe('loyalty_tier');
    });

    it('leaves a self-asserted requirement alone', () => {
        expect(requestKeyFor(attrs, 'name')).toBe('name');
    });
});
