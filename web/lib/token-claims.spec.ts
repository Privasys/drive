import { claimString, decodeTokenClaims } from './token-claims';

const jwt = (payload: unknown): string => {
    const json = JSON.stringify(payload);
    const bytes = new TextEncoder().encode(json);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `header.${b64}.signature`;
};

describe('decodeTokenClaims', () => {
    it('reads the claims a sign-in disclosed', () => {
        const claims = decodeTokenClaims(jwt({ sub: 'abc', email: 'someone@example.org' }));
        expect(claims.sub).toBe('abc');
        expect(claims.email).toBe('someone@example.org');
    });

    it('keeps a name that is not Latin-1', () => {
        expect(decodeTokenClaims(jwt({ name: 'Zoë Śliwiński' })).name).toBe('Zoë Śliwiński');
    });

    it('reports nothing disclosed rather than throwing', () => {
        // A minimal sign-in carries no name or email at all, which is the
        // case this exists to distinguish, and the rest must not throw on a
        // page whose only job is to open a shared file.
        expect(decodeTokenClaims(jwt({ sub: 'abc' })).email).toBeUndefined();
        for (const bad of [undefined, '', 'not-a-jwt', 'a.b', 'a.!!!.c', jwt('a string'), jwt([1, 2])]) {
            expect(decodeTokenClaims(bad as string | undefined)).toEqual({});
        }
    });
});

describe('claimString', () => {
    it('takes a usable string and nothing else', () => {
        expect(claimString({ name: 'Ada' }, 'name')).toBe('Ada');
        expect(claimString({ name: '  Ada  ' }, 'name')).toBe('Ada');
        expect(claimString({ name: '   ' }, 'name')).toBeUndefined();
        expect(claimString({ name: 42 }, 'name')).toBeUndefined();
        expect(claimString({ name: { given: 'Ada' } }, 'name')).toBeUndefined();
        expect(claimString({}, 'name')).toBeUndefined();
    });
});
