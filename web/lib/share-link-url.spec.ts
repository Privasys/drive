import { buildLinkURL, linkPreviewKey, parseLinkURL } from './share-link-url';

const split = (url: string) => {
    const u = new URL(url);
    return { search: u.search, hash: u.hash };
};

describe('share link addresses', () => {
    it('carries only the id and the secret', () => {
        const url = buildLinkURL('https://drive.test.privasys.org', 'abc', 'S3cr3t');
        expect(url).toBe('https://drive.test.privasys.org/l?id=abc#S3cr3t');
        const { search, hash } = split(url);
        expect(parseLinkURL(search, hash)).toEqual({ id: 'abc', secret: 'S3cr3t', attrs: [] });
    });

    it('still reads the requirement hint of an older address', () => {
        expect(parseLinkURL('?id=abc&a=name%2Cemail', '#S3cr3t')).toEqual({
            id: 'abc',
            secret: 'S3cr3t',
            attrs: ['name', 'email']
        });
    });

    it('derives the same preview key as the service', async () => {
        // The vector is pinned in the service too (TestLinkPreviewKeyVector).
        expect(await linkPreviewKey('BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc')).toBe(
            'urExxQiXkVuo6HKpYJOnNLetpELWRuayjBd9bf0DtgQ'
        );
    });

    it('keeps the secret out of the query', () => {
        const url = buildLinkURL('https://drive.privasys.org', 'abc', 'S3cr3t');
        expect(new URL(url).search).not.toContain('S3cr3t');
    });

    it('reads an address from before the hint existed', () => {
        expect(parseLinkURL('?id=abc', '#S3cr3t')).toEqual({ id: 'abc', secret: 'S3cr3t', attrs: [] });
    });

    it('drops anything that is not an attribute key', () => {
        // The hint is untrusted input headed for an authorize request.
        expect(parseLinkURL('?id=a&a=name,,EMAIL,<script>,privasys:age_over_18,name, email ', '#s').attrs).toEqual([
            'name',
            'privasys:age_over_18',
            'email'
        ]);
    });

    it('caps how much a crafted address can ask for', () => {
        const many = Array.from({ length: 100 }, (_, i) => `k${i}`).join(',');
        expect(parseLinkURL(`?id=a&a=${many}`, '#s').attrs).toHaveLength(24);
    });
});
