import { parseDeepLink } from './deep-link';

const T = '031b5151-c496-4373-8377-5f17b72795dc';
const N = '9d0c6f1e-2b7a-4c55-8e3f-6a1b2c3d4e5f';

describe('deep links', () => {
    it('opens a view', () => {
        expect(parseDeepLink('#files')).toEqual({ view: 'files' });
        expect(parseDeepLink('#shared')).toEqual({ view: 'shared' });
        expect(parseDeepLink(`#requests/${T}`)).toEqual({ view: 'requests', tenantID: T });
    });

    it('brings a shared item forward', () => {
        expect(parseDeepLink(`#shared/${T}/${N}`)).toEqual({ view: 'shared', item: { tenantID: T, nodeID: N } });
        expect(parseDeepLink(`#/shared/${T}/${N}`)).toEqual({ view: 'shared', item: { tenantID: T, nodeID: N } });
    });

    it('ignores anything malformed', () => {
        for (const h of [
            '',
            '#',
            '#members',
            `#shared/${T}`,
            `#shared/${T}/${N}/x`,
            `#requests/${T}/${N}`,
            '#shared/../x',
            '#shared/a b/c',
            `#shared/${T}/<script>`
        ]) {
            expect(parseDeepLink(h)).toBeNull();
        }
    });
});
