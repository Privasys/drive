import { buildTree, parseWorkspaceManifest, summarise } from './workspace-manifest';

function bytesOf(obj: unknown): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(obj));
}

describe('workspace manifest', () => {
    it('parses a v1 manifest and drops escaping or malformed entries', () => {
        const m = parseWorkspaceManifest(
            bytesOf({
                version: 1,
                app: 'abc',
                saved_at: '2026-09-08T10:00:00Z',
                files: [
                    { path: 'src/main.go', size: 10, blob: 'AA' },
                    { path: './README.md', size: 5, blob: 'bb' },
                    { path: '../escape', size: 1, blob: 'cc' },
                    { path: '/abs', size: 1, blob: 'dd' },
                    { path: 'noblob', size: 1 }
                ]
            })
        );
        expect(m.files.map((f) => f.path)).toEqual(['src/main.go', 'README.md']);
        expect(m.files[0].blob).toBe('aa');
        expect(summarise(m)).toEqual({ fileCount: 2, bytes: 15, savedAt: '2026-09-08T10:00:00Z', app: 'abc' });
    });

    it('rejects anything that is not a v1 manifest', () => {
        expect(() => parseWorkspaceManifest(bytesOf({ version: 2, files: [] }))).toThrow();
        expect(() => parseWorkspaceManifest(bytesOf({ hello: 'world' }))).toThrow();
    });

    it('builds a directory tree for read-only browsing', () => {
        const m = parseWorkspaceManifest(
            bytesOf({
                version: 1,
                files: [
                    { path: 'src/a.go', size: 1, blob: 'x' },
                    { path: 'src/pkg/b.go', size: 2, blob: 'y' },
                    { path: 'top.txt', size: 3, blob: 'z' }
                ]
            })
        );
        const t = buildTree(m);
        expect(t.files.map((f) => f.path)).toEqual(['top.txt']);
        expect([...t.dirs.keys()]).toEqual(['src']);
        expect(t.dirs.get('src')!.files.map((f) => f.path)).toEqual(['a.go']);
        expect(t.dirs.get('src')!.dirs.get('pkg')!.files[0].size).toBe(2);
    });
});
