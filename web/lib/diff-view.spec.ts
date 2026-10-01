import { summariseDiff, toDiffRows, type DiffRow } from './diff-view';
import type { DiffHunk } from './drive-api';

const hunk = (over: Partial<DiffHunk>): DiffHunk => ({
    old_start: 1,
    old_lines: 0,
    new_start: 1,
    new_lines: 0,
    lines: [],
    ...over
});

const lineRows = (rows: DiffRow[]) => rows.filter((r) => r.kind === 'line');

describe('toDiffRows', () => {
    it('numbers both sides, skipping the side a line does not exist on', () => {
        const view = toDiffRows([
            hunk({
                old_start: 10,
                new_start: 10,
                lines: [
                    { op: ' ', text: 'context' },
                    { op: '-', text: 'was' },
                    { op: '+', text: 'is' },
                    { op: ' ', text: 'after' }
                ]
            })
        ]);
        expect(lineRows(view.rows)).toEqual([
            { kind: 'line', oldLine: 10, newLine: 10, op: ' ', text: 'context' },
            { kind: 'line', oldLine: 11, newLine: null, op: '-', text: 'was' },
            { kind: 'line', oldLine: null, newLine: 11, op: '+', text: 'is' },
            { kind: 'line', oldLine: 12, newLine: 12, op: ' ', text: 'after' }
        ]);
    });

    it('counts what changed', () => {
        const view = toDiffRows([
            hunk({
                lines: [
                    { op: '+', text: 'a' },
                    { op: '+', text: 'b' },
                    { op: '-', text: 'c' }
                ]
            })
        ]);
        expect(view.added).toBe(2);
        expect(view.removed).toBe(1);
    });

    it('marks the break between hunks so the gap is not read as adjacency', () => {
        const view = toDiffRows([
            hunk({ old_start: 1, new_start: 1, lines: [{ op: '-', text: 'early' }] }),
            hunk({ old_start: 90, new_start: 89, lines: [{ op: '+', text: 'late' }] })
        ]);
        expect(view.rows.map((r) => r.kind)).toEqual(['line', 'gap', 'line']);
        // Numbering restarts from the second hunk's own header.
        const [, , second] = view.rows;
        expect(second).toEqual({ kind: 'line', oldLine: null, newLine: 89, op: '+', text: 'late' });
    });

    it('has nothing to show for an empty comparison', () => {
        const view = toDiffRows([]);
        expect(view.rows).toEqual([]);
        expect(summariseDiff(view)).toBe('no changes');
    });
});

describe('summariseDiff', () => {
    it('reports each direction only when it happened', () => {
        expect(summariseDiff({ rows: [], added: 3, removed: 1 })).toBe('3 added, 1 removed');
        expect(summariseDiff({ rows: [], added: 2, removed: 0 })).toBe('2 added');
        expect(summariseDiff({ rows: [], added: 0, removed: 5 })).toBe('5 removed');
    });
});

describe('a comparison that changed nothing', () => {
    it('survives a missing list rather than dying on it', () => {
        expect(toDiffRows(null)).toEqual({ rows: [], added: 0, removed: 0 });
        expect(toDiffRows(undefined)).toEqual({ rows: [], added: 0, removed: 0 });
    });
});
