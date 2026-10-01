import { changedFraction, tokenise, wordDiff } from './word-diff';
import { toDiffRows } from './diff-view';
import type { DiffHunk } from './drive-api';

const rebuild = (segs: { text: string }[]) => segs.map((s) => s.text).join('');

describe('tokenise', () => {
    it('keeps every character, so the segments can rebuild the line', () => {
        for (const line of ['a b', '  indented(x, y);', '', 'ünïcode — dash', 'a1_b2 c']) {
            expect(tokenise(line).join('')).toBe(line);
        }
    });
});

describe('wordDiff', () => {
    it('marks only the word that changed', () => {
        const { old, new: now } = wordDiff(
            'Privacy that is verifiable, not promised.',
            'Privacy that is provable, not promised.'
        );
        expect(rebuild(old)).toBe('Privacy that is verifiable, not promised.');
        expect(rebuild(now)).toBe('Privacy that is provable, not promised.');
        expect(old.filter((s) => s.changed).map((s) => s.text)).toEqual(['verifiable']);
        expect(now.filter((s) => s.changed).map((s) => s.text)).toEqual(['provable']);
    });

    it('treats identical lines as unchanged throughout', () => {
        const { old, new: now } = wordDiff('same line', 'same line');
        expect(old).toEqual([{ text: 'same line', changed: false }]);
        expect(now).toEqual([{ text: 'same line', changed: false }]);
    });

    it('marks an insertion on one side only', () => {
        const { old, new: now } = wordDiff('one two', 'one and two');
        expect(old.some((s) => s.changed)).toBe(false);
        expect(now.filter((s) => s.changed).map((s) => s.text.trim())).toEqual(['and']);
        expect(rebuild(now)).toBe('one and two');
    });

    it('flags the whole line when nothing is shared', () => {
        const { old, new: now } = wordDiff('alpha', 'beta');
        expect(changedFraction(old)).toBe(1);
        expect(changedFraction(now)).toBe(1);
    });

    it('handles an empty side', () => {
        const { old, new: now } = wordDiff('', 'added text');
        expect(rebuild(old)).toBe('');
        expect(rebuild(now)).toBe('added text');
    });
});

describe('changedFraction', () => {
    it('measures how much of a line differs', () => {
        expect(changedFraction([{ text: 'abcd', changed: false }])).toBe(0);
        expect(changedFraction([{ text: 'ab', changed: true }, { text: 'cd', changed: false }])).toBe(0.5);
        expect(changedFraction([])).toBe(0);
    });
});

const hunk = (lines: DiffHunk['lines']): DiffHunk => ({
    old_start: 1,
    old_lines: 0,
    new_start: 1,
    new_lines: 0,
    lines
});

describe('pairing removed lines with what replaced them', () => {
    it('marks the words that changed on both sides of a pair', () => {
        const { rows } = toDiffRows([
            hunk([
                { op: ' ', text: 'context' },
                { op: '-', text: 'the quick brown fox' },
                { op: '+', text: 'the quick red fox' }
            ])
        ]);
        const lines = rows.filter((r) => r.kind === 'line');
        const removed = lines[1];
        const added = lines[2];
        if (removed.kind !== 'line' || added.kind !== 'line') throw new Error('expected lines');
        expect(removed.segments?.filter((s) => s.changed).map((s) => s.text)).toEqual(['brown']);
        expect(added.segments?.filter((s) => s.changed).map((s) => s.text)).toEqual(['red']);
    });

    it('pairs several removals with several additions in order', () => {
        const { rows } = toDiffRows([
            hunk([
                { op: '-', text: 'alpha one' },
                { op: '-', text: 'beta two' },
                { op: '+', text: 'alpha ONE' },
                { op: '+', text: 'beta TWO' }
            ])
        ]);
        const lines = rows.filter((r) => r.kind === 'line');
        for (const row of lines) {
            if (row.kind !== 'line') continue;
            expect(row.segments).toBeDefined();
            // The shared word stays unmarked on every row.
            expect(row.segments?.some((s) => !s.changed)).toBe(true);
        }
    });

    it('leaves a removal with no counterpart unmarked', () => {
        const { rows } = toDiffRows([hunk([{ op: '-', text: 'gone entirely' }])]);
        const [row] = rows;
        if (row.kind !== 'line') throw new Error('expected a line');
        expect(row.segments).toBeUndefined();
    });

    it('does not mark words when the two lines are not recognisably the same line', () => {
        const { rows } = toDiffRows([
            hunk([
                { op: '-', text: 'completely different content here' },
                { op: '+', text: 'nothing alike whatsoever' }
            ])
        ]);
        for (const row of rows) {
            if (row.kind !== 'line') continue;
            expect(row.segments).toBeUndefined();
        }
    });
});
