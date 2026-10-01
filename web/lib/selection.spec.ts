import { clickSelection, type SelectionState } from './selection';

const ids = ['a', 'b', 'c', 'd', 'e'];
const empty: SelectionState = { selected: new Set(), anchor: null };
const plain = { shift: false, toggle: false };
const shift = { shift: true, toggle: false };
const toggle = { shift: false, toggle: true };
const both = { shift: true, toggle: true };

const sel = (s: SelectionState) => [...s.selected].sort();

describe('row selection', () => {
    it('a plain click selects one row and anchors it', () => {
        const s = clickSelection(ids, { selected: new Set(['a', 'b']), anchor: 'a' }, 'd', plain);
        expect(sel(s)).toEqual(['d']);
        expect(s.anchor).toBe('d');
    });

    it('ctrl or cmd adds and removes, moving the anchor each time', () => {
        let s = clickSelection(ids, empty, 'b', plain);
        s = clickSelection(ids, s, 'd', toggle);
        expect(sel(s)).toEqual(['b', 'd']);
        expect(s.anchor).toBe('d');
        s = clickSelection(ids, s, 'b', toggle);
        expect(sel(s)).toEqual(['d']);
        expect(s.anchor).toBe('b');
    });

    it('shift selects the whole range from the anchor, in either direction', () => {
        const down = clickSelection(ids, { selected: new Set(['b']), anchor: 'b' }, 'd', shift);
        expect(sel(down)).toEqual(['b', 'c', 'd']);
        const up = clickSelection(ids, { selected: new Set(['d']), anchor: 'd' }, 'b', shift);
        expect(sel(up)).toEqual(['b', 'c', 'd']);
    });

    it('keeps the anchor so a second shift-click re-derives one range', () => {
        let s = clickSelection(ids, { selected: new Set(['b']), anchor: 'b' }, 'e', shift);
        expect(sel(s)).toEqual(['b', 'c', 'd', 'e']);
        expect(s.anchor).toBe('b');
        // Shrinking: the range comes from the same anchor, it does not chain.
        s = clickSelection(ids, s, 'c', shift);
        expect(sel(s)).toEqual(['b', 'c']);
    });

    it('shift alone replaces the selection, ctrl or cmd with shift adds to it', () => {
        const start: SelectionState = { selected: new Set(['a']), anchor: 'c' };
        expect(sel(clickSelection(ids, start, 'd', shift))).toEqual(['c', 'd']);
        expect(sel(clickSelection(ids, start, 'd', both))).toEqual(['a', 'c', 'd']);
    });

    it('shift on the same row as the anchor selects just that row', () => {
        const s = clickSelection(ids, { selected: new Set(['a', 'b', 'c']), anchor: 'b' }, 'b', shift);
        expect(sel(s)).toEqual(['b']);
    });

    it('shift with no anchor, or a stale one, selects the clicked row instead', () => {
        const first = clickSelection(ids, empty, 'c', shift);
        expect(sel(first)).toEqual(['c']);
        expect(first.anchor).toBe('c');
        const stale = clickSelection(ids, { selected: new Set(), anchor: 'gone' }, 'c', shift);
        expect(sel(stale)).toEqual(['c']);
        expect(stale.anchor).toBe('c');
    });
});
