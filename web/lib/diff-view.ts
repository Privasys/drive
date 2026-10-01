// Turning the enclave's diff into something a reader can follow.
//
// The comparison arrives as hunks: runs of changed lines with their
// context, each carrying the line numbers it starts at on both sides. A
// reader needs those numbers per line, and a visible break where the diff
// skipped over unchanged text, so the gaps are not mistaken for adjacency.

import type { DiffHunk } from './drive-api';
import { changedFraction, wordDiff, type Segment } from './word-diff';

/** A row to render: either a line, or the break between two hunks. */
export type DiffRow =
    | { kind: 'gap' }
    | {
        kind: 'line';
        /** Line number in the older revision; null for an added line. */
        oldLine: number | null;
        /** Line number in the newer revision; null for a removed line. */
        newLine: number | null;
        op: ' ' | '-' | '+';
        text: string;
        /**
         * The line split into unchanged and changed runs, set only where a
         * removed line was paired with the line that replaced it and the two
         * are recognisably the same line edited.
         */
        segments?: Segment[];
    };

// A pairing is only worth marking word by word while the two lines still
// look like one line edited. Past this much difference the marks cover
// most of the row and say less than the row colour already does.
const MAX_PAIRED_CHANGE = 0.6;

export interface DiffView {
    rows: DiffRow[];
    added: number;
    removed: number;
}

/**
 * Number every line of every hunk on both sides, with a gap between hunks
 * that are not adjacent in the file.
 */
export function toDiffRows(hunks: DiffHunk[] | null | undefined): DiffView {
    const rows: DiffRow[] = [];
    let added = 0;
    let removed = 0;
    // An unchanged comparison may arrive with no list at all; a viewer that
    // dies on "nothing changed" is worse than one that shows nothing.
    (hunks ?? []).forEach((hunk, i) => {
        if (i > 0) rows.push({ kind: 'gap' });
        let oldLine = hunk.old_start;
        let newLine = hunk.new_start;
        for (const line of hunk.lines) {
            switch (line.op) {
                case '-':
                    rows.push({ kind: 'line', oldLine, newLine: null, op: '-', text: line.text });
                    oldLine++;
                    removed++;
                    break;
                case '+':
                    rows.push({ kind: 'line', oldLine: null, newLine, op: '+', text: line.text });
                    newLine++;
                    added++;
                    break;
                default:
                    rows.push({ kind: 'line', oldLine, newLine, op: ' ', text: line.text });
                    oldLine++;
                    newLine++;
            }
        }
    });
    markWordChanges(rows);
    return { rows, added, removed };
}

/**
 * Pair each run of removed lines with the run of added lines that follows
 * it, and mark the words that differ. Lines are paired in order, which is
 * what a save usually produces: line three became this, line four that.
 */
function markWordChanges(rows: DiffRow[]): void {
    let i = 0;
    while (i < rows.length) {
        const row = rows[i];
        if (row.kind !== 'line' || row.op !== '-') {
            i++;
            continue;
        }
        const removed: number[] = [];
        while (i < rows.length && rows[i].kind === 'line' && (rows[i] as { op: string }).op === '-') {
            removed.push(i);
            i++;
        }
        const added: number[] = [];
        while (i < rows.length && rows[i].kind === 'line' && (rows[i] as { op: string }).op === '+') {
            added.push(i);
            i++;
        }
        for (let k = 0; k < Math.min(removed.length, added.length); k++) {
            const before = rows[removed[k]];
            const after = rows[added[k]];
            if (before.kind !== 'line' || after.kind !== 'line') continue;
            const pair = wordDiff(before.text, after.text);
            if (
                changedFraction(pair.old) > MAX_PAIRED_CHANGE &&
                changedFraction(pair.new) > MAX_PAIRED_CHANGE
            ) {
                continue; // too different to be the same line edited
            }
            before.segments = pair.old;
            after.segments = pair.new;
        }
    }
}

/** "3 added, 1 removed", or "no changes" when the revisions match. */
export function summariseDiff(view: DiffView): string {
    if (view.added === 0 && view.removed === 0) return 'no changes';
    const parts: string[] = [];
    if (view.added > 0) parts.push(`${view.added} added`);
    if (view.removed > 0) parts.push(`${view.removed} removed`);
    return parts.join(', ');
}
