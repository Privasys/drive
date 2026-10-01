// Highlighting what changed WITHIN a line.
//
// A line diff says a line was replaced; it does not say which word. When a
// removed line and the line that replaced it are mostly the same, marking
// only the differing words is the difference between reading a change and
// hunting for it.
//
// This runs in the browser, on text the page already holds: both lines
// arrived in the comparison, so nothing has to be asked of the enclave.

/** A run of text, flagged when it differs from the other side. */
export interface Segment {
    text: string;
    changed: boolean;
}

// Lines are short, but a minified bundle or a base64 blob on one line is
// not. Past this many tokens the whole line is marked rather than spending
// the time on a comparison nobody is reading word by word.
const MAX_TOKENS = 400;

/**
 * Split into words, runs of whitespace, and runs of punctuation, keeping
 * every character so the segments rebuild the line exactly.
 */
export function tokenise(line: string): string[] {
    return line.match(/(\s+|[A-Za-z0-9_]+|[^\sA-Za-z0-9_]+)/g) ?? [];
}

/**
 * Compare two lines and return the segments of each, with the parts that
 * differ flagged. Identical lines come back as a single unchanged segment.
 */
export function wordDiff(oldLine: string, newLine: string): { old: Segment[]; new: Segment[] } {
    if (oldLine === newLine) {
        return { old: [{ text: oldLine, changed: false }], new: [{ text: newLine, changed: false }] };
    }
    const a = tokenise(oldLine);
    const b = tokenise(newLine);
    if (a.length === 0 || b.length === 0 || a.length > MAX_TOKENS || b.length > MAX_TOKENS) {
        return { old: [{ text: oldLine, changed: true }], new: [{ text: newLine, changed: true }] };
    }

    // Longest common subsequence over tokens. Lines are short, so the table
    // is small and the clarity is worth more than a cleverer algorithm.
    const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
    for (let i = a.length - 1; i >= 0; i--) {
        for (let j = b.length - 1; j >= 0; j--) {
            lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
        }
    }

    const oldSegs: Segment[] = [];
    const newSegs: Segment[] = [];
    const push = (segs: Segment[], text: string, changed: boolean) => {
        const last = segs[segs.length - 1];
        if (last && last.changed === changed) last.text += text;
        else segs.push({ text, changed });
    };
    let i = 0;
    let j = 0;
    while (i < a.length && j < b.length) {
        if (a[i] === b[j]) {
            push(oldSegs, a[i], false);
            push(newSegs, b[j], false);
            i++;
            j++;
        } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
            push(oldSegs, a[i], true);
            i++;
        } else {
            push(newSegs, b[j], true);
            j++;
        }
    }
    for (; i < a.length; i++) push(oldSegs, a[i], true);
    for (; j < b.length; j++) push(newSegs, b[j], true);
    return { old: oldSegs, new: newSegs };
}

/**
 * How much of a line changed, 0 to 1. Pairing two lines only helps when
 * they are recognisably the same line edited; past this the word marks
 * would be noise and the whole line reads better plainly marked.
 */
export function changedFraction(segs: Segment[]): number {
    let changed = 0;
    let total = 0;
    for (const s of segs) {
        total += s.text.length;
        if (s.changed) changed += s.text.length;
    }
    return total === 0 ? 0 : changed / total;
}
