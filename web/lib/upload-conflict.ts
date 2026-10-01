// Uploading onto a name that is already taken.
//
// The Drive refuses a colliding upload (409) rather than guessing, so the
// front asks: replace what is there, keep both, or skip this one. A drop
// of many files can collide many times, hence "do this for the rest".

/** What the user chose for a colliding upload. */
export type ConflictAction = 'replace' | 'copy' | 'skip';

export interface ConflictChoice {
    action: ConflictAction;
    /** Apply the same choice to every later collision in this drop. */
    applyToRest: boolean;
}

/**
 * A free name next to the ones already there: "report.pdf" becomes
 * "report (1).pdf", then "report (2).pdf". A leading dot is part of the
 * name, not an extension, so ".env" becomes ".env (1)".
 */
export function copyName(name: string, taken: Iterable<string>): string {
    const used = new Set(taken);
    const dot = name.lastIndexOf('.');
    const stem = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : '';
    for (let i = 1; ; i++) {
        const candidate = `${stem} (${i})${ext}`;
        if (!used.has(candidate)) return candidate;
    }
}
