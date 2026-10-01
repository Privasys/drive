// Row selection in the file list: which rows a click leaves selected.
//
// The model is the one every file manager uses, so nobody has to learn it:
//
//   click                 select that row alone, and remember it as the anchor
//   ctrl/cmd + click      add or remove that row, and make it the new anchor
//   shift + click         select every row between the anchor and this one
//   ctrl/cmd + shift      add that range to what is already selected
//
// The anchor survives a shift-click, so moving the shift-click up and down the
// list grows and shrinks one range from the same origin rather than chaining
// new ones. Ranges are taken in DISPLAY order (the order the rows are rendered
// in, folders first), which is the order the user is pointing at.

/** Modifier keys held during the click. */
export interface ClickMods {
    /** Shift: extend from the anchor. */
    shift: boolean;
    /** Ctrl on Windows and Linux, Cmd on a Mac: add to the selection. */
    toggle: boolean;
}

/** What a click leaves behind: the selected ids and the anchor for the next one. */
export interface SelectionState {
    selected: Set<string>;
    anchor: string | null;
}

/**
 * Resolve a click on row `id` against the current state.
 *
 * `ids` is every row currently displayed, in display order. A shift-click with
 * no usable anchor (the first click in a folder, or an anchor since deleted,
 * renamed away or filtered out) degrades to a plain select rather than doing
 * nothing, so the next shift-click has somewhere to extend from.
 */
export function clickSelection(
    ids: readonly string[],
    state: SelectionState,
    id: string,
    mods: ClickMods
): SelectionState {
    if (mods.shift) {
        const to = ids.indexOf(id);
        const from = state.anchor === null ? -1 : ids.indexOf(state.anchor);
        if (to >= 0 && from >= 0) {
            const range = ids.slice(Math.min(from, to), Math.max(from, to) + 1);
            return {
                selected: new Set(mods.toggle ? [...state.selected, ...range] : range),
                anchor: state.anchor
            };
        }
        return { selected: new Set([id]), anchor: id };
    }
    if (mods.toggle) {
        const selected = new Set(state.selected);
        if (!selected.delete(id)) selected.add(id);
        return { selected, anchor: id };
    }
    return { selected: new Set([id]), anchor: id };
}
