// Small display helpers for the Drive UI.

export function formatBytes(n: number): string {
    if (!n || n < 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    const v = n / Math.pow(1024, i);
    return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

/** A short, human label for the file kind (from a mime hint or name). */
export function kindLabel(name: string, mime?: string): string {
    if (mime) {
        if (mime.startsWith('image/')) return 'Image';
        if (mime.startsWith('video/')) return 'Video';
        if (mime.startsWith('audio/')) return 'Audio';
        if (mime === 'application/pdf') return 'PDF';
        if (mime.startsWith('text/')) return 'Text';
    }
    const ext = name.split('.').pop()?.toLowerCase() ?? '';
    if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(ext)) return 'Image';
    if (['pdf'].includes(ext)) return 'PDF';
    if (['doc', 'docx'].includes(ext)) return 'Document';
    if (['xls', 'xlsx', 'csv'].includes(ext)) return 'Spreadsheet';
    if (['zip', 'tar', 'gz'].includes(ext)) return 'Archive';
    if (['txt', 'md'].includes(ext)) return 'Text';
    return ext ? ext.toUpperCase() : 'File';
}

/** "me" for the caller, else the first 8 chars of the sub. */
export function ownerLabel(createdBy: string | undefined, mySub: string): string {
    if (!createdBy) return 'me';
    if (createdBy === mySub) return 'me';
    return createdBy.slice(0, 8);
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Compact date: "14 Jul" this year, "14 Jul 2025" otherwise. */
export function formatDate(iso?: string): string {
    if (!iso) return '';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    const base = `${d.getDate()} ${MONTHS[d.getMonth()]}`;
    return d.getFullYear() === new Date().getFullYear() ? base : `${base} ${d.getFullYear()}`;
}

/** Human duration from milliseconds: "45 s", "12 min 5 s", "3 h 20 min". */
export function formatDuration(ms: number): string {
    if (!ms || ms <= 0) return '0 s';
    if (ms < 1000) return '<1 s';
    const s = Math.round(ms / 1000);
    if (s < 60) return `${s} s`;
    const m = Math.floor(s / 60);
    if (m < 60) {
        const rs = s % 60;
        return rs ? `${m} min ${rs} s` : `${m} min`;
    }
    const h = Math.floor(m / 60);
    const rm = m % 60;
    return rm ? `${h} h ${rm} min` : `${h} h`;
}

/** Relative time: "just now", "5 min ago", "3 h ago", else a compact date. */
export function relativeTime(iso?: string): string {
    if (!iso) return '';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    const diff = Date.now() - d.getTime();
    if (diff < 60_000) return 'just now';
    const min = Math.floor(diff / 60_000);
    if (min < 60) return `${min} min ago`;
    const h = Math.floor(min / 60);
    if (h < 24) return `${h} h ago`;
    const days = Math.floor(h / 24);
    if (days === 1) return 'yesterday';
    if (days < 7) return `${days} days ago`;
    return formatDate(iso);
}

/** subject:<sub> -> <sub>; leaves link/app subjects intact. */
export function granteeLabel(subject: string): string {
    if (subject.startsWith('subject:')) return subject.slice('subject:'.length);
    if (subject === 'link') return 'Anyone with the link';
    if (subject.startsWith('app:')) return `App ${subject.slice('app:'.length, 12)}…`;
    return subject;
}

/** A stable, deterministic pastel colour for an avatar from a string. */
export function avatarColor(seed: string): string {
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) & 0xffff;
    return `hsl(${h % 360} 55% 55%)`;
}

export function initials(label: string): string {
    const s = label.replace(/[^a-zA-Z0-9]/g, '');
    return (s.slice(0, 2) || '?').toUpperCase();
}
