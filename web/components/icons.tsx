// Inline SVG icons (no icon-font dependency), Material-ish to fit the
// Google-Drive / SharePoint look. All inherit currentColor.

import type { SVGProps } from 'react';

type P = SVGProps<SVGSVGElement>;
const base = (p: P) => ({
    width: 20,
    height: 20,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    ...p
});

export const FolderIcon = (p: P) => (
    <svg {...base(p)} fill="currentColor" stroke="none">
        <path d="M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8l-2-2Z" />
    </svg>
);

// A folder somebody else can reach. The person is knocked out of the
// folder rather than drawn over it (fill-rule evenodd makes the enclosed
// subpaths holes), so the mark reads the same on a row, on hover and on
// the selected-row tint without carrying a background colour of its own.
export const SharedFolderIcon = (p: P) => (
    <svg {...base(p)} fill="currentColor" stroke="none">
        <path
            fillRule="evenodd"
            clipRule="evenodd"
            d="M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8l-2-2Zm2 6.1a2.15 2.15 0 1 1 0 4.3 2.15 2.15 0 0 1 0-4.3ZM8.1 18.4c0-1.75 1.75-3.05 3.9-3.05s3.9 1.3 3.9 3.05v.25H8.1v-.25Z"
        />
    </svg>
);

export const ChevronDown = (p: P) => (
    <svg {...base(p)}>
        <path d="m6 9 6 6 6-6" />
    </svg>
);

export const FileIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" />
        <path d="M14 3v5h5" />
    </svg>
);

export const UploadIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M12 15V4" />
        <path d="m7 9 5-5 5 5" />
        <path d="M5 19h14" />
    </svg>
);

export const DownloadIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M12 4v11" />
        <path d="m7 10 5 5 5-5" />
        <path d="M5 19h14" />
    </svg>
);

export const NewFolderIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8l-2-2Z" />
        <path d="M12 11v6M9 14h6" />
    </svg>
);

export const ShareIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="18" cy="5" r="3" />
        <circle cx="6" cy="12" r="3" />
        <circle cx="18" cy="19" r="3" />
        <path d="m8.6 13.5 6.8 4M15.4 6.5 8.6 10.5" />
    </svg>
);

export const TrashIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M4 7h16M9 7V4h6v3M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13" />
    </svg>
);

export const GridIcon = (p: P) => (
    <svg {...base(p)}>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
);

export const ListIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
    </svg>
);

export const ChevronRight = (p: P) => (
    <svg {...base(p)} width={16} height={16}>
        <path d="m9 6 6 6-6 6" />
    </svg>
);

export const HomeIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="m3 11 9-8 9 8" />
        <path d="M5 10v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V10" />
    </svg>
);

export const PeopleIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="9" cy="8" r="3" />
        <path d="M3 20a6 6 0 0 1 12 0" />
        <path d="M16 5.5a3 3 0 0 1 0 5M21 20a6 6 0 0 0-4-5.7" />
    </svg>
);

export const LockIcon = (p: P) => (
    <svg {...base(p)} width={16} height={16}>
        <rect x="4" y="10" width="16" height="10" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </svg>
);

export const ShieldCheck = (p: P) => (
    <svg {...base(p)} width={16} height={16}>
        <path d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6l-7-3Z" />
        <path d="m9 12 2 2 4-4" />
    </svg>
);

export const SearchIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="11" cy="11" r="7" />
        <path d="m21 21-4.35-4.35" />
    </svg>
);

export const SearchOffIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="11" cy="11" r="7" />
        <path d="m21 21-4.35-4.35" />
        <path d="m8 8 6 6" />
    </svg>
);

export const IndexedIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="12" cy="12" r="9" />
        <path d="m8.5 12 2.5 2.5 4.5-5" />
    </svg>
);

export const ProcessingIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 3" />
    </svg>
);

export const PlusIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M12 5v14" />
        <path d="M5 12h14" />
    </svg>
);

export const MoveIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M5 9 2 12l3 3" />
        <path d="M9 5l3-3 3 3" />
        <path d="M15 19l-3 3-3-3" />
        <path d="M19 9l3 3-3 3" />
        <path d="M2 12h20" />
        <path d="M12 2v20" />
    </svg>
);

export const EyeIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
        <circle cx="12" cy="12" r="3" />
    </svg>
);

export const InboxIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M22 12h-6l-2 3h-4l-2-3H2" />
        <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z" />
    </svg>
);

export const LinkIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
);

export const CloseIcon = (p: P) => (
    <svg {...base(p)} width={18} height={18}>
        <path d="M6 6l12 12M18 6 6 18" />
    </svg>
);

export const ChartIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M4 20V13" />
        <path d="M10 20V4" />
        <path d="M16 20v-9" />
        <path d="M22 20H2" />
    </svg>
);

export const GraphIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="5" cy="6" r="2.5" />
        <circle cx="18" cy="5" r="2.5" />
        <circle cx="13" cy="18" r="2.5" />
        <path d="m7.4 5.6 8.2-0.8M6.4 8.2l5.2 8M15.6 6.9l-2 8.6" />
    </svg>
);

export const MoreIcon = (p: P) => (
    <svg {...base(p)}>
        <circle cx="5" cy="12" r="1.4" fill="currentColor" stroke="none" />
        <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
        <circle cx="19" cy="12" r="1.4" fill="currentColor" stroke="none" />
    </svg>
);

/** A workspace snapshot: a folder with a layered-tree mark. */
export const WorkspaceIcon = (p: P) => (
    <svg {...base(p)}>
        <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
        <path d="M8 13h8M8 16h5" />
    </svg>
);

/** Apps with access: a grid of squares. */
export const AppsIcon = (p: P) => (
    <svg {...base(p)}>
        <rect x="4" y="4" width="6" height="6" rx="1.2" />
        <rect x="14" y="4" width="6" height="6" rx="1.2" />
        <rect x="4" y="14" width="6" height="6" rx="1.2" />
        <rect x="14" y="14" width="6" height="6" rx="1.2" />
    </svg>
);

/** Storage: a stacked disc. */
export const StorageIcon = (p: P) => (
    <svg {...base(p)}>
        <ellipse cx="12" cy="6" rx="8" ry="3" />
        <path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6" />
        <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
    </svg>
);
