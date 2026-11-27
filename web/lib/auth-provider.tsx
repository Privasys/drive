'use client';

import { useMemo, type ReactNode } from 'react';
import type { AuthFrameConfig } from '@privasys/auth';
import { PrivasysAuthProvider } from './privasys-auth';
import { driveHost } from './drive-api';
import { RUNTIME } from './runtime-config';

// Drive's pitch for the SDK gate's left panel (page presentation). The SDK
// styles it; strings only.
const DRIVE_PITCH = {
    title: 'Your files, sealed.',
    description:
        'Privasys Drive keeps every file end-to-end encrypted inside a ' +
        'hardware-protected enclave. The operator can never read your data, ' +
        'and you can verify it yourself by remote attestation.',
    bullets: [
        'Sealed browser-to-enclave transport. The gateway only sees ciphertext.',
        'Directories and per-file, per-folder sharing you control.',
        'No passwords. Sign in with the Privasys Wallet on your phone.',
        'Attestation-verified confidential computing. Verify it yourself, no need to trust the operator.'
    ]
};

// The environment's own client when the service names one (dev: the test
// platform's), so dev and production sign-ins never share a session.
const PAGE_CLIENT_ID = RUNTIME.clientId || process.env.NEXT_PUBLIC_AUTH_CLIENT_ID || 'privasys-platform';

function isLinkPage(): boolean {
    return typeof window !== 'undefined' && /^\/l\/?$/.test(window.location.pathname);
}

// The sign-in for drive.privasys.org. Every method is offered: a wallet
// sign-in reaches Drive over the sealed channel the wallet approves in the
// same tap (`apps`); any other reaches it directly, as a guest (see
// use-drive).
//
// The share-link page signs its visitor in differently: with the client
// Drive binds a link's billing grant to, inline in the page, and with the
// minimal scope, so opening a link never asks for a name or an email. What a
// restricted link requires is asked for at connect() (use-drive).
function driveConfig(): AuthFrameConfig {
    const host = driveHost();
    const base = {
        // The platform audience of the environment this Drive runs in, as the
        // service writes it (ui_audience). Unset: the sign-in default.
        ...(RUNTIME.audience ? { audience: RUNTIME.audience } : {}),
        appName: 'Privasys Drive',
        authOrigin: process.env.NEXT_PUBLIC_IDP_ORIGIN ?? 'https://privasys.id',
        brokerUrl: process.env.NEXT_PUBLIC_BROKER_URL ?? 'wss://relay.privasys.org/relay',
        privacyPolicyUrl: 'https://privasys.org/legal/',
        ...(host ? { apps: [host] } : {}),
        // Drive pays for a user's query-time embeddings with the user's
        // credits, under a monthly cap the wallet asks them to approve at
        // sign-in. Suggested cap £5.
        spend: { cap: 5_000_000 }
    };
    if (isLinkPage()) {
        return {
            ...base,
            clientId: RUNTIME.linkClientId || PAGE_CLIENT_ID,
            scope: ['openid', 'offline_access'],
            presentation: 'inline'
        };
    }
    return {
        ...base,
        clientId: PAGE_CLIENT_ID,
        scope: ['openid', 'email', 'profile', 'offline_access'],
        presentation: 'page',
        pitch: DRIVE_PITCH,
        app: {
            displayName: 'Privasys Drive',
            ...(typeof window !== 'undefined'
                ? { logoUrl: `${window.location.origin}/favicon/privasys-logo.mini.svg` }
                : {})
        }
    };
}

export function AuthProvider({ children }: { children: ReactNode }) {
    const config = useMemo(driveConfig, []);
    return <PrivasysAuthProvider config={config}>{children}</PrivasysAuthProvider>;
}
