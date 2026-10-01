'use client';

import type { ReactNode } from 'react';
import { PrivasysAuthProvider } from './privasys-auth';
import { RUNTIME } from './runtime-config';

// SDK config for drive.privasys.org (Privasys wallet auth via privasys.id).
//
// Reuses the shared `privasys-platform` OIDC client on privasys.id
// (the hosted iframe handles redirect_uri internally on privasys.id,
// so no per-adopter redirect registration is required). When chat
// gets its own backend audience we'll switch this to a `privasys-chat`
// client.
const SDK_CONFIG = {
    // The control plane of the platform this Drive runs on (runtime config),
    // so the cached session row names the right origin on dev too.
    apiBase: RUNTIME.apiBase,
    appName: 'Privasys Drive',
    authOrigin:
        process.env.NEXT_PUBLIC_IDP_ORIGIN ?? 'https://privasys.id',
    rpId: process.env.NEXT_PUBLIC_IDP_RP_ID ?? 'privasys.id',
    brokerUrl:
        process.env.NEXT_PUBLIC_BROKER_URL ?? 'wss://relay.privasys.org/relay',
    clientId: process.env.NEXT_PUBLIC_AUTH_CLIENT_ID ?? 'privasys-platform',
    scope: ['openid', 'email', 'profile', 'offline_access'] as const,
    // Explicitly ask the wallet to share these so it prompts for consent at
    // sign-in (the `profile` scope alone does not raise the picker). Shared
    // transiently for display only; the platform stores no PII of its own.
    requestedAttributes: ['name', 'email'],
    privacyPolicyUrl: 'https://privasys.org/legal/',
    // Spend consent (acting-subject plan v2): Drive pays for a user's
    // query-time embeddings with the USER's credits, under a monthly cap
    // the wallet asks them to approve at sign-in. Suggested cap £5.
    // Typed natively by @privasys/auth 0.12.0; the hosted iframe honours
    // it whatever client version renders the page.
    spend: { cap: 5_000_000 }
};

export function AuthProvider({ children }: { children: ReactNode }) {
    return <PrivasysAuthProvider config={SDK_CONFIG}>{children}</PrivasysAuthProvider>;
}
