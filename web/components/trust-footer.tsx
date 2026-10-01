'use client';

import { useEffect, useState } from 'react';
import type { SealedSession } from '@privasys/auth';
import {
    AttestationStatusBadge,
    attestationStatusOf,
    computeAttestationSummary,
    useAttestation
} from '@privasys/attestation-view';
import { useAuth } from '~/lib/privasys-auth';
import { RUNTIME } from '~/lib/runtime-config';
import { getStatus } from '~/lib/drive-api';

// Sidebar footer trust block, mirroring chat's "Secure enclave ✓ Verified"
// pill. It runs a live attestation of the Drive enclave (the same handshake
// the Security view offers, but headless) and shows the UI and backend build
// ids so what you are looking at is always identifiable.
//
// The attestation needs the Drive app id (runtime config, from the service)
// to address the platform attest endpoint; without it the pill reads "Not
// attested" rather than lying.

const API_BASE = RUNTIME.apiBase;
const APP_ID = RUNTIME.appId;
const UI_COMMIT = process.env.NEXT_PUBLIC_COMMIT_SHA ?? '';
const AS_VERIFY = 'https://as.privasys.org/verify-quote';

export function TrustFooter({
    session,
    onOpenSecurity
}: {
    session: SealedSession;
    /** Open the full-pane Security view (the whole pill is the trigger). */
    onOpenSecurity?: () => void;
}) {
    const { getTokenForAudience } = useAuth();

    const attestUrl = APP_ID ? `${API_BASE}/api/v1/apps/${APP_ID}/attest` : '';
    const [state] = useAttestation({
        attestUrl,
        verifyQuoteUrl: AS_VERIFY,
        token: () => getTokenForAudience('attestation-server'),
        verifyQuoteToken: () => getTokenForAudience('attestation-server'),
        autoInspect: Boolean(attestUrl),
        autoVerifyQuote: true
    });
    const summary = computeAttestationSummary(state, undefined);
    const { status, reason } = attestationStatusOf(summary, Boolean(attestUrl));

    // Backend build id, read once from /status over the sealed session.
    const [backend, setBackend] = useState<string | null>(null);
    useEffect(() => {
        let cancelled = false;
        void getStatus(session)
            .then((s) => {
                if (!cancelled) setBackend(s.version ?? null);
            })
            .catch(() => {
                /* transient — the pill still carries the trust signal */
            });
        return () => {
            cancelled = true;
        };
    }, [session]);

    const short = (v: string) => (/^[0-9a-f]{7,}$/i.test(v) ? v.slice(0, 7) : v);

    return (
        <div
            className="border-t px-4 py-3 text-xs"
            style={{ borderColor: 'var(--drv-border)', color: 'var(--drv-text-muted)' }}
        >
            <button
                type="button"
                onClick={onOpenSecurity}
                title="Open the enclave attestation report"
                className="-mx-2 flex w-[calc(100%+1rem)] items-center gap-2 rounded-md px-2 py-1 text-left transition-colors hover:bg-[var(--drv-surface-2)]"
            >
                <span style={{ color: 'var(--drv-text-secondary)' }}>Secure enclave</span>
                <AttestationStatusBadge status={status} reason={reason} className="shrink-0" />
                <ChevronRight />
            </button>
            <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 px-0.5">
                {UI_COMMIT && <span>UI {short(UI_COMMIT)}</span>}
                {backend && <span>Drive {short(backend)}</span>}
            </div>
        </div>
    );
}

function ChevronRight() {
    return (
        <svg
            width="13"
            height="13"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="ml-auto shrink-0 opacity-60"
            aria-hidden="true"
        >
            <path d="m9 18 6-6-6-6" />
        </svg>
    );
}
