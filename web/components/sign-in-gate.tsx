'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useDrive } from '~/lib/use-drive';

// Full-page sign-in gate. The auth SDK renders the ENTIRE surface (page
// presentation, Option C): a templated header with Drive's logo and name,
// the "Secured by Privasys ID" seal and a Close control; Drive's pitch in
// the SDK-styled left panel; every ceremony state on the right; the SDK
// terms footer. Drive renders NO chrome of its own here — one container,
// and reactions to three outcomes: ready (drive bootstraps), cancelled
// (a quiet closed panel with a way back in), error (banner with retry).
export function SignInGate() {
    const { status, error, connectInto } = useDrive();
    const ceremonyRef = useRef<HTMLDivElement>(null);
    const started = useRef(false);
    const [closed, setClosed] = useState(false);

    const start = useCallback(() => {
        const el = ceremonyRef.current;
        if (!el || started.current) return;
        started.current = true;
        setClosed(false);
        void connectInto(el)
            .then((outcome) => {
                if (outcome === 'cancelled') setClosed(true);
            })
            .finally(() => {
                started.current = false;
            });
    }, [connectInto]);

    useEffect(() => {
        if (status !== 'signed-out' || closed) return;
        start();
    }, [status, closed, start]);

    if (status === 'misconfigured') {
        return (
            <div className="flex min-h-screen items-center justify-center px-6" style={{ background: 'var(--drv-surface)' }}>
                <p className="max-w-md rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-600">
                    {error ?? 'Drive is not configured.'}
                </p>
            </div>
        );
    }

    if (closed) {
        return (
            <div className="flex min-h-screen flex-col items-center justify-center gap-4 px-6 text-center" style={{ background: 'var(--drv-surface)' }}>
                <h1 className="text-xl font-semibold" style={{ color: 'var(--drv-text)' }}>
                    Sign-in closed
                </h1>
                <p className="max-w-sm text-sm" style={{ color: 'var(--drv-text-muted)' }}>
                    You need to sign in with Privasys ID to open your drive.
                </p>
                {/* Clearing `closed` remounts the ceremony container; the
                    effect then restarts connect() against it. */}
                <button
                    onClick={() => setClosed(false)}
                    className="drv-btn-primary rounded-full px-6 py-2.5 text-[15px]"
                >
                    Sign in
                </button>
            </div>
        );
    }

    return (
        <div className="flex min-h-screen flex-col" style={{ background: 'var(--drv-surface)' }}>
            {status === 'error' && (
                <div className="mx-auto mt-6 flex max-w-md items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-500">
                    <span className="flex-1">{error ?? 'Could not connect to Drive.'}</span>
                    <button
                        onClick={start}
                        className="shrink-0 rounded-full border border-red-500/40 px-3 py-1 text-xs font-medium hover:bg-red-500/10"
                    >
                        Try again
                    </button>
                </div>
            )}
            {/* The SDK gate fills the viewport (page presentation). */}
            <div ref={ceremonyRef} className="min-h-[640px] w-full flex-1" />
        </div>
    );
}
