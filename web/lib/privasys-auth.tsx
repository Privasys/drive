'use client';

import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useRef,
    useState,
    type ReactNode
} from 'react';
import { AuthFrame, type AuthFrameConfig, type SealedSession } from '@privasys/auth';

// Auth context for the Privasys Chat front-end.
//
// Mirrors the developer-portal implementation
// (`developer.privasys.org/lib/privasys-auth.tsx`). The full
// portal version also handles role decoding and a session-cookie
// for Next.js middleware; chat doesn't currently need either, so
// this is the trimmed-down variant.
//
// All websites use the hosted `@privasys/auth` SDK against
// privasys.id (OIDC PKCE inside an iframe).

export interface AuthSession {
    /** JWT access_token issued by the IdP. */
    accessToken: string;
    /** RP ID this session is authenticated for. */
    rpId: string;
    /** When the session was established (epoch ms). */
    authenticatedAt: number;
}

/**
 * Outcome of a sealed-session (re-)establish attempt.
 *
 * - `ok`         — a live sealed session is installed.
 * - `no-voucher` — the user never completed a sealed sign-in for this app.
 * - `rejected`   — the enclave refused the voucher; its identity/measurement
 *                  changed and a fresh wallet ceremony is required.
 * - `unavailable`— transient transport failure, worth retrying.
 */
export type SealedResumeOutcome = 'ok' | 'no-voucher' | 'rejected' | 'unavailable';

/**
 * Why the enclave refused the EncAuth voucher, when it said (SDK rejects
 * with `rejected:<reason>`): `workload-changed` = the app's code/config
 * was updated since the user verified it; `enc-changed` = the hosting
 * platform's identity changed. Both need a fresh wallet ceremony — the
 * wallet then shows the user exactly what changed. Null when the enclave
 * gave no reason (older enclave, or a voucher-lifecycle refusal).
 */
export type SealedStaleReason = 'workload-changed' | 'enc-changed' | null;

function parseStaleReason(msg: string): SealedStaleReason {
    if (msg.includes('workload-changed')) return 'workload-changed';
    if (msg.includes('enc-changed')) return 'enc-changed';
    return null;
}

// withTimeout rejects with `label` if p does not settle within ms, so a hung
// sealed-session ceremony (iframe/enclave never responds) cannot park a
// caller's await indefinitely.
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(label)), ms);
        p.then(
            (v) => { clearTimeout(t); resolve(v); },
            (e) => { clearTimeout(t); reject(e as Error); }
        );
    });
}

interface AuthContextValue {
    session: AuthSession | null;
    loading: boolean;
    expired: boolean;
    /**
     * Sealed CBOR-AES-GCM session against the enclave that the wallet
     * attested during sign-in. Only populated when the caller passed
     * `sessionRelayHost` to `signIn`/`signInInto` — typically the
     * `instance.session_relay.app_host` returned by the management
     * service.
     */
    sealedSession: SealedSession | null;
    /**
     * Mint a per-audience JWT (challenge mode) without rotating the
     * primary session. Used to call attestation-server's verify-quote
     * endpoint with `aud=attestation-server`. The returned token is
     * single-use-shaped (15-minute lifetime, audience-bound) and is
     * never persisted into the session context.
     */
    getTokenForAudience: (audience: string) => Promise<string>;
    /** Open the auth ceremony in a full-screen overlay (default). */
    signIn: (opts?: { sessionRelayHost?: string; extraAppHosts?: string[] }) => Promise<void>;
    /**
     * Mount the auth iframe inline inside `container` (instead of a
     * full-screen overlay). Used by the in-panel sign-in view so the
     * surrounding chat shell stays visible. The provider builds a
     * one-shot `AuthFrame` per call; once the ceremony resolves, the
     * persistent renewal frame picks up the session via cross-origin
     * SSO and starts the silent-renewal timer.
     */
    signInInto: (container: HTMLElement, opts?: { sessionRelayHost?: string; extraAppHosts?: string[]; requestedAttributes?: readonly string[] }) => Promise<void>;
    /**
     * One-call gate (SDK `connect()`): silent restore → one-tap wallet
     * re-approval (enclave measurement changed) → full ceremony, all
     * rendered by the SDK inside `container` in page presentation with
     * the app's `pitch`. Registers the sealed session under `appHost`
     * so `getSealedSession(appHost)` returns it. Resolves with the
     * sealed session; rejects with the SDK's typed ConnectError
     * (`code: 'cancelled' | 'timeout' | 'failed'`).
     */
    connectInto: (container: HTMLElement, opts: {
        appHost: string;
        pitch?: { title?: string; description?: string; bullets?: string[]; logoUrl?: string };
        /** App identity for the SDK gate header (logo + display name). */
        app?: { logoUrl?: string; displayName?: string };
        methods?: readonly ('wallet' | 'passkey' | 'social')[];
    }) => Promise<SealedSession | null>;
    /**
     * Abort an in-flight `signInInto`/`connectInto` ceremony. The pending
     * promise rejects and the SDK removes its iframe. No-op when nothing
     * is in flight.
     */
    cancelSignIn: () => void;
    /**
     * Re-establish the sealed enclave session after a page reload with
     * no wallet ceremony and no push: the privasys.id iframe bootstraps
     * against the enclave using the EncAuth voucher stored at the IdP.
     * No-op when a sealed session is already live; silently leaves
     * `sealedSession` null when no voucher exists or the enclave
     * refused it (sign-in then re-creates it).
     */
    resumeSealed: (appHost: string) => Promise<void>;
    /**
     * Force-rebuild the primary sealed enclave session, tearing down the
     * existing (possibly dead) transport first. Unlike `resumeSealed` this
     * does NOT short-circuit when a sealed session is already present — it is
     * the recovery path after the enclave was redeployed or went unreachable.
     * Returns the outcome so the caller can distinguish a transient failure
     * (retry) from a measurement change (`rejected` → prompt re-sign-in).
     * Leaves the per-host sessions (e.g. chat-service) untouched; those
     * self-heal via PrivasysSession's request()-level silent rebind.
     */
    reestablishSealed: (appHost: string) => Promise<SealedResumeOutcome>;
    /**
     * Why the last `reestablishSealed` rejection happened, when the enclave
     * said (`workload-changed` = app updated, `enc-changed` = platform
     * changed). Cleared when a sealed session is (re-)established. Drives
     * the specific wording on the stale-transport banner.
     */
    staleReason: SealedStaleReason;
    /**
     * True while a sealed-session recovery is waiting on a wallet push
     * approval — most often because the enclave's platform was upgraded and
     * the user must approve the new measurement on their phone.
     */
    sealedApprovalPending: boolean;
    /**
     * Return a sealed session for an arbitrary enclave `appHost` (e.g. the
     * chat-service back-end), independent of the primary `sealedSession`
     * (which is the inference instance). Per-host cached; resumes silently
     * via the EncAuth voucher. Returns null when not signed in, no voucher
     * exists, or the enclave refused — callers then degrade gracefully.
     */
    getSealedSession: (appHost: string) => Promise<SealedSession | null>;
    /**
     * Ask the wallet (via push notification) to voucher an additional enclave
     * host for the current session — one biometric approval on the phone, no
     * sign-out. Rejects with `no-push` (session not wallet-backed), `timeout`
     * (not approved / old wallet), or `no-session`.
     */
    requestAppVoucher: (appHost: string) => Promise<void>;
    signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
    session: null,
    loading: true,
    expired: false,
    sealedSession: null,
    getTokenForAudience: async () => {
        throw new Error('getTokenForAudience called outside PrivasysAuthProvider');
    },
    signIn: async () => {},
    signInInto: async () => {},
    connectInto: async () => null,
    cancelSignIn: () => {},
    resumeSealed: async () => {},
    reestablishSealed: async () => 'unavailable',
    staleReason: null,
    sealedApprovalPending: false,
    getSealedSession: async () => null,
    requestAppVoucher: async () => {},
    signOut: async () => {}
});

export function useAuth(): AuthContextValue {
    return useContext(AuthContext);
}

function isJwt(token: string): boolean {
    return typeof token === 'string' && token.split('.').length === 3;
}

function sessionFromToken(
    token: string,
    rpId: string,
    authenticatedAt?: number
): AuthSession {
    return {
        accessToken: token,
        rpId,
        authenticatedAt: authenticatedAt ?? Date.now()
    };
}

interface PrivasysAuthProviderProps {
    children: ReactNode;
    config: AuthFrameConfig;
}

// Drive's transport constraint, applied to EVERY sign-in path here.
//
// The Drive API is reachable only over the wallet-attested sealed channel:
// the enclave serves a self-signed RA-TLS certificate, and only the wallet
// can verify it and relay a session. A social or passkey sign-in therefore
// authenticates the visitor and then has nowhere to go, so offering those
// options is a promise the product cannot keep — a share-link recipient who
// picked "Continue with Google" would sign in and still be unable to open
// the file.
//
// It lives here rather than at each call site because it was previously
// passed only by connectInto, so the share-link flow (signInInto) silently
// offered every provider. Lift it once a wallet-less transport exists.
const DRIVE_METHODS = ['wallet'] as const;

export function PrivasysAuthProvider({ children, config }: PrivasysAuthProviderProps) {
    const [session, setSession] = useState<AuthSession | null>(null);
    const [loading, setLoading] = useState(true);
    const [expired, setExpired] = useState(false);
    const [sealedSession, setSealedSession] = useState<SealedSession | null>(null);
    const [staleReason, setStaleReason] = useState<SealedStaleReason>(null);
    // True while a sealed-session recovery is waiting on a wallet push
    // approval (most often the enclave's platform was upgraded and the user
    // must approve the new measurement on their phone).
    const [sealedApprovalPending, setSealedApprovalPending] = useState(false);
    const frameRef = useRef<AuthFrame | null>(null);
    // In-flight one-shot inline/connect frame; lets cancelSignIn abort the
    // ceremony when the user navigates away.
    const inlineFrameRef = useRef<AuthFrame | null>(null);
    // Dedicated frame for voucher-based sealed resume. Separate from the
    // persistent renewal frame because `sessionRelay.appHost` is a
    // constructor-only option and the appHost is per-instance (only
    // known once the instance metadata loads).
    const sealedFrameRef = useRef<AuthFrame | null>(null);
    const sealedHostRef = useRef<string | null>(null);
    const sealedResumeInFlight = useRef<Promise<void> | null>(null);
    // Per-host sealed sessions for enclaves other than the inference instance
    // (e.g. the chat-service back-end). Each enclave needs its own sealed
    // session; this map keeps one frame + session per appHost.
    const sealedByHost = useRef<Map<string, { frame: AuthFrame; session: SealedSession }>>(new Map());
    const sealedByHostInFlight = useRef<Map<string, Promise<SealedSession | null>>>(new Map());

    const getFrame = useCallback(() => {
        if (!frameRef.current) {
            frameRef.current = new AuthFrame(config);
            frameRef.current.onSessionExpired = () => {
                setSession(null);
                setExpired(true);
            };
            frameRef.current.onSessionRenewed = (_rpId, accessToken) => {
                // Adopt the freshly-renewed token directly. Round-tripping
                // through getSession() can return a cached, already-expired
                // token → false "session expired" cleared only by reload.
                if (accessToken) {
                    setSession(sessionFromToken(accessToken, config.rpId ?? config.appName));
                    setExpired(false);
                }
            };
        }
        return frameRef.current;
    }, [config]);

    // Cross-site SSO check on mount.
    useEffect(() => {
        const frame = getFrame();
        frame
            .getSession()
            .then((s) => {
                if (s) {
                    if (!isJwt(s.token)) {
                        // Stale opaque session token. Clear it; next interaction
                        // will trigger a fresh OIDC sign-in.
                        frame.clearSession().catch(() => undefined);
                    } else {
                        setSession(
                            sessionFromToken(s.token, s.rpId, s.authenticatedAt)
                        );
                    }
                }
                setLoading(false);
            })
            .catch(() => setLoading(false));
    }, [getFrame]);

    const acceptResultToken = useCallback(
        (token: string) => {
            setSession(sessionFromToken(token, config.rpId ?? config.appName));
            setExpired(false);
            // Bootstrap (or refresh) the silent-renewal iframe via the
            // persistent frame; it reads the session out of the auth
            // origin's localStorage.
            getFrame().getSession();
        },
        [config, getFrame]
    );

    const signIn = useCallback(
        async (opts?: { sessionRelayHost?: string; extraAppHosts?: string[] }) => {
            // For the sealed-transport flow we need a one-shot frame whose
            // `sessionRelay.appHost` was set at construction time so the QR
            // includes the SDK pubkey. The persistent frame (used for SSO
            // check + silent renewal) doesn't need it.
            if (opts?.sessionRelayHost) {
                const oneShot = new AuthFrame({
                    ...config,
                    methods: DRIVE_METHODS,
                    sessionRelay: {
                        appHost: opts.sessionRelayHost,
                        ...(opts.extraAppHosts?.length ? { extraAppHosts: opts.extraAppHosts } : {})
                    }
                });
                const result = await oneShot.signIn();
                acceptResultToken(result.accessToken ?? result.sessionToken);
                if (result.sessionRelay) {
                    try {
                        const s = await oneShot.session();
                        setSealedSession(s);
                        setStaleReason(null);
                    } catch (err) {
                        console.warn('[chat-auth] sealed session install failed:', err);
                    }
                }
                return;
            }
            const frame = getFrame();
            const result = await frame.signIn();
            acceptResultToken(result.accessToken ?? result.sessionToken);
        },
        [config, getFrame, acceptResultToken]
    );

    const signInInto = useCallback(
        async (container: HTMLElement, opts?: { sessionRelayHost?: string; extraAppHosts?: string[]; requestedAttributes?: readonly string[] }) => {
            // One-shot inline frame. We don't reuse `frameRef` because
            // `container` is a constructor-only option in @privasys/auth
            // and the persistent frame must keep its renewal iframe
            // attached to <body>.
            // Share-link redeem is a MINIMAL identity flow: prove a wallet sub
            // to open a sealed session, nothing more. The account sign-in
            // (connectInto) still asks for name+email for display, but a visitor
            // opening a shared file should not be prompted for PII. The frame
            // derives the wallet prompt from `scope` bundles plus `attributes`
            // named one by one, so the base config's email+profile scope must
            // be overridden here — a restricted link that genuinely needs
            // attributes names exactly those (and only then).
            const inlineConfig = {
                ...config,
                container,
                methods: DRIVE_METHODS,
                scope: ['openid', 'offline_access'] as const,
                attributes: opts?.requestedAttributes ?? [],
                ...(opts?.sessionRelayHost
                    ? {
                        sessionRelay: {
                            appHost: opts.sessionRelayHost,
                            ...(opts.extraAppHosts?.length ? { extraAppHosts: opts.extraAppHosts } : {})
                        }
                    }
                    : {})
            };
            const inline = new AuthFrame(inlineConfig);
            inlineFrameRef.current = inline;
            try {
                const result = await inline.signIn();
                acceptResultToken(result.accessToken ?? result.sessionToken);
                if (opts?.sessionRelayHost && result.sessionRelay) {
                    try {
                        const s = await inline.session();
                        setSealedSession(s);
                        setStaleReason(null);
                    } catch (err) {
                        console.warn('[drive-auth] sealed session install failed:', err);
                    }
                }
            } finally {
                if (inlineFrameRef.current === inline) inlineFrameRef.current = null;
            }
        },
        [config, acceptResultToken]
    );

    // One-call gate: SDK connect() in page presentation. The SDK owns the
    // whole surface (pitch panel + ceremony/approval states); we only adopt
    // the resulting sealed session into the per-host cache.
    const connectInto = useCallback(
        async (
            container: HTMLElement,
            opts: {
                appHost: string;
                pitch?: { title?: string; description?: string; bullets?: string[]; logoUrl?: string };
                app?: { logoUrl?: string; displayName?: string };
                methods?: readonly ('wallet' | 'passkey' | 'social')[];
            }
        ): Promise<SealedSession | null> => {
            const frame = new AuthFrame({
                ...config,
                container,
                presentation: 'page',
                ...(opts.pitch ? { pitch: opts.pitch } : {}),
                ...(opts.app ? { app: opts.app } : {}),
                methods: opts.methods ?? DRIVE_METHODS,
                sessionRelay: { appHost: opts.appHost }
            });
            inlineFrameRef.current = frame;
            try {
                const res = await frame.connect();
                acceptResultToken(res.accessToken);
                if (res.session) {
                    // Adopt as the canonical per-host sealed session,
                    // replacing any stale pre-redeploy entry.
                    sealedByHost.current.get(opts.appHost)?.frame.destroy();
                    sealedByHost.current.set(opts.appHost, { frame, session: res.session });
                    sealedByHostInFlight.current.delete(opts.appHost);
                    setStaleReason(null);
                }
                return res.session;
            } finally {
                if (inlineFrameRef.current === frame) inlineFrameRef.current = null;
            }
        },
        [config, acceptResultToken]
    );

    // Abort the in-flight inline/connect ceremony (if any). AuthFrame.cancel()
    // is a no-op once the ceremony has resolved, so this can never tear down
    // a live sealed session.
    const cancelSignIn = useCallback(() => {
        inlineFrameRef.current?.cancel();
    }, []);

    const resumeSealed = useCallback(
        async (appHost: string) => {
            if (sealedSession) return;
            if (sealedResumeInFlight.current) return sealedResumeInFlight.current;
            const run = (async () => {
                let frame = sealedFrameRef.current;
                if (!frame || sealedHostRef.current !== appHost) {
                    sealedFrameRef.current?.destroy();
                    frame = new AuthFrame({
                        ...config,
                        sessionRelay: { appHost }
                    });
                    sealedFrameRef.current = frame;
                    sealedHostRef.current = appHost;
                }
                try {
                    const s = await frame.resumeSession();
                    setSealedSession(s);
                    setStaleReason(null);
                } catch (err) {
                    // no-voucher    → user never completed a sealed sign-in here
                    // rejected      → enclave identity/measurement changed; a
                    //                 wallet ceremony is required
                    // unavailable   → transient transport failure
                    // All three leave sealedSession null; the sign-in flow
                    // (or a later retry) re-creates the sealed transport.
                    console.log('[chat-auth] sealed resume unavailable:', (err as Error).message);
                }
            })();
            sealedResumeInFlight.current = run;
            try {
                await run;
            } finally {
                sealedResumeInFlight.current = null;
            }
        },
        [config, sealedSession]
    );

    // Recovery path: tear down the (possibly dead) primary sealed frame and
    // rebuild it from the EncAuth voucher. Used by the chat shell after the
    // enclave was redeployed (stale session → unsealed 401) or came back from
    // an outage (VM stopped → 502). Returns the outcome so the shell can show
    // "reconnecting" vs. a hard "the back-end changed, sign in again" prompt.
    const reestablishSealed = useCallback(
        async (appHost: string): Promise<SealedResumeOutcome> => {
            setSealedSession(null);
            sealedFrameRef.current?.destroy();
            sealedResumeInFlight.current = null;
            const frame = new AuthFrame({ ...config, sessionRelay: { appHost } });
            sealedFrameRef.current = frame;
            sealedHostRef.current = appHost;
            try {
                // Bound the rebind: the voucher ceremony runs in the privasys.id
                // iframe and can hang (enclave rebind endpoint stalls, iframe
                // never posts back). Without a timeout a hang parks the shell's
                // recovery loop on `await` forever, so the "Connecting…" spinner
                // never advances to the actionable Reconnect (`stale`) prompt.
                // A timeout surfaces as `unavailable`, which the recovery loop
                // retries a few times and then escalates to `stale`.
                const s = await withTimeout(frame.resumeSession(), 15_000, 'sealed-resume-timeout');
                setSealedSession(s);
                setStaleReason(null);
                return 'ok';
            } catch (err) {
                const msg = (err as Error).message ?? '';

                // A `no-voucher` or `rejected:<reason>` resume is recoverable
                // WITHOUT a sign-out: the enclave has no usable voucher (none
                // yet, or it refused the current one because the PLATFORM was
                // upgraded — `enc-changed`, the session-relay enc_pub is pinned
                // to the platform measurement — or the app changed,
                // `workload-changed`). A voucher-only push re-attests through
                // the wallet: the user reviews what changed and, on one
                // approval, a fresh voucher is minted against the CURRENT
                // enc_pub. This turns a platform roll from a dead-end into a
                // one-tap re-approval — never a wallet forget/re-add. A hung
                // silent resume (timeout) is NOT recoverable this way.
                const recoverable =
                    !msg.includes('sealed-resume-timeout') &&
                    (msg.includes('no-voucher') || msg.includes('rejected'));
                if (recoverable) {
                    try {
                        console.warn(`[drive-auth] sealed ${appHost} ${msg} — requesting wallet re-approval`);
                        setSealedApprovalPending(true);
                        // requestAppVoucher resolves only once a NEW voucher
                        // lands (human-scale deadline inside the SDK), so it is
                        // NOT wrapped in the short silent-resume timeout.
                        await frame.getSession();
                        await frame.requestAppVoucher(appHost);
                        const s = await withTimeout(frame.resumeSession(), 15_000, 'sealed-resume-timeout');
                        setSealedSession(s);
                        setStaleReason(null);
                        return 'ok';
                    } catch (e2) {
                        console.warn(`[drive-auth] wallet re-approval for ${appHost} did not complete:`, (e2 as Error).message);
                    } finally {
                        setSealedApprovalPending(false);
                    }
                }

                try { frame.destroy(); } catch { /* frame already torn down */ }
                // Recovery exhausted — keep the enclave's reason so the stale
                // banner says WHAT changed instead of a generic prompt.
                if (msg.includes('rejected')) {
                    console.warn(`[drive-auth] sealed session for ${appHost} rejected:`, msg);
                    setStaleReason(parseStaleReason(msg));
                    return 'rejected';
                }
                if (msg.includes('no-voucher')) {
                    console.warn(`[drive-auth] no voucher for ${appHost} — interactive sign-in needed`);
                    return 'no-voucher';
                }
                console.log('[drive-auth] sealed reestablish failed:', msg);
                return 'unavailable';
            }
        },
        [config]
    );

    // getSealedSession returns (and caches) a sealed session for an arbitrary
    // enclave appHost, independent of the primary instance session. Used to
    // reach the chat-service back-end (a separate enclave) without the bearer
    // or tool data ever crossing the gateway's terminate path.
    const getSealedSession = useCallback(
        async (appHost: string): Promise<SealedSession | null> => {
            if (!session) return null;
            const cached = sealedByHost.current.get(appHost);
            if (cached) return cached.session;
            const inflight = sealedByHostInFlight.current.get(appHost);
            if (inflight) return inflight;
            const run = (async (): Promise<SealedSession | null> => {
                const frame = new AuthFrame({ ...config, sessionRelay: { appHost } });
                try {
                    const s = await frame.resumeSession();
                    sealedByHost.current.set(appHost, { frame, session: s });
                    return s;
                } catch (err) {
                    frame.destroy();
                    // no-voucher / rejected / unavailable — caller degrades.
                    console.log(`[chat-auth] sealed session for ${appHost} unavailable:`, (err as Error).message);
                    return null;
                }
            })();
            sealedByHostInFlight.current.set(appHost, run);
            try {
                return await run;
            } finally {
                sealedByHostInFlight.current.delete(appHost);
            }
        },
        [config, session]
    );

    const signOut = useCallback(async () => {
        const frame = getFrame();
        await frame.clearSession();
        setSession(null);
        setSealedSession(null);
        sealedFrameRef.current?.destroy();
        sealedFrameRef.current = null;
        sealedHostRef.current = null;
        for (const { frame: f } of sealedByHost.current.values()) f.destroy();
        sealedByHost.current.clear();
    }, [getFrame]);

    const getTokenForAudience = useCallback(
        async (audience: string) => {
            const frame = getFrame();
            // The persistent renewal iframe must be live for the
            // postMessage relay; cross-site SSO bootstraps it on mount,
            // but call getSession() defensively to ensure it's mounted
            // (no-op if a session iframe is already attached).
            await frame.getSession();
            return frame.getTokenForAudience(audience);
        },
        [getFrame]
    );

    // Ask the wallet (via push) to voucher an additional enclave host for
    // the live session — incremental multi-app attestation. On success the
    // per-host sealed session can then resume silently; we drop any cached
    // null so getSealedSession re-resumes on the next call.
    const requestAppVoucher = useCallback(
        async (appHost: string) => {
            const frame = getFrame();
            await frame.getSession(); // ensure the persistent iframe is mounted
            await frame.requestAppVoucher(appHost);
            sealedByHost.current.get(appHost)?.frame.destroy();
            sealedByHost.current.delete(appHost);
            sealedByHostInFlight.current.delete(appHost);
        },
        [getFrame]
    );

    // Expose a minimal helper on `window.PrivasysAuth` so the copy-paste
    // quote-verification snippet (and other dev-console flows) can mint
    // an audience-scoped token without having to wire the React context
    // out by hand. Only the audience-token method is exposed - sign-in /
    // sign-out flows stay routed through the React context.
    useEffect(() => {
        if (typeof window === 'undefined') return;
        const w = window as unknown as {
            PrivasysAuth?: { getTokenForAudience: (_audience: string) => Promise<string> };
        };
        w.PrivasysAuth = { getTokenForAudience };
        return () => {
            if (w.PrivasysAuth?.getTokenForAudience === getTokenForAudience) {
                delete w.PrivasysAuth;
            }
        };
    }, [getTokenForAudience]);

    return (
        <AuthContext.Provider
            value={{ session, loading, expired, sealedSession, getTokenForAudience, signIn, signInInto, connectInto, cancelSignIn, resumeSealed, reestablishSealed, staleReason, sealedApprovalPending, getSealedSession, requestAppVoucher, signOut }}
        >
            {children}
        </AuthContext.Provider>
    );
}
