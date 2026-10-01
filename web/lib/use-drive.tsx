'use client';

// DriveProvider - owns the sealed session to the Drive enclave and the
// caller's personal drive (tenant). Wraps the wallet auth context.
//
// Flow: the user signs in with `sessionRelayHost = driveHost()`, so the
// wallet attests the Drive enclave's quote and binds the session to a
// sealed CBOR-AES-GCM transport in the same ceremony. We then resume that
// sealed session with getSealedSession(driveHost()) (silent across
// reloads; a voucher request covers the cold case), and bootstrap the
// personal tenant.

import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useRef,
    useState,
    type ReactNode
} from 'react';
import type { SealedSession } from '@privasys/auth';
import { useAuth } from './privasys-auth';
import {
    createWorkspace,
    driveHost,
    ensurePersonalTenant,
    getMe,
    type Me,
    type Tenant
} from './drive-api';
import { fetchUserProfile, type UserProfile } from './me-api';

/** Best display name for the signed-in user, falling back gracefully. */
export function displayName(profile: UserProfile | null, me: Me | null): string {
    return (
        profile?.display_name ||
        profile?.name ||
        profile?.display_email ||
        profile?.email ||
        me?.email ||
        me?.sub ||
        ''
    );
}

export type DriveStatus =
    | 'signed-out'
    | 'connecting'
    | 'ready'
    | 'error'
    | 'misconfigured';

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

interface DriveContextValue {
    status: DriveStatus;
    error: string | null;
    session: SealedSession | null;
    me: Me | null;
    profile: UserProfile | null;
    name: string; // best display name for the signed-in user
    tenant: Tenant | null; // the ACTIVE tenant (personal drive or a workspace)
    /** All the caller's tenants (personal + enterprise workspaces). */
    tenants: Tenant[];
    /** Switch the active tenant (workspace switcher). */
    switchTenant: (t: Tenant) => void;
    /** Create an enterprise workspace, refresh memberships, switch to it. */
    newWorkspace: (name: string) => Promise<void>;
    signIn: () => Promise<void>;
    signInInto: (el: HTMLElement, requestedAttributes?: readonly string[]) => Promise<void>;
    /**
     * The one-call gate (SDK connect()): mounts the whole sign-in surface
     * (header + pitch + ceremony/approval states) into `el` and bootstraps
     * the drive on success. Returns the outcome so the gate can render a
     * "closed" panel on user cancel (the SDK's Close button); 'error'
     * (with a message) only when the SDK gave up.
     */
    connectInto: (el: HTMLElement) => Promise<'ready' | 'cancelled' | 'error'>;
    signOut: () => void;
    /**
     * Recover after the enclave restarted or went unreachable: retry the
     * sealed session, force-rebuild it if needed, and re-bootstrap. Lands
     * on 'need-approval' when the enclave's identity changed (fresh
     * wallet ceremony required).
     */
    reconnect: () => Promise<void>;
    /**
     * The holder's own IdP token, for the calls Drive makes on their behalf
     * to other apps (app folders): the sealed session asserts only the sub.
     */
    holderToken: string | undefined;
}

const DriveContext = createContext<DriveContextValue>({
    status: 'signed-out',
    error: null,
    session: null,
    me: null,
    profile: null,
    name: '',
    tenant: null,
    tenants: [],
    switchTenant: () => {},
    newWorkspace: async () => {},
    signIn: async () => {},
    signInInto: async () => {},
    connectInto: async () => 'error' as const,
    signOut: () => {},
    reconnect: async () => {},
    holderToken: undefined
});

export function useDrive(): DriveContextValue {
    return useContext(DriveContext);
}

export function DriveProvider({ children }: { children: ReactNode }) {
    const auth = useAuth();
    const host = driveHost();
    const [status, setStatus] = useState<DriveStatus>('connecting');
    const [error, setError] = useState<string | null>(null);
    const [session, setSession] = useState<SealedSession | null>(null);
    const [me, setMe] = useState<Me | null>(null);
    const [profile, setProfile] = useState<UserProfile | null>(null);
    const [tenant, setTenant] = useState<Tenant | null>(null);
    const bootstrapping = useRef(false);

    const bootstrap = useCallback(
        async (s: SealedSession) => {
            // Right after a fresh wallet ceremony the sealed channel can
            // need a beat before the first request lands (the enclave-side
            // session is still settling); retry briefly instead of
            // surfacing a scary banner on first sign-in.
            let meRes!: Me, tenantRes!: Tenant;
            for (let attempt = 0; ; attempt++) {
                try {
                    [meRes, tenantRes] = await Promise.all([getMe(s), ensurePersonalTenant(s)]);
                    break;
                } catch (e) {
                    if (attempt >= 2) throw e;
                    await new Promise((r) => setTimeout(r, 1200 * (attempt + 1)));
                }
            }
            setMe(meRes);
            // Default the active tenant to the personal drive, keeping a
            // previously selected workspace across reconnects.
            setTenant((cur) => {
                if (cur) {
                    const still = meRes.tenants.find((t) => t.id === cur.id);
                    if (still) return still;
                }
                return tenantRes;
            });
            setSession(s);
            setStatus('ready');
            // Profile (real name) lives behind the management-service /me,
            // not the sealed identity (the relay asserts only the sub).
            const token = auth.session?.accessToken;
            if (token) {
                fetchUserProfile(token)
                    .then(setProfile)
                    .catch(() => {
                        /* name is a nicety; fall back to email/sub */
                    });
            }
        },
        [auth.session?.accessToken]
    );

    // Resolve the sealed Drive session whenever the wallet session changes.
    useEffect(() => {
        if (!host) {
            setStatus('misconfigured');
            setError('NEXT_PUBLIC_DRIVE_APP_HOST is not set.');
            return;
        }
        if (auth.loading) {
            setStatus('connecting');
            return;
        }
        if (!auth.session) {
            setStatus('signed-out');
            setSession(null);
            setMe(null);
            setTenant(null);
            return;
        }
        let cancelled = false;
        setStatus('connecting');
        setError(null);
        void auth
            .getSealedSession(host)
            .then(async (s) => {
                if (cancelled) return;
                if (!s) {
                    // Signed in, but no live sealed session for Drive — the
                    // gate's connect() handles re-approval or a fresh
                    // ceremony from here.
                    setStatus('signed-out');
                    return;
                }
                await bootstrap(s);
            })
            .catch((e: unknown) => {
                if (cancelled) return;
                setStatus('error');
                setError(e instanceof Error ? e.message : 'Could not connect to Drive.');
            });
        return () => {
            cancelled = true;
        };
    }, [auth.session, auth.loading, auth.getSealedSession, host, bootstrap]);

    const signIn = useCallback(async () => {
        setError(null);
        try {
            await auth.signIn({ sessionRelayHost: host });
        } catch (e) {
            if (e instanceof Error && e.message !== 'Authentication cancelled') {
                setError(e.message);
                setStatus('error');
            }
        }
    }, [auth, host]);

    // Inline ceremony: the wallet SDK renders its own sign-in surface
    // (install-the-wallet / connect-with-passkey) into the container.
    const signInInto = useCallback(
        async (el: HTMLElement, requestedAttributes?: readonly string[]) => {
            setError(null);
            try {
                await auth.signInInto(el, { sessionRelayHost: host, requestedAttributes });
            } catch (e) {
                if (e instanceof Error && e.message !== 'Authentication cancelled') {
                    setError(e.message);
                    setStatus('error');
                }
                // Rethrow so the caller can offer a retry: a swallowed
                // ceremony failure leaves its page stuck on a dead frame
                // (the wallet may have gone through an install or import
                // detour that outlived the ceremony session).
                throw e;
            }
        },
        [auth, host]
    );

    // The one-call gate: SDK connect() renders every state (silent restore,
    // one-tap re-approval, full ceremony) inside `el`; we bootstrap the
    // drive when it hands back the sealed session.
    const connectInto = useCallback(async (el: HTMLElement): Promise<'ready' | 'cancelled' | 'error'> => {
        if (bootstrapping.current) return 'error';
        bootstrapping.current = true;
        setError(null);
        try {
            const s = await auth.connectInto(el, {
                appHost: host,
                // Drive's OWN transport constraint (not an SDK default):
                // the Drive API speaks exclusively over the wallet-attested
                // sealed channel today, so non-wallet sign-ins would
                // authenticate and then have no way to reach the enclave.
                // Lift this once a wallet-less (unverified) transport
                // exists. A visitor missing a verified email imports it in
                // the WALLET (link an IdP there).
                methods: ['wallet'],
                pitch: DRIVE_PITCH,
                app: {
                    displayName: 'Privasys Drive',
                    ...(typeof window !== 'undefined'
                        ? { logoUrl: `${window.location.origin}/favicon/privasys-logo.mini.svg` }
                        : {})
                }
            });
            if (!s) throw new Error('Drive connection was not completed.');
            await bootstrap(s);
            return 'ready';
        } catch (e) {
            if ((e as { code?: string }).code === 'cancelled') {
                setStatus('signed-out');
                return 'cancelled';
            }
            setStatus('error');
            setError(e instanceof Error ? e.message : 'Could not connect to Drive.');
            return 'error';
        } finally {
            bootstrapping.current = false;
        }
    }, [auth, host, bootstrap]);

    const switchTenant = useCallback((t: Tenant) => setTenant(t), []);

    const newWorkspace = useCallback(
        async (wsName: string) => {
            if (!session) throw new Error('Not connected.');
            const t = await createWorkspace(session, wsName);
            // Refresh memberships so the switcher lists it with the role.
            const meRes = await getMe(session);
            setMe(meRes);
            setTenant(meRes.tenants.find((x) => x.id === t.id) ?? t);
        },
        [session]
    );

    const reconnect = useCallback(async () => {
        setError(null);
        setStatus('connecting');
        try {
            // The cached per-host session self-heals at request level once
            // the enclave is back; try it first.
            let s = await auth.getSealedSession(host);
            if (s) {
                try {
                    await bootstrap(s);
                    return;
                } catch {
                    /* fall through to a forced rebuild */
                }
            }
            const outcome = await auth.reestablishSealed(host);
            if (outcome === 'rejected') {
                // The enclave's identity/measurement changed: the wallet
                // must verify it again — hand over to the gate (its
                // connect() renders the one-tap approval).
                setStatus('signed-out');
                return;
            }
            s = await auth.getSealedSession(host);
            if (s) {
                await bootstrap(s);
                return;
            }
            setStatus('error');
            setError('Could not reconnect to Drive. Try again in a moment.');
        } catch (e) {
            setStatus('error');
            setError(e instanceof Error ? e.message : 'Could not reconnect to Drive.');
        }
    }, [auth, host, bootstrap]);

    const signOut = useCallback(() => {
        auth.signOut();
        setSession(null);
        setMe(null);
        setProfile(null);
        setTenant(null);
        setStatus('signed-out');
    }, [auth]);

    return (
        <DriveContext.Provider
            value={{
                status,
                error,
                session,
                me,
                profile,
                name: displayName(profile, me),
                tenant,
                tenants: me?.tenants ?? [],
                switchTenant,
                newWorkspace,
                signIn,
                signInInto,
                connectInto,
                signOut,
                reconnect,
                holderToken: auth.session?.accessToken
            }}
        >
            {children}
        </DriveContext.Provider>
    );
}
