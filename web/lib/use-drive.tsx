'use client';

// DriveProvider - owns the channel to the Drive enclave and the caller's
// personal drive (tenant). Wraps the Privasys ID auth context.
//
// A wallet sign-in approves the Drive enclave in the same tap, so its
// channel is sealed and opens silently, across reloads too; a later change
// of the enclave asks the wallet for one more tap. Any other sign-in reaches
// Drive directly with a token for Drive's audience, as a guest who opens
// what was shared with them and owns no drive.

import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useRef,
    useState,
    type ReactNode
} from 'react';
import type { AppChannel } from '@privasys/auth';
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
import { RUNTIME } from './runtime-config';

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

/** Shown when the runtime refuses a direct sign-in; the gate offers a new one. */
export const DIRECT_SIGN_IN_REFUSED = 'Your sign-in is not valid for Drive. Sign in again to continue.';

// The audience of a direct channel's token: this app.
const DRIVE_AUDIENCE = RUNTIME.appId ? `app:${RUNTIME.appId.replace(/-/g, '')}` : undefined;


/** What the wallet is asked to approve again, in words, or null for a first approval. */
export function approvalMessage(reason: string | null): string {
    if (reason === 'workload-changed') return 'Privasys Drive was updated since you last approved it. Approve it in your Privasys Wallet to continue.';
    if (reason === 'enc-changed') return 'The platform Privasys Drive runs on was updated. Approve it in your Privasys Wallet to continue.';
    return 'Approve Privasys Drive in your Privasys Wallet to continue.';
}

// refusalAware names the runtime's refusal of a direct sign-in: it refused the
// sign-in itself, not Drive a request, and retrying sends the same token, so
// only a new sign-in helps.
function refusalAware(ch: AppChannel): AppChannel {
    return {
        get transport() {
            return ch.transport;
        },
        get state() {
            return ch.state;
        },
        onState: (cb) => ch.onState(cb),
        async request(method, path, body, init) {
            const r = await ch.request(method, path, body, init);
            if (r.status === 401 && new TextDecoder().decode(r.body).includes('not valid for this app')) {
                throw new Error(DIRECT_SIGN_IN_REFUSED);
            }
            return r;
        },
        stream: (method, path, body, init) => ch.stream(method, path, body, init),
        openWebSocket: (path) => ch.openWebSocket(path)
    };
}

interface DriveContextValue {
    status: DriveStatus;
    error: string | null;
    /** The channel to Drive, once open. */
    session: AppChannel | null;
    /** Set while the wallet is asked to approve Drive: the message to show. */
    approval: string | null;
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
    /**
     * A share link's sign-in, inline in `el`: the link page's frame asks for
     * the minimal scope, plus the attributes the link needs, paid by its grant,
     * offered only to the wallet when only the wallet can share them.
     * Rejects when it did not complete, so the page can offer a retry.
     */
    signInInto: (
        el: HTMLElement,
        attributes?: readonly string[],
        link?: { billingGrant?: string; methods?: readonly ('wallet' | 'passkey' | 'social')[] }
    ) => Promise<void>;
    /**
     * The gate: restores the session or runs the sign-in inside `el`; the
     * drive opens once signed in. 'cancelled' when the person closed it,
     * 'error' (with `error` set) when it failed.
     */
    connectInto: (el: HTMLElement) => Promise<'ready' | 'cancelled' | 'error'>;
    signOut: () => void;
    /** Open the channel to Drive again and re-bootstrap. */
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
    approval: null,
    me: null,
    profile: null,
    name: '',
    tenant: null,
    tenants: [],
    switchTenant: () => {},
    newWorkspace: async () => {},
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
    const [session, setSession] = useState<AppChannel | null>(null);
    const [approval, setApproval] = useState<string | null>(null);
    const [me, setMe] = useState<Me | null>(null);
    const [profile, setProfile] = useState<UserProfile | null>(null);
    const [tenant, setTenant] = useState<Tenant | null>(null);
    // Bumped to open the channel again: a channel that signed out, or a retry.
    const [attempt, setAttempt] = useState(0);
    const connecting = useRef(false);
    const signedIn = !!auth.session;
    const token = auth.session?.token;
    const tokenRef = useRef(token);
    useEffect(() => {
        tokenRef.current = token;
    }, [token]);

    const bootstrap = useCallback(async (ch: AppChannel) => {
        // Right after a fresh wallet ceremony the sealed channel can need a
        // beat before the first request lands (the enclave-side session is
        // still settling); retry briefly instead of surfacing a scary banner
        // on first sign-in.
        let meRes!: Me, tenantRes!: Tenant | null;
        for (let n = 0; ; n++) {
            try {
                meRes = await getMe(ch);
                // A guest (no wallet) owns no drive: only what was shared
                // with them, and any workspace they were made a member of.
                tenantRes = meRes.guest ? (meRes.tenants[0] ?? null) : await ensurePersonalTenant(ch);
                break;
            } catch (e) {
                if (n >= 2) throw e;
                await new Promise((r) => setTimeout(r, 1200 * (n + 1)));
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
        setSession(ch);
        setStatus('ready');
        // Profile (real name) lives behind the management-service /me, not
        // the sealed identity (the relay asserts only the sub).
        if (tokenRef.current) {
            fetchUserProfile(tokenRef.current)
                .then(setProfile)
                .catch(() => {
                    /* name is a nicety; fall back to email/sub */
                });
        }
    }, []);

    // Open the channel to Drive whenever the person signs in or out, the
    // page's frame is replaced (auth.app changes), or a retry asks for it.
    // A renewal changes none of these.
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
        if (!signedIn) {
            setStatus('signed-out');
            setSession(null);
            setApproval(null);
            setMe(null);
            setTenant(null);
            return;
        }
        let cancelled = false;
        let offState: (() => void) | undefined;
        setStatus('connecting');
        setError(null);
        void auth
            .app(host, {
                audience: DRIVE_AUDIENCE,
                onApproval: (reason) => {
                    if (!cancelled) setApproval(approvalMessage(reason));
                }
            })
            .then(async (ch) => {
                if (cancelled) return;
                setApproval(null);
                // A channel that cannot continue (the session ended, or the
                // enclave needs a new approval) is opened again.
                offState = ch.onState((st) => {
                    if (st === 'signed-out') setAttempt((n) => n + 1);
                });
                await bootstrap(ch.transport === 'direct' ? refusalAware(ch) : ch);
            })
            .catch((e: unknown) => {
                if (cancelled) return;
                setApproval(null);
                setStatus('error');
                setError(e instanceof Error ? e.message : 'Could not connect to Drive.');
            });
        return () => {
            cancelled = true;
            offState?.();
        };
    }, [signedIn, auth.loading, auth.app, host, bootstrap, attempt]);

    // A share link's sign-in: an open link is a minimal identity flow (no
    // PII), and a restricted one asks for exactly what it requires, so its
    // visitor is never prompted for their name or email otherwise (the link
    // page's frame, auth-provider). The link's billing grant pays for this
    // ceremony, so the sharer, not the client's owner, pays for a paid
    // attribute.
    const signInInto = useCallback(
        async (
            el: HTMLElement,
            attributes?: readonly string[],
            link?: { billingGrant?: string; methods?: readonly ('wallet' | 'passkey' | 'social')[] }
        ) => {
            setError(null);
            try {
                await auth.connect(el, {
                    ...(attributes?.length ? { attributes } : {}),
                    ...(link?.billingGrant ? { billingGrant: link.billingGrant } : {}),
                    ...(link?.methods ? { methods: link.methods } : {})
                });
            } catch (e) {
                if ((e as { code?: string }).code !== 'cancelled') {
                    setError(e instanceof Error ? e.message : 'The sign-in did not complete.');
                    setStatus('error');
                }
                // Rethrow so the caller can offer a retry: a swallowed
                // ceremony failure leaves its page stuck on a dead frame
                // (the wallet may have gone through an install or import
                // detour that outlived the ceremony session).
                throw e;
            }
        },
        [auth]
    );

    // The gate: connect() renders every state (silent restore, full
    // ceremony) inside `el`; the effect above opens the drive once signed in.
    const connectInto = useCallback(
        async (el: HTMLElement): Promise<'ready' | 'cancelled' | 'error'> => {
            if (connecting.current) return 'error';
            connecting.current = true;
            setError(null);
            try {
                await auth.connect(el);
                setAttempt((n) => n + 1);
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
                connecting.current = false;
            }
        },
        [auth]
    );

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
        setAttempt((n) => n + 1);
    }, []);

    const signOut = useCallback(() => {
        void auth.signOut();
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
                approval,
                me,
                profile,
                name: displayName(profile, me),
                tenant,
                tenants: me?.tenants ?? [],
                switchTenant,
                newWorkspace,
                signInInto,
                connectInto,
                signOut,
                reconnect,
                holderToken: token
            }}
        >
            {children}
        </DriveContext.Provider>
    );
}
