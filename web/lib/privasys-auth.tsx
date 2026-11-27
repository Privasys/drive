'use client';

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { AuthFrame, type AppChannel, type AuthFrameConfig, type Session } from '@privasys/auth';

// The page's sign-in with Privasys ID: one AuthFrame, the session it holds,
// and the channels it opens to enclave apps.

/** What one sign-in asks beyond the configuration: a share link's step-up
 *  attributes, and the billing grant that pays for them. */
export interface SignInOptions {
    attributes?: readonly string[];
    billingGrant?: string;
}

interface AuthContextValue {
    /** The person's session, or null when signed out. */
    session: Session | null;
    /** True until the frame has reported the stored session. */
    loading: boolean;
    /** Restore the session silently, or run the gate inside `container`.
     *  Rejects with the SDK's ConnectError (`code: 'cancelled' | 'timeout' | 'failed'`). */
    connect: (container: HTMLElement, opts?: SignInOptions) => Promise<Session>;
    /** Abort the gate in progress, if any. */
    cancel: () => void;
    /** The channel to the enclave app at `host`: sealed for a wallet session,
     *  direct with a token for `audience` otherwise. */
    app: (host: string, opts?: { audience?: string; onApproval?: (reason: string | null) => void }) => Promise<AppChannel>;
    /** The session's token, or one minted for `audience`. */
    token: (audience?: string) => Promise<string>;
    signOut: () => Promise<void>;
}

const outside = async (): Promise<never> => {
    throw new Error('Privasys auth used outside PrivasysAuthProvider');
};

const AuthContext = createContext<AuthContextValue>({
    session: null,
    loading: true,
    connect: outside,
    cancel: () => {},
    app: outside,
    token: outside,
    signOut: async () => {}
});

export function useAuth(): AuthContextValue {
    return useContext(AuthContext);
}

export function PrivasysAuthProvider({ children, config }: { children: ReactNode; config: AuthFrameConfig }) {
    const [session, setSession] = useState<Session | null>(null);
    const [loading, setLoading] = useState(true);
    const frameRef = useRef<AuthFrame | null>(null);

    // The frame lives for the page; built on first use, removed on unmount.
    const frame = useCallback((): AuthFrame => {
        if (!frameRef.current) {
            const f = new AuthFrame(config);
            f.onSessionChange((s) => {
                if (frameRef.current !== f) return;
                setSession(s);
                setLoading(false);
            });
            frameRef.current = f;
        }
        return frameRef.current;
    }, [config]);

    useEffect(() => {
        frame();
        return () => {
            frameRef.current?.destroy();
            frameRef.current = null;
        };
    }, [frame]);

    const connect = useCallback(
        (container: HTMLElement, opts?: SignInOptions) => frame().connect({ container, ...opts }),
        [frame]
    );
    const cancel = useCallback(() => frameRef.current?.cancel(), []);
    const app = useCallback(
        (host: string, opts?: { audience?: string; onApproval?: (reason: string | null) => void }) => frame().app(host, opts),
        [frame]
    );
    const token = useCallback((audience?: string) => frame().token(audience), [frame]);
    const signOut = useCallback(() => frame().signOut(), [frame]);

    return (
        <AuthContext.Provider value={{ session, loading, connect, cancel, app, token, signOut }}>
            {children}
        </AuthContext.Provider>
    );
}
