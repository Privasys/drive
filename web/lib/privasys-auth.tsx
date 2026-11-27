'use client';

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { AuthFrame, type AppChannel, type AuthFrameConfig, type Session } from '@privasys/auth';

// The page's sign-in with Privasys ID: one AuthFrame, the session it holds,
// and the channels it opens to enclave apps.

/**
 * What one sign-in may ask differently from the provider's configuration. A
 * share link signs its visitor in with the link's client, billing grant,
 * attributes and methods, inline in the link page.
 */
export type SignInOptions = Partial<
    Pick<AuthFrameConfig, 'clientId' | 'scope' | 'attributes' | 'methods' | 'billingGrant' | 'presentation'>
>;

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
     *  direct with a token for `audience` otherwise. Changes identity when the
     *  frame is replaced, so a caller holding a channel opens it again. */
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

interface Current {
    frame: AuthFrame;
    /** The SignInOptions the frame was built with, serialised. */
    key: string;
    off: () => void;
}

export function PrivasysAuthProvider({ children, config }: { children: ReactNode; config: AuthFrameConfig }) {
    const [session, setSession] = useState<Session | null>(null);
    const [loading, setLoading] = useState(true);
    // Bumped when the frame is replaced: the callbacks below change identity,
    // which tells a consumer its channels belong to the old frame.
    const [generation, setGeneration] = useState(0);
    const current = useRef<Current | null>(null);

    const drop = useCallback(() => {
        current.current?.off();
        current.current?.frame.destroy();
        current.current = null;
    }, []);

    // frameFor returns the page's one AuthFrame, built for `opts`. The SDK
    // takes the client, attributes and grant at construction only, so a
    // sign-in that asks for others replaces the frame; the session it reports
    // is then the one stored for that configuration.
    const frameFor = useCallback(
        (opts?: SignInOptions): AuthFrame => {
            const key = JSON.stringify(opts ?? {});
            if (current.current?.key === key) return current.current.frame;
            const replacing = current.current !== null;
            drop();
            const frame = new AuthFrame({ ...config, ...opts });
            const off = frame.onSessionChange((s) => {
                if (current.current?.frame !== frame) return;
                setSession(s);
                setLoading(false);
            });
            current.current = { frame, key, off };
            if (replacing) setGeneration((g) => g + 1);
            return frame;
        },
        [config, drop]
    );

    useEffect(() => {
        frameFor();
        return drop;
    }, [frameFor, drop]);

    // Every call but connect() acts on the frame as it is: a share link's
    // frame stays the page's frame until another sign-in replaces it.
    const live = useCallback(() => current.current?.frame ?? frameFor(), [frameFor]);

    const connect = useCallback(
        (container: HTMLElement, opts?: SignInOptions) => frameFor(opts).connect({ container }),
        [frameFor]
    );

    const cancel = useCallback(() => current.current?.frame.cancel(), []);

    const app = useCallback(
        (host: string, opts?: { audience?: string; onApproval?: (reason: string | null) => void }) => live().app(host, opts),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [live, generation]
    );

    const token = useCallback((audience?: string) => live().token(audience), [live]);

    const signOut = useCallback(() => live().signOut(), [live]);

    return (
        <AuthContext.Provider value={{ session, loading, connect, cancel, app, token, signOut }}>
            {children}
        </AuthContext.Provider>
    );
}
