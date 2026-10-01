// Sealed-transport core for the Privasys Drive enclave.
//
// The browser reaches Drive over a DEDICATED SEALED SESSION (PrivasysSession
// from @privasys/auth) — never plain fetch. Bytes and metadata are sealed
// browser->enclave (CBOR-AES-GCM); the gateway only ever sees ciphertext,
// and Drive authenticates the sealed session itself (the enclave relay
// asserts the wallet-vouched sub via X-Privasys-Sub). This module is the
// shared plumbing consumed by both drive.privasys.org and chat.privasys.org
// so the request conventions, timeouts and error shape never drift.

import type { SealedResponse, SealedSession } from '@privasys/auth';

const decoder = new TextDecoder();

/**
 * Resolve the bare host (no scheme) of the Drive enclave backend from an env
 * value, or '' when unset. Both fronts read `NEXT_PUBLIC_DRIVE_APP_HOST` and
 * gate every Drive-backed behaviour on its presence.
 */
export function driveHostFromEnv(raw: string | undefined | null): string {
    if (!raw) return '';
    try {
        return raw.includes('://') ? new URL(raw).host : raw;
    } catch {
        return raw;
    }
}

/** A Drive API error carrying the enclave's HTTP status + message. */
export class DriveError extends Error {
    status: number;
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
        this.name = 'DriveError';
    }
}

export function decodeError(res: SealedResponse): DriveError {
    // A reply without a numeric status is not an HTTP error but a sealed
    // channel hiccup (typically the enclave session still settling right
    // after a fresh ceremony) — name it, and mark it retryable.
    if (typeof res.status !== 'number') {
        return new DriveError(0, 'The sealed channel is not ready yet. Retrying usually fixes this.');
    }
    const text = res.body && res.body.byteLength ? decoder.decode(res.body) : '';
    let msg = `HTTP ${res.status}`;
    try {
        const j = text ? (JSON.parse(text) as { error?: string; code?: string }) : null;
        if (j?.error) msg = j.error;
    } catch {
        if (text) msg = text;
    }
    return new DriveError(res.status, msg);
}

export function ok(res: SealedResponse): boolean {
    return typeof res.status === 'number' && res.status >= 200 && res.status < 300;
}

// A sealed request to an unreachable enclave can otherwise hang forever
// (the iframe RPC has no deadline of its own), leaving the UI silently
// stuck. Cap every call so the failure surfaces and can be retried.
export const REQUEST_TIMEOUT_MS = 30_000;
export const TRANSFER_TIMEOUT_MS = 180_000; // uploads/downloads of larger files

/**
 * A sealed session request with a hard deadline. `init` carries request
 * headers where the API needs them: the conditional-write fence is an
 * If-Match header, so a caller that must not clobber a concurrent writer
 * has to be able to set one.
 */
export function timed(
    session: SealedSession,
    method: string,
    path: string,
    body: unknown,
    ms: number = REQUEST_TIMEOUT_MS,
    init?: RequestInit
): Promise<SealedResponse> {
    return new Promise<SealedResponse>((resolve, reject) => {
        const t = setTimeout(
            () =>
                reject(
                    new DriveError(
                        0,
                        'The Drive enclave is not responding. It may be restarting or unreachable.'
                    )
                ),
            ms
        );
        session.request(method, path, body, init).then(
            (r) => {
                clearTimeout(t);
                resolve(r);
            },
            (e: unknown) => {
                clearTimeout(t);
                reject(e instanceof Error ? e : new Error(String(e)));
            }
        );
    });
}

/** JSON request over the sealed session; throws DriveError on non-2xx. */
export async function json<T>(
    session: SealedSession,
    method: string,
    path: string,
    body?: unknown,
    ms: number = REQUEST_TIMEOUT_MS,
    init?: RequestInit
): Promise<T> {
    const res = await timed(session, method, path, body, ms, init);
    if (!ok(res)) throw decodeError(res);
    const text = res.body && res.body.byteLength ? decoder.decode(res.body) : '';
    return (text ? JSON.parse(text) : {}) as T;
}

/** Decode a sealed response body as UTF-8 text (empty string when absent). */
export function textOf(res: SealedResponse): string {
    return res.body && res.body.byteLength ? decoder.decode(res.body) : '';
}

/** Base64-encode raw bytes (browser-safe, chunked to avoid arg limits). */
export function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}
