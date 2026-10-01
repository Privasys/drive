// Where this UI's backend lives, read at runtime rather than baked at build.
//
// The UI ships inside the Drive image, and one image runs on every platform
// (dev and production alike), so nothing per-environment may be compiled in.
// The Drive service writes /privasys-config.js on each request, from its own
// identity and the platform host the gateway names it by; the root layout
// loads that script before any of the app's code runs.
//
// Under `next dev` there is no Drive serving the page, so the NEXT_PUBLIC_*
// variables fill in, and failing those the production platform.

export interface DriveRuntimeConfig {
    /** Control plane base URL: attestation reports, attribute prices, /me. */
    apiBase: string;
    /** The Drive app's id on that control plane. */
    appId: string;
    /** The Drive enclave's platform hostname, which the sealed session is
     * attested against. An alias domain in the address bar never changes it. */
    appHost: string;
}

declare global {
    interface Window {
        __DRIVE_CFG__?: Partial<DriveRuntimeConfig>;
    }
}

const FALLBACK: DriveRuntimeConfig = {
    apiBase: process.env.NEXT_PUBLIC_API_BASE_URL ?? 'https://api.developer.privasys.org',
    appId: process.env.NEXT_PUBLIC_DRIVE_APP_ID ?? '',
    appHost: process.env.NEXT_PUBLIC_DRIVE_APP_HOST ?? ''
};

function read(): DriveRuntimeConfig {
    const injected = typeof window === 'undefined' ? undefined : window.__DRIVE_CFG__;
    return {
        apiBase: injected?.apiBase || FALLBACK.apiBase,
        appId: injected?.appId || FALLBACK.appId,
        appHost: injected?.appHost || FALLBACK.appHost
    };
}

/** This page's backend, fixed for the life of the page. */
export const RUNTIME: DriveRuntimeConfig = read();
