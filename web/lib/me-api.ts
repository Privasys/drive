// Minimal /api/v1/me client for drive.privasys.org.
//
// The OIDC access_token issued by privasys.id only carries the `sub`
// claim; profile attributes (email, name) live behind the
// management-service `/api/v1/me` endpoint, which the IdP populates
// after the wallet shares them. The full UserInfo type lives in
// `developer.privasys.org/lib/api.ts`; the chat front only needs the
// display fields.

import { RUNTIME } from './runtime-config';

export const API_BASE_URL = RUNTIME.apiBase;

export interface UserProfile {
    sub: string;
    email?: string;
    name?: string;
    display_name?: string;
    display_email?: string;
}

export async function fetchUserProfile(
    token: string,
    signal?: AbortSignal
): Promise<UserProfile> {
    const res = await fetch(`${API_BASE_URL}/api/v1/me`, {
        signal,
        headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${token}`
        }
    });
    if (!res.ok) {
        throw new Error(`/me failed: ${res.status} ${res.statusText}`);
    }
    return res.json() as Promise<UserProfile>;
}
