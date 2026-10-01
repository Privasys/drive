// File upload helpers for the Privasys Drive enclave (sealed).
//
// Small files upload in one sealed request; larger ones go through the
// chunked upload session (sequential sealed parts, finalized server-side
// through the same seal path). Shared by both fronts so the chunking
// thresholds and progress contract stay identical.

import type { SealedSession } from '@privasys/auth';
import { DriveError, decodeError, json, ok, textOf, timed, TRANSFER_TIMEOUT_MS } from './transport';

// Files above this go through the chunked upload session; below it, one
// sealed request. Parts stay well under the transport's comfort zone. This
// mirrors the server's 8 MiB single-request tool cap.
export const STREAM_THRESHOLD = 8 * 1024 * 1024;
const PART_SIZE = 4 * 1024 * 1024;

/** How an upload should behave when the destination name is taken. */
export interface UploadOptions {
    /**
     * Rewrite an existing file of the same name in place. The file keeps
     * its node id, so shares, links and its index entry survive. Without
     * this a taken name answers 409 and the caller decides what to do.
     */
    overwrite?: boolean;
    /** Store under this name instead of the file's own (uploading a copy). */
    name?: string;
}

/** Upload a file's bytes (sealed). Small-file path (single request). */
export async function uploadFile<T = { id: string }>(
    session: SealedSession,
    tenantID: string,
    parentID: string | null,
    name: string,
    mime: string,
    bytes: Uint8Array,
    opts: UploadOptions = {}
): Promise<T> {
    const qs = new URLSearchParams({ name: opts.name ?? name });
    if (mime) qs.set('mime', mime);
    if (parentID) qs.set('parent_id', parentID);
    if (opts.overwrite) qs.set('overwrite', 'true');
    const res = await timed(
        session,
        'POST',
        `/v1/tenants/${tenantID}/files?${qs.toString()}`,
        bytes,
        TRANSFER_TIMEOUT_MS
    );
    if (!ok(res)) throw decodeError(res);
    return JSON.parse(textOf(res)) as T;
}

/**
 * Upload of any size with progress: small files in one sealed request,
 * larger ones as a chunked session (sequential sealed parts, finalized
 * through the same seal path server-side). On failure mid-session the
 * staged upload is best-effort cleaned up.
 */
export async function uploadFileStreaming<T = { id: string }>(
    session: SealedSession,
    tenantID: string,
    parentID: string | null,
    file: File,
    onProgress?: (sentBytes: number, totalBytes: number) => void,
    opts: UploadOptions = {}
): Promise<T> {
    const name = opts.name ?? file.name;
    if (file.size <= STREAM_THRESHOLD) {
        onProgress?.(0, file.size);
        const bytes = new Uint8Array(await file.arrayBuffer());
        const node = await uploadFile<T>(session, tenantID, parentID, name, file.type, bytes, opts);
        onProgress?.(file.size, file.size);
        return node;
    }
    const created = await json<{ id: string }>(session, 'POST', `/v1/tenants/${tenantID}/uploads`, {
        parent_id: parentID ?? '',
        name,
        mime: file.type,
        size: file.size,
        overwrite: opts.overwrite === true
    });
    try {
        let sent = 0;
        let index = 0;
        while (sent < file.size) {
            const slice = file.slice(sent, Math.min(sent + PART_SIZE, file.size));
            const bytes = new Uint8Array(await slice.arrayBuffer());
            const res = await timed(
                session,
                'PUT',
                `/v1/tenants/${tenantID}/uploads/${created.id}/chunks/${index}`,
                bytes,
                TRANSFER_TIMEOUT_MS
            );
            if (!ok(res)) throw decodeError(res);
            sent += bytes.byteLength;
            index += 1;
            onProgress?.(sent, file.size);
        }
        return await json<T>(
            session,
            'POST',
            `/v1/tenants/${tenantID}/uploads/${created.id}/finalize`
        );
    } catch (e) {
        // Best-effort cleanup of the staged session.
        void session
            .request('DELETE', `/v1/tenants/${tenantID}/uploads/${created.id}`)
            .catch(() => undefined);
        throw e instanceof Error ? e : new DriveError(0, String(e));
    }
}
