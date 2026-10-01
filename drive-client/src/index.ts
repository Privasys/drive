// @privasys/drive-client
//
// Shared client plumbing for the Privasys Drive enclave: the sealed-transport
// core (timeouts, error shape, JSON helper), file-upload helpers (small +
// chunked), and the drag-and-drop file affordance. Consumed by both
// drive.privasys.org and chat.privasys.org so the transport conventions and
// the drop UX never drift between them.

export {
    DriveError,
    decodeError,
    driveHostFromEnv,
    ok,
    timed,
    json,
    textOf,
    bytesToBase64,
    REQUEST_TIMEOUT_MS,
    TRANSFER_TIMEOUT_MS
} from './transport';

export { uploadFile, uploadFileStreaming, STREAM_THRESHOLD } from './upload';

export { useFileDrop, FileDropZone } from './use-file-drop';
export type { FileDropHandlers } from './use-file-drop';
