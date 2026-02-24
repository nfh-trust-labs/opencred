/**
 * IPC channel names for main <-> renderer communication.
 *
 * All IPC channels are defined here as typed constants so that both the main
 * process (ipc-handlers.ts) and the renderer preload (preload.ts) reference
 * the same channel strings. This prevents typo-related silent failures and
 * enables compile-time checking.
 */

export const IPC_CHANNELS = {
  // --- Key management ---
  /** Import a key file from disk. Payload: file path. Response: key metadata (id, fingerprint). */
  KEY_IMPORT: "key:import",
  /** List imported key identifiers. Response: array of key metadata. */
  KEY_LIST: "key:list",

  // --- Signing ---
  /** Request the main process to sign a credential. Payload: unsigned VC + key ID. Response: signed VC. */
  SIGN_CREDENTIAL: "credential:sign",

  // --- Verification ---
  /** Verify a signed credential. Payload: VC JSON string. Response: verification result. */
  VERIFY_CREDENTIAL: "credential:verify",

  // --- File operations ---
  /** Open a native file-open dialog. Payload: dialog options. Response: file contents or null. */
  FILE_OPEN: "file:open",
  /** Open a native file-save dialog and write contents. Payload: { defaultName, content }. Response: saved path or null. */
  FILE_SAVE: "file:save",

  // --- Offline status ---
  /** Query the current online/offline status. Response: boolean. */
  GET_OFFLINE_STATUS: "status:offline",

  // --- Config (electron-store) ---
  /** Read a config value. Payload: key string. Response: value or undefined. */
  GET_CONFIG: "config:get",
  /** Write a config value. Payload: { key, value }. Response: void. */
  SET_CONFIG: "config:set",
} as const;

/** Union type of all IPC channel name values. */
export type IpcChannel = (typeof IPC_CHANNELS)[keyof typeof IPC_CHANNELS];
