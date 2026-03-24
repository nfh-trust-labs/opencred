/**
 * Local configuration store backed by electron-store.
 *
 * Persists user preferences such as the last-used key ID, window state,
 * and application settings. Data is stored as an encrypted JSON file in
 * the platform-appropriate user data directory.
 *
 * SECURITY NOTE: Never store private keys, signing buffers, or credential
 * payloads in this store. Only metadata and user preferences are persisted.
 */

import ElectronStore from "electron-store";
import * as fs from "node:fs";

/** A record of a previously issued credential (stored locally). */
export interface CredentialHistoryEntry {
  /** Unique ID for this history entry. */
  id: string;
  /** Schema ID used (e.g. "education") or "custom:<uuid>". */
  schemaId: string;
  /** Human-readable schema name for display. */
  schemaName: string;
  /** One-line summary of the credential subject (e.g. "John Doe — BSc"). */
  subjectSummary: string;
  /** ISO 8601 timestamp when the credential was issued. */
  issuedAt: string;
  /** The full signed credential JSON (serialized). */
  credentialJson: string;
  /** Fingerprint of the key used to sign. */
  keyFingerprint: string;
  /** Proof format used (backward-compatible — absent means "vc-jwt"). */
  proofFormat?: string;
}

/** A user-defined custom schema saved for reuse. */
export interface CustomSchemaEntry {
  /** ID in the form "custom:<uuid>". */
  id: string;
  /** User-chosen name for this schema. */
  name: string;
  /** The JSON Schema definition. */
  schema: Record<string, unknown>;
  /** ISO 8601 timestamp when this schema was created. */
  createdAt: string;
}

/** Maximum number of credential history entries to retain (FIFO). */
export const CREDENTIAL_HISTORY_CAP = 100;

export interface StoreSchema {
  /** ID of the last-used signing key (for convenience, not the key itself). */
  lastKeyId: string | undefined;
  /** User-preferred theme. */
  theme: "light" | "dark" | "system";
  /** Whether to start in offline-first mode. */
  offlineMode: boolean;
  /** URL for the bug report Google Form (configurable). */
  bugReportFormUrl: string;
  /**
   * Whether to persist imported key file paths in the config store.
   * When true (default), key file paths are saved so they can be auto-reloaded
   * on restart. When false, key paths are not persisted and must be re-imported
   * each session.
   */
  persistKeyPaths: boolean;
  /** Custom user preferences — intentionally loosely typed for extensibility. */
  preferences: Record<string, unknown>;
  /** Recently issued credentials (capped at CREDENTIAL_HISTORY_CAP). */
  credentialHistory: CredentialHistoryEntry[];
  /** User-created custom schemas for blank credentials. */
  customSchemas: CustomSchemaEntry[];
}

const DEFAULTS: StoreSchema = {
  lastKeyId: undefined,
  theme: "system",
  offlineMode: false,
  bugReportFormUrl: "https://forms.gle/f1wFUhzN1VwgR5QD6",
  persistKeyPaths: true,
  preferences: {},
  credentialHistory: [],
  customSchemas: [],
};

let store: ElectronStore<StoreSchema> | null = null;

/**
 * Initialise the store. Call once during app startup.
 */
export function initStore(): ElectronStore<StoreSchema> {
  if (!store) {
    store = new ElectronStore<StoreSchema>({
      name: "opencred-config",
      defaults: DEFAULTS,
    });
  }
  return store;
}

/**
 * Get the singleton store instance.
 * @throws if called before {@link initStore}.
 */
export function getStore(): ElectronStore<StoreSchema> {
  if (!store) {
    throw new Error("Store has not been initialised. Call initStore() first.");
  }
  return store;
}

/**
 * Restrict the electron-store config file to owner-only permissions (0600).
 *
 * On Unix-like systems (macOS, Linux) this sets read/write for the owner only.
 * On Windows, Node.js fs.chmod is a no-op for permission bits; Windows ACLs
 * must be configured separately (noted as a platform limitation).
 */
export function restrictStoreFilePermissions(): void {
  if (!store) {
    return;
  }

  try {
    const storePath = store.path;
    // 0o600 = owner read + write only (no group, no other)
    fs.chmodSync(storePath, 0o600);
  } catch {
    // Best-effort: on Windows or if the file does not yet exist, chmod may
    // fail silently. This is acceptable — the mitigation is documented.
  }
}
