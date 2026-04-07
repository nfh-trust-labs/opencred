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
  /** Source URL if the schema was imported from a URL. */
  sourceUrl?: string;
  /** DeDi lookup URL for the published schema. */
  dediSchemaUrl?: string;
  /** DeDi lookup URL for the published context. */
  dediContextUrl?: string;
  /** Auto-generated JSON-LD context for this schema. */
  generatedContext?: Record<string, unknown>;
  /**
   * Fetched & cached JSON-LD context document for this schema's context URL.
   * Populated at schema-save time so the document loader can serve the URL
   * during issuance/verification without making any runtime network requests.
   */
  cachedContextDocument?: Record<string, unknown>;
  /** ISO 8601 timestamp at which the context document was fetched. */
  cachedContextFetchedAt?: string;
  /**
   * SHA-256 hex digest of `JSON.stringify(cachedContextDocument)`. Used by
   * `handleCustomSchemaSave` to detect context-URL collisions: per JSON-LD
   * 1.1 §3.1 a URL is a global identifier, so two schemas that claim the
   * same URL but hash to different bodies are refused at save time. Older
   * entries written before this field existed may have the hash absent.
   */
  cachedContextDocumentHash?: string;
}

/** A recently used credential template (no credential data stored). */
export interface RecentTemplateEntry {
  /** Schema ID used (e.g. "education") or "custom:<uuid>". */
  schemaId: string;
  /** Human-readable schema name for display. */
  schemaName: string;
  /** ISO 8601 timestamp of the most recent use. */
  lastUsedAt: string;
  /** Number of times this template has been used. */
  useCount: number;
}

/** Maximum number of recent templates to retain. */
export const RECENT_TEMPLATES_CAP = 20;

/** @deprecated Kept for backward compat. */
export const CREDENTIAL_HISTORY_CAP = 100;

/**
 * Non-sensitive DeDi integration metadata persisted in electron-store.
 *
 * SECURITY NOTE: Credentials (API keys, passwords) are encrypted via
 * Electron's safeStorage API and stored as an encrypted blob in the
 * preferences field of this config file. The encryption key is managed
 * by the OS keychain (macOS Keychain, Windows DPAPI, Linux libsecret).
 * On systems without a keyring, DeDi credential persistence is unavailable.
 */
export interface DeDiStoreConfig {
  /** Base URL of the DeDi API (e.g., "https://api.dedi.global"). */
  baseUrl: string;
  /** The issuer's DeDi namespace (typically their domain). */
  namespace: string;
  /** Authentication type (determines which credential to retrieve from safeStorage). */
  authType: "api-key" | "bearer";
}

/**
 * Persisted issuer branding (logo + brand colors).
 *
 * SECURITY NOTE: This is presentation-layer only. It NEVER appears in
 * any signed Verifiable Credential payload — verifiers receive the same
 * VC regardless of branding. The logo is always a `data:` URI (base64
 * PNG or sanitized SVG); remote URLs are rejected at the IPC boundary.
 * Hex colors are validated against `^#[0-9a-fA-F]{3,6}$`.
 */
export interface IssuerBrandingStoreEntry {
  /** Base64 `data:` URI for the logo. */
  logoDataUri?: string;
  /** Detected MIME type of the logo (`image/png` or `image/svg+xml`). */
  logoMimeType?: "image/png" | "image/svg+xml";
  /** Hex primary color (`#RRGGBB`). */
  primaryColor?: string;
  /** Hex accent color (`#RRGGBB`). */
  accentColor?: string;
  /** ISO 8601 timestamp of the most recent update. */
  updatedAt?: string;
}

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
  /** Recently used templates — schema metadata only, no credential data. */
  recentTemplates: RecentTemplateEntry[];
  /** @deprecated Credential history with full payloads. Migrated to recentTemplates on startup. */
  credentialHistory: CredentialHistoryEntry[];
  /** User-created custom schemas for blank credentials. */
  customSchemas: CustomSchemaEntry[];
  /** Domain for Self-Published Keys (did:web) workflow. */
  selfPublishedKeyDomain?: string;
  /** DeDi integration configuration (optional — absent means DeDi is not configured). */
  dediConfig?: DeDiStoreConfig;
  /** Schema IDs that have been published to DeDi (cached to avoid redundant publishes). */
  dediPublishedSchemas: string[];
  /** ISO 8601 date until which the key rotation reminder is snoozed. */
  keyRotationDismissedUntil?: string;
  /** Persisted issuer branding (logo + colors) used by the SVG renderer. */
  issuerBranding?: IssuerBrandingStoreEntry;
}

const DEFAULTS: StoreSchema = {
  lastKeyId: undefined,
  theme: "system",
  offlineMode: false,
  bugReportFormUrl: "https://forms.gle/f1wFUhzN1VwgR5QD6",
  persistKeyPaths: true,
  preferences: {},
  recentTemplates: [],
  credentialHistory: [],
  customSchemas: [],
  dediPublishedSchemas: [],
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
