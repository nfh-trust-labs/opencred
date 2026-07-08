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
import { createLogger } from "./logger.js";

const logger = createLogger("store");

/**
 * A record of a previously issued credential (stored locally).
 *
 * @deprecated Use {@link RecentTemplateEntry} instead — credential history
 * is migrated on startup and {@link migrateCredentialHistory} clears the
 * old store. This type is retained only so legacy reads of the persisted
 * data on disk type-check during the migration step.
 *
 * NOTE: the `credentialJson` field has been removed. Signed credentials
 * are ephemeral and never persisted to disk; consumers that need the
 * full VC must capture it at signing time (see {@link
 * BuildAndSignResponse.signedCredential}).
 */
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
  /**
   * Publish status for the DeDi schema/context records.
   *
   * `pending`   — the publish promise is still in flight. UI should not
   *               treat `dediSchemaUrl` / `dediContextUrl` as resolvable
   *               yet.
   * `published` — both schema and context were successfully published.
   * `failed`    — at least one publish failed; UI should offer retry.
   *
   * Unset on entries that were not published to DeDi (no DeDi configured,
   * or the entry pre-dates this field). Treat unset as "not attempted".
   */
  dediPublishState?: "pending" | "published" | "failed";
  /** Last publish failure message for UI display (e.g. "namespace not found"). */
  dediPublishError?: string;
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
  /**
   * Verification methods (key ids) that have been published to DeDi's
   * key registry from this desktop client. Tracking these locally lets us
   * call `setKeyStatus(vm, "rotated")` when the user regenerates their key —
   * without this list we would have to either query DeDi on every key
   * generation (slow + leaks key ids) or silently leave prior records
   * showing `status: "active"`.
   *
   * The list is append-only; entries are never removed locally. If the
   * issuer manually deletes their DeDi record we just get a 404 on
   * `setKeyStatus(vm, "rotated")` and swallow it.
   */
  dediPublishedKeys: string[];
  /**
   * The sequential index (`#key-<n>`) of the issuer's CURRENT did:web signing
   * key. Set explicitly when a key is published or rotated; read at signing
   * time so issued credentials carry the matching `#key-<n>` verification
   * method. Defaults to `0` (a fresh issuer's first key). Stateless by design —
   * this records the operator's explicit choice, it is never auto-incremented.
   */
  dediActiveKeyIndex: number;
  /** ISO 8601 date until which the key rotation reminder is snoozed. */
  keyRotationDismissedUntil?: string;
  /** Issuer branding customization for credential templates. */
  branding?: {
    primaryColor?: string;
    logoDataUri?: string;
    issuerDisplayName?: string;
  };
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
  dediPublishedKeys: [],
  dediActiveKeyIndex: 0,
};

let store: ElectronStore<StoreSchema> | null = null;

/**
 * One-time migration from the deprecated `credentialHistory` field to
 * `recentTemplates`.
 *
 * For each legacy history entry that does not already have a matching
 * `recentTemplates` row (keyed by `schemaId`), insert a summary entry.
 * After migration the `credentialHistory` field is cleared so the full
 * credential JSON is no longer persisted on disk.
 *
 * Exposed so callers (and tests) can run the migration on-demand; `initStore`
 * also calls it automatically on first use.
 */
export function migrateCredentialHistory(s: ElectronStore<StoreSchema>): void {
  // electron-store's generic get() returns the value defaulted via the schema
  // (here, []). Read safely to tolerate older on-disk shapes.
  const history =
    (s.get("credentialHistory") as unknown as CredentialHistoryEntry[] | undefined) ?? [];
  if (history.length === 0) {
    return;
  }
  const templates =
    (s.get("recentTemplates") as unknown as RecentTemplateEntry[] | undefined) ?? [];
  const bySchema = new Map<string, RecentTemplateEntry>();
  for (const t of templates) {
    bySchema.set(t.schemaId, t);
  }
  for (const entry of history) {
    const existing = bySchema.get(entry.schemaId);
    if (existing) {
      // Keep the richer existing entry; bump lastUsedAt if the legacy entry is newer.
      if (entry.issuedAt > existing.lastUsedAt) {
        existing.lastUsedAt = entry.issuedAt;
      }
      existing.useCount += 1;
      continue;
    }
    const migrated: RecentTemplateEntry = {
      schemaId: entry.schemaId,
      schemaName: entry.schemaName,
      lastUsedAt: entry.issuedAt,
      useCount: 1,
    };
    bySchema.set(entry.schemaId, migrated);
  }
  const merged = Array.from(bySchema.values()).sort((a, b) =>
    b.lastUsedAt.localeCompare(a.lastUsedAt),
  );
  s.set("recentTemplates", merged.slice(0, RECENT_TEMPLATES_CAP));
  s.set("credentialHistory", []);
  logger.info("Migrated credentialHistory → recentTemplates", {
    migrated: history.length,
    templates: merged.length,
  });
}

/**
 * Migrate the legacy `dediPublishedDIDs` list to `dediPublishedKeys`.
 *
 * The per-key registry change renamed the on-disk list of
 * previously-published DeDi entries (it now holds verification methods, not
 * DIDs). Without this migration an upgrading user's prior entries would be
 * orphaned and `dediPublishedKeys` would default to `[]`, so the
 * key-generation hook would never flip their previously-published keys to
 * `rotated`. Copy the legacy values across (when the new list is still empty)
 * and drop the old key. Idempotent: a no-op once migrated.
 */
export function migrateDediPublishedKeys(s: ElectronStore<StoreSchema>): void {
  const legacy = s.get("dediPublishedDIDs" as keyof StoreSchema) as unknown as string[] | undefined;
  if (!Array.isArray(legacy) || legacy.length === 0) {
    return;
  }
  const current = (s.get("dediPublishedKeys") as unknown as string[] | undefined) ?? [];
  if (current.length === 0) {
    s.set("dediPublishedKeys", legacy);
  }
  s.delete("dediPublishedDIDs" as keyof StoreSchema);
  logger.info("Migrated dediPublishedDIDs → dediPublishedKeys", { migrated: legacy.length });
}

/**
 * Initialise the store. Call once during app startup.
 */
export function initStore(): ElectronStore<StoreSchema> {
  if (!store) {
    store = new ElectronStore<StoreSchema>({
      name: "opencred-config",
      defaults: DEFAULTS,
    });
    migrateCredentialHistory(store);
    migrateDediPublishedKeys(store);
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
  } catch (err: unknown) {
    // Best-effort: on Windows or if the file does not yet exist, chmod may
    // fail. Log a warning so the issue is visible in logs.
    const message = err instanceof Error ? err.message : String(err);
    logger.warn("Failed to restrict store file permissions", {
      path: store.path,
      error: message,
    });
  }
}
