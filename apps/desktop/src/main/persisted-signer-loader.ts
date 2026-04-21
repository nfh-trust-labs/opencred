/**
 * Auto-reload persisted signing keys on app startup.
 *
 * Reads `preferences.importedKeyPaths` from the electron-store and
 * re-creates SoftwareSigner instances for each saved key file.
 *
 * Entries whose key file no longer exists (ENOENT) are removed from the
 * store — that's the "moved or deleted" case. Any other failure
 * (permission denied, locked by another process, unparseable file, etc.)
 * is logged at error level and the entry is kept so the user can retry
 * on next launch. Previously every failure category flowed to silent
 * removal, which meant a transient permission hiccup on startup could
 * wipe the user's entire key list.
 *
 * SECURITY: Private key material is NEVER logged. Only key IDs and
 * fingerprints appear in log output.
 */

import { existsSync } from "node:fs";
import { createSoftwareSigner } from "../signing/software-signer.js";
import type { KeyMetadata } from "../shared/ipc-types.js";
import { createLogger } from "./logger.js";

const logger = createLogger("signer-reload");

/** Persisted entry — file path + optional label saved to electron-store. */
export interface PersistedSignerEntry {
  path: string;
  label?: string;
}

/** Minimal store interface — avoids importing electron-store directly. */
interface SignerStore {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
}

/** Result maps — populated by this module, consumed by ipc-handlers. */
export interface ReloadResult {
  metadata: Map<string, KeyMetadata>;
  signers: Map<string, ReturnType<typeof createSoftwareSigner>["signer"]>;
}

/**
 * Reload previously imported signing identities from persisted file paths.
 *
 * @param store - The electron-store instance (injected to avoid importing electron).
 * @returns Maps of reloaded metadata and signers.
 */
export function reloadPersistedSigners(store: SignerStore): ReloadResult {
  const metadata = new Map<string, KeyMetadata>();
  const signers = new Map<string, ReturnType<typeof createSoftwareSigner>["signer"]>();

  try {
    const shouldPersist = (store.get("persistKeyPaths") as boolean | undefined) ?? true;
    if (!shouldPersist) {
      logger.info("Persistence disabled, skipping reload");
      return { metadata, signers };
    }

    const prefs = (store.get("preferences") as Record<string, unknown>) ?? {};
    const saved =
      (prefs["importedKeyPaths"] as Record<string, string | PersistedSignerEntry>) ?? {};
    const ids = Object.keys(saved);

    if (ids.length === 0) {
      logger.info("No persisted signers to reload");
      return { metadata, signers };
    }

    logger.info("Reloading persisted signers", { count: ids.length });
    const staleIds: string[] = [];

    for (const id of ids) {
      const entry = saved[id];
      // Support both legacy string format and new { path, label } format
      const filePath = typeof entry === "string" ? entry : entry.path;
      const label = typeof entry === "string" ? undefined : entry.label;

      // Pre-check file existence. If the file is gone, treat the entry as
      // stale and remove — that's the "moved or deleted" case. If the file
      // is present but createSoftwareSigner fails for some other reason,
      // we keep the entry and log at error level so the user can retry.
      if (!existsSync(filePath)) {
        logger.warn("Stale signer path (file missing), removing", { id });
        staleIds.push(id);
        continue;
      }

      try {
        const { signer, format } = createSoftwareSigner(filePath, label);
        const meta: KeyMetadata = {
          id: signer.id,
          fingerprint: signer.metadata.fingerprint,
          algorithm: "ECDSA P-256",
          importedAt: new Date().toISOString(),
          label,
          format,
          source: "file",
        };

        metadata.set(signer.id, meta);
        signers.set(signer.id, signer);
        logger.info("Signer reloaded", { id: signer.id, fingerprint: meta.fingerprint });
      } catch (err) {
        // File exists but loading failed (permission, locked, corrupt,
        // unsupported format, etc.). Keep the entry so the user can retry.
        logger.error("Signer reload failed, keeping entry for next launch", {
          id,
          error: err instanceof Error ? err.message : "unknown error",
        });
      }
    }

    // Clean up stale entries
    if (staleIds.length > 0) {
      const cleaned = { ...saved };
      for (const id of staleIds) {
        delete cleaned[id];
      }
      store.set("preferences", { ...prefs, importedKeyPaths: cleaned });
      logger.info("Removed stale signer entries", { count: staleIds.length });
    }
  } catch (err) {
    // Never crash the app due to a corrupt store
    const message = err instanceof Error ? err.message : "Unknown error";
    logger.error("Failed to reload persisted signers", { error: message });
  }

  return { metadata, signers };
}
