/**
 * Desktop schema update orchestrator.
 *
 * Runs at startup (after the window is shown) to check for schema updates
 * in the background. The app always starts with bundled schemas immediately;
 * this module downloads and caches any available updates for the next launch.
 *
 * SECURITY NOTES:
 *  - Schema updates happen at startup only, NEVER during credential operations.
 *  - Cached schemas are validated via SHA-256 checksum before being loaded.
 *  - Network failures are silently ignored — bundled schemas are always the fallback.
 */

import { app } from "electron";
import * as path from "node:path";
import {
  getSchemaManifest,
  checkForSchemaUpdates,
  downloadSchema,
  saveSchemasToCache,
  loadCachedSchemas,
  validateSchemaChecksum,
} from "@opencred/schema-engine";
import type { SchemaDefinition } from "@opencred/schema-engine";

/** Default URL for schema manifest. Points to GitHub Releases by default. */
const DEFAULT_SCHEMA_UPDATE_URL =
  "https://github.com/nfh-trust-labs/opencred/releases/latest/download";

/**
 * Get the schema cache directory within the app's user data folder.
 */
function getSchemaCacheDir(): string {
  return path.join(app.getPath("userData"), "schema-cache");
}

/**
 * Run the full schema update lifecycle:
 *  1. Load the current bundled manifest
 *  2. Check the remote server for newer versions
 *  3. Download updated schemas
 *  4. Validate checksums and cache to disk
 *
 * This function is designed to be called with `.catch()` — it never throws
 * in a way that would disrupt app startup.
 */
export async function checkForSchemaUpdatesAtStartup(): Promise<void> {
  const updateUrl = DEFAULT_SCHEMA_UPDATE_URL;
  const cacheDir = getSchemaCacheDir();

  console.log("[schema-updater] Starting background schema update check");

  // 1. Get the current bundled manifest
  const currentManifest = getSchemaManifest();
  console.log(
    `[schema-updater] Current manifest: ${currentManifest.schemas.length} schemas`,
  );

  // 2. Check for updates
  const result = await checkForSchemaUpdates(currentManifest, updateUrl);
  if (!result.hasUpdates) {
    console.log("[schema-updater] No schema updates available");
    return;
  }

  console.log(`[schema-updater] Updates available for: ${result.updatedIds.join(", ")}`);

  // 3. Download updated schemas and validate checksums
  const checksumLookup = new Map(
    result.remoteManifest.schemas.map((s) => [s.id, s.checksum]),
  );
  const downloaded: SchemaDefinition[] = [];
  for (const schemaId of result.updatedIds) {
    const schema = await downloadSchema(schemaId, updateUrl);
    if (!schema) {
      console.warn(`[schema-updater] Failed to download: ${schemaId}`);
      continue;
    }

    // Validate checksum to prevent tampered/corrupted schemas from being cached
    const expectedChecksum = checksumLookup.get(schemaId);
    if (expectedChecksum && !validateSchemaChecksum(schema, expectedChecksum)) {
      console.warn(
        `[schema-updater] Checksum mismatch for ${schemaId} — discarding (possible tampering)`,
      );
      continue;
    }

    downloaded.push(schema);
    console.log(`[schema-updater] Downloaded and verified: ${schemaId}@${schema.version}`);
  }

  if (downloaded.length === 0) {
    console.log("[schema-updater] No schemas were successfully downloaded");
    return;
  }

  // 4. Cache to disk
  await saveSchemasToCache(downloaded, cacheDir);
  console.log(`[schema-updater] Cached ${downloaded.length} schema updates to ${cacheDir}`);
}

/**
 * Load any previously cached schema updates from disk.
 * Returns an empty array if no cache exists or cache is corrupt.
 */
export async function loadCachedSchemaUpdates(): Promise<SchemaDefinition[]> {
  const cacheDir = getSchemaCacheDir();
  return loadCachedSchemas(cacheDir);
}
