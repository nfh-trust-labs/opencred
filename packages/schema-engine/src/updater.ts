/**
 * Schema update checking and caching.
 *
 * This module provides functions to:
 *  - Check a remote manifest for schema updates
 *  - Download individual schema definitions
 *  - Load/save schemas from/to a local filesystem cache
 *
 * SECURITY NOTES:
 *  - Schema updates are a startup-time optimization ONLY.
 *  - Schemas are NEVER fetched at runtime during credential operations.
 *  - Cached schemas are validated via SHA-256 checksum before use.
 *  - All network operations fail gracefully — bundled schemas are always the fallback.
 */

import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { SchemaDefinition, SchemaManifest, SchemaUpdateResult } from "./types.js";

/**
 * Compare two semver version strings.
 * Returns a positive number if `a > b`, negative if `a < b`, 0 if equal.
 */
export function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Compute SHA-256 checksum for a schema object (deterministic via JSON.stringify).
 */
export function computeChecksum(schema: Record<string, unknown>): string {
  const canonical = JSON.stringify(schema);
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Fetch a remote schema manifest and compare it against the current local manifest.
 *
 * Returns a result indicating which schemas have newer versions available.
 * If the network request fails, returns `{ hasUpdates: false }` so the caller
 * can gracefully fall back to bundled schemas.
 *
 * @param currentManifest - The manifest of currently loaded schemas
 * @param updateUrl       - Base URL for the schema update server (manifest at `<url>/manifest.json`)
 */
export async function checkForSchemaUpdates(
  currentManifest: SchemaManifest,
  updateUrl: string,
): Promise<SchemaUpdateResult> {
  try {
    const manifestUrl = updateUrl.endsWith("/")
      ? `${updateUrl}manifest.json`
      : `${updateUrl}/manifest.json`;

    const response = await fetch(manifestUrl);
    if (!response.ok) {
      return { hasUpdates: false, updatedIds: [], remoteManifest: currentManifest };
    }

    const remoteManifest = (await response.json()) as SchemaManifest;

    // Build a lookup of current schema versions
    const currentVersions = new Map<string, string>();
    for (const entry of currentManifest.schemas) {
      currentVersions.set(entry.id, entry.version);
    }

    // Find schemas that have newer versions in the remote manifest
    const updatedIds: string[] = [];
    for (const remote of remoteManifest.schemas) {
      const currentVersion = currentVersions.get(remote.id);
      if (!currentVersion || compareSemver(remote.version, currentVersion) > 0) {
        updatedIds.push(remote.id);
      }
    }

    return {
      hasUpdates: updatedIds.length > 0,
      updatedIds,
      remoteManifest,
    };
  } catch {
    // Network failure — gracefully fall back to bundled schemas
    return { hasUpdates: false, updatedIds: [], remoteManifest: currentManifest };
  }
}

/**
 * Download a single schema definition from the update server.
 *
 * Returns the schema definition if successful, or `null` if the download fails.
 * The caller should verify the checksum before using the schema.
 *
 * @param schemaId  - ID of the schema to download
 * @param updateUrl - Base URL for the schema update server (schema at `<url>/schemas/<id>.json`)
 */
export async function downloadSchema(
  schemaId: string,
  updateUrl: string,
): Promise<SchemaDefinition | null> {
  try {
    const base = updateUrl.endsWith("/") ? updateUrl : `${updateUrl}/`;
    const schemaUrl = `${base}schemas/${schemaId}.json`;

    const response = await fetch(schemaUrl);
    if (!response.ok) {
      return null;
    }

    const definition = (await response.json()) as SchemaDefinition;
    return definition;
  } catch {
    return null;
  }
}

/**
 * Load cached schema definitions from a local directory.
 *
 * Each schema is stored as `<cacheDir>/<id>.json`. Only files that pass
 * JSON parsing are returned — corrupt cache entries are silently skipped.
 *
 * @param cacheDir - Absolute path to the cache directory
 */
export async function loadCachedSchemas(cacheDir: string): Promise<SchemaDefinition[]> {
  try {
    const entries = await readdir(cacheDir);
    const schemas: SchemaDefinition[] = [];

    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const content = await readFile(join(cacheDir, entry), "utf-8");
        const definition = JSON.parse(content) as SchemaDefinition;
        // Validate required fields and checksum integrity
        if (definition.id && definition.schema && definition.version) {
          if (definition.checksum) {
            const actual = createHash("sha256")
              .update(JSON.stringify(definition.schema))
              .digest("hex");
            if (actual !== definition.checksum) continue; // skip corrupted
          }
          schemas.push(definition);
        }
      } catch {
        // Skip corrupt cache entries
      }
    }

    return schemas;
  } catch {
    // Cache directory doesn't exist or can't be read
    return [];
  }
}

/**
 * Persist schema definitions to a local cache directory.
 *
 * Creates the cache directory if it doesn't exist. Each schema is written
 * as `<cacheDir>/<id>.json`.
 *
 * @param schemas  - Schema definitions to cache
 * @param cacheDir - Absolute path to the cache directory
 */
export async function saveSchemasToCache(
  schemas: SchemaDefinition[],
  cacheDir: string,
): Promise<void> {
  try {
    await mkdir(cacheDir, { recursive: true });
    for (const schema of schemas) {
      const filePath = join(cacheDir, `${schema.id}.json`);
      const withChecksum = {
        ...schema,
        checksum: createHash("sha256").update(JSON.stringify(schema.schema)).digest("hex"),
      };
      await writeFile(filePath, JSON.stringify(withChecksum, null, 2), "utf-8");
    }
  } catch {
    // Cache write failure is non-fatal — bundled schemas remain available
  }
}

/**
 * Validate a cached schema against an expected checksum from the manifest.
 *
 * @param schema           - The schema definition to validate
 * @param expectedChecksum - SHA-256 hex checksum from the manifest
 * @returns `true` if the checksum matches, `false` otherwise
 */
export function validateSchemaChecksum(
  schema: SchemaDefinition,
  expectedChecksum: string,
): boolean {
  const actual = computeChecksum(schema.schema);
  return actual === expectedChecksum;
}
