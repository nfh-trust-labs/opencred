/**
 * Schema update checker — fetches a remote manifest at startup and
 * registers any schemas that are newer than the bundled versions.
 *
 * SECURITY INVARIANTS:
 *  - Updates happen ONCE at startup, NEVER during signing/verification.
 *  - Bundled schemas are ALWAYS the fallback — any failure silently
 *    degrades to the bundled set with a logged warning.
 *  - HTTPS only, no redirects, SSRF-protected (isPrivateIP).
 *  - Every downloaded schema is SHA-256 verified before registration.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fetchWithPinnedIp, resolveDnsForSsrf } from "@opencred/shared";
import type { SchemaDefinition } from "./types.js";
import type { SchemaRegistry } from "./schema-registry.js";

// -------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------

/** A single entry in the remote update manifest. */
export interface SchemaUpdateManifestEntry {
  id: string;
  version: string;
  checksum: string;
  downloadUrl: string;
  contextUrl?: string;
}

/** Remote update manifest served at the configured HTTPS URL. */
export interface SchemaUpdateManifest {
  version: number;
  timestamp: string;
  schemas: SchemaUpdateManifestEntry[];
}

/** Configuration for the startup schema update check. */
export interface SchemaUpdateConfig {
  /** HTTPS URL of the update manifest. If unset, updates are disabled. */
  manifestUrl?: string;
  /** Local directory for caching downloaded schemas between restarts. */
  cacheDir: string;
  /** Network timeout in milliseconds (default 10 000). */
  timeoutMs?: number;
  /** Optional structured logger. */
  logger?: { info(...args: unknown[]): void; warn(...args: unknown[]): void };
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 10_000;

/** Noop logger when none is provided. */
const NOOP_LOGGER = { info: () => {}, warn: () => {} };

/**
 * Compare two semver strings. Returns:
 *  - positive if a > b
 *  - negative if a < b
 *  - 0 if equal
 */
function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Validate that a URL is HTTPS, then resolve its hostname and reject
 * private/loopback IPs (SSRF protection).
 *
 * Uses `resolveDnsForSsrf`, which validates every resolved A and AAAA
 * address, rather than `dns.lookup`, which returns only a single address
 * and could leave other records unchecked. The connection is then pinned
 * to the validated addresses via `fetchWithPinnedIp` (DNS-rebinding TOCTOU
 * prevention).
 */
async function ssrfSafeFetch(url: string, timeoutMs: number): Promise<Response> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`Non-HTTPS URL rejected: ${url}`);
  }

  // The validated addresses are pinned for the connection — a plain
  // `fetch(url)` would re-resolve the hostname, letting a rebinding DNS
  // server swap in a private IP between the check and the fetch (TOCTOU).
  const pinnedAddresses = await resolveDnsForSsrf(parsed.hostname);

  return fetchWithPinnedIp(url, pinnedAddresses, {
    signal: AbortSignal.timeout(timeoutMs),
  });
}

/** Compute SHA-256 hex digest of a canonical JSON string. */
function sha256(json: string): string {
  return createHash("sha256").update(json).digest("hex");
}

/** Convert a schema ID to a safe filename for the cache directory. */
function cacheFileName(id: string): string {
  return id.replace(/\//g, "-") + ".json";
}

// -------------------------------------------------------------------------
// Core update logic
// -------------------------------------------------------------------------

/**
 * Check a remote manifest for updated schemas and merge them into the
 * provided registry. On ANY failure the function logs a warning and
 * returns the registry with whatever loaded successfully — bundled
 * schemas are never removed.
 */
export async function checkForUpdates(
  config: SchemaUpdateConfig,
  currentRegistry: SchemaRegistry,
): Promise<SchemaRegistry> {
  const log = config.logger ?? NOOP_LOGGER;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  if (!config.manifestUrl) {
    return currentRegistry;
  }

  // Compute the manifest origin once up front. Every downloadUrl MUST match
  // this origin — this prevents a compromised or malicious manifest from
  // redirecting schema fetches to an attacker-controlled host.
  const manifestUrl = config.manifestUrl;
  let manifestOrigin: string;
  try {
    manifestOrigin = new URL(manifestUrl).origin;
  } catch (urlErr) {
    log.warn(
      `Schema update check failed: manifestUrl is not a valid URL: ${urlErr instanceof Error ? urlErr.message : String(urlErr)}`,
    );
    return currentRegistry;
  }

  try {
    // 1. Fetch the manifest
    const manifestRes = await ssrfSafeFetch(manifestUrl, timeoutMs);
    if (!manifestRes.ok) {
      log.warn(`Schema update manifest fetch failed: HTTP ${manifestRes.status}`);
      return currentRegistry;
    }

    const manifest = (await manifestRes.json()) as SchemaUpdateManifest;
    if (manifest.version !== 1) {
      log.warn(`Unsupported manifest version ${manifest.version}, skipping update`);
      return currentRegistry;
    }

    // 2. Build a lookup of currently registered schemas
    const currentManifest = currentRegistry.getManifest();
    const currentVersions = new Map(currentManifest.schemas.map((s) => [s.id, s.version]));

    // 3. Ensure cache directory exists
    await mkdir(config.cacheDir, { recursive: true });

    // 4. Process each schema entry
    for (const entry of manifest.schemas) {
      try {
        const currentVersion = currentVersions.get(entry.id);
        if (currentVersion && compareSemver(entry.version, currentVersion) <= 0) {
          continue; // bundled version is same or newer
        }

        let schemaJson: string | null = null;

        // Try loading from local cache first
        const cachePath = join(config.cacheDir, cacheFileName(entry.id));
        try {
          const cached = await readFile(cachePath, "utf-8");
          if (sha256(cached) === entry.checksum) {
            schemaJson = cached;
          }
        } catch {
          // Cache miss — will fetch from network
        }

        // Fetch from network if not cached
        if (!schemaJson) {
          // Enforce that downloadUrl shares the manifest's origin. Any
          // mismatch (different scheme, host, or port) is rejected so
          // the manifest cannot redirect us to a third-party host.
          let downloadOrigin: string;
          try {
            downloadOrigin = new URL(entry.downloadUrl).origin;
          } catch {
            log.warn(`Skipping schema ${entry.id}: downloadUrl is not a valid URL`);
            continue;
          }
          if (downloadOrigin !== manifestOrigin) {
            log.warn(
              `Skipping schema ${entry.id}: downloadUrl origin ${downloadOrigin} differs from manifest origin ${manifestOrigin}`,
            );
            continue;
          }

          const res = await ssrfSafeFetch(entry.downloadUrl, timeoutMs);
          if (!res.ok) {
            log.warn(`Failed to fetch schema ${entry.id}: HTTP ${res.status}`);
            continue;
          }

          const body = await res.text();
          // Canonicalise by parsing and re-serialising
          const parsed = JSON.parse(body) as Record<string, unknown>;
          schemaJson = JSON.stringify(parsed);

          // Verify checksum
          if (sha256(schemaJson) !== entry.checksum) {
            log.warn(`Checksum mismatch for schema ${entry.id}, skipping`);
            continue;
          }

          // Write to cache for next startup
          try {
            await writeFile(cachePath, schemaJson, "utf-8");
          } catch (cacheErr) {
            log.warn(
              `Failed to cache schema ${entry.id}: ${cacheErr instanceof Error ? cacheErr.message : String(cacheErr)}`,
            );
          }
        }

        // Register the updated schema
        const schema = JSON.parse(schemaJson) as Record<string, unknown>;
        const def: SchemaDefinition = {
          id: entry.id,
          schema,
          version: entry.version,
          lastUpdated: manifest.timestamp,
          checksum: entry.checksum,
          contextUrl: entry.contextUrl,
          source: {
            kind: "referenced",
            upstreamUrl: entry.downloadUrl,
            upstreamOwner: "Remote Update",
            upstreamLicense: "Unknown",
          },
        };
        currentRegistry.register(def);
        log.info(`Updated schema ${entry.id} to v${entry.version}`);
      } catch (entryErr) {
        log.warn(
          `Failed to process schema ${entry.id}: ${entryErr instanceof Error ? entryErr.message : String(entryErr)}`,
        );
      }
    }
  } catch (err) {
    log.warn(`Schema update check failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  return currentRegistry;
}
