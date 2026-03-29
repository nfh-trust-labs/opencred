/**
 * Revocation queue for offline-first credential revocation.
 *
 * When the user revokes a credential while offline, the revocation is queued
 * and persisted to electron-store. When connectivity is restored, the queued
 * revocations are published to the DeDi revocation registry.
 *
 * SECURITY INVARIANTS:
 *  - No key material is stored in the queue.
 *  - Only credential IDs and revocation metadata are persisted.
 *  - Publication to DeDi happens only when connectivity is available.
 */

import * as crypto from "node:crypto";
import { DeDiClient } from "@opencred/dedi-client";
import { getStore } from "./store.js";
import type { DeDiCredentials } from "../shared/ipc-types.js";

/**
 * Status of a queued revocation item.
 */
export type RevocationStatus = "pending" | "publishing" | "published" | "failed";

/**
 * A single revocation queue item.
 */
export interface RevocationQueueItem {
  /** Unique queue item ID. */
  queueId: string;
  /** The credential ID being revoked. */
  credentialId: string;
  /** The revocation registry URL. */
  registryUrl: string;
  /** The revocation hash (for DeDi). */
  revocationHash?: string;
  /** Current status. */
  status: RevocationStatus;
  /** When the revocation was queued (ISO 8601). */
  queuedAt: string;
  /** When the revocation was last attempted (ISO 8601). */
  lastAttemptAt?: string;
  /** Error message from the last failed attempt. */
  lastError?: string;
  /** Number of publish attempts. */
  attemptCount: number;
  /** Optional reason for revocation. */
  reason?: string;
}

/** Store key for the revocation queue. */
const QUEUE_STORE_KEY = "revocationQueue";

/**
 * Load the revocation queue from persistent storage.
 */
function loadQueue(): RevocationQueueItem[] {
  try {
    const store = getStore();
    const data = store.get(QUEUE_STORE_KEY as keyof typeof store.store) as
      | RevocationQueueItem[]
      | undefined;
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

/**
 * Save the revocation queue to persistent storage.
 */
function saveQueue(queue: RevocationQueueItem[]): void {
  try {
    const store = getStore();
    store.set(QUEUE_STORE_KEY as keyof typeof store.store, queue);
  } catch {
    // Store may not be initialized in test environments
  }
}

/**
 * Queue a credential revocation for later publication.
 *
 * @param credentialId - The credential ID to revoke.
 * @param registryUrl - The revocation registry URL.
 * @param options - Optional revocation details.
 * @returns The created queue item.
 */
export function queueRevocation(
  credentialId: string,
  registryUrl: string,
  options?: { revocationHash?: string; reason?: string },
): RevocationQueueItem {
  const queue = loadQueue();

  const item: RevocationQueueItem = {
    queueId: crypto.randomBytes(16).toString("hex"),
    credentialId,
    registryUrl,
    revocationHash: options?.revocationHash,
    status: "pending",
    queuedAt: new Date().toISOString(),
    attemptCount: 0,
    reason: options?.reason,
  };

  queue.push(item);
  saveQueue(queue);

  return item;
}

/**
 * Get all items in the revocation queue.
 */
export function getQueueItems(): RevocationQueueItem[] {
  return loadQueue();
}

/**
 * Get items by status.
 */
export function getQueueItemsByStatus(status: RevocationStatus): RevocationQueueItem[] {
  return loadQueue().filter((item) => item.status === status);
}

/**
 * Get a specific queue item by ID.
 */
export function getQueueItem(queueId: string): RevocationQueueItem | undefined {
  return loadQueue().find((item) => item.queueId === queueId);
}

/**
 * Update the status of a queue item.
 */
export function updateQueueItemStatus(
  queueId: string,
  status: RevocationStatus,
  error?: string,
): RevocationQueueItem | undefined {
  const queue = loadQueue();
  const item = queue.find((i) => i.queueId === queueId);

  if (!item) {
    return undefined;
  }

  item.status = status;
  item.lastAttemptAt = new Date().toISOString();
  item.attemptCount += 1;
  if (error) {
    item.lastError = error;
  }

  saveQueue(queue);
  return item;
}

/**
 * Remove published items from the queue.
 */
export function purgePublished(): number {
  const queue = loadQueue();
  const before = queue.length;
  const remaining = queue.filter((item) => item.status !== "published");
  saveQueue(remaining);
  return before - remaining.length;
}

/** Maximum number of publish attempts before an item is permanently failed. */
const MAX_PUBLISH_ATTEMPTS = 5;

/**
 * Create a temporary DeDi client from issuer-provided credentials.
 *
 * The client is ephemeral — it is created for one publish cycle and then
 * discarded. Credentials are never persisted or logged.
 *
 * @param dediBaseUrl - The DeDi API base URL.
 * @param dediCredentials - The issuer's DeDi credentials.
 * @param defaultNamespace - Default namespace for record operations.
 */
function createDeDiClient(
  dediBaseUrl: string,
  dediCredentials: DeDiCredentials,
  defaultNamespace: string,
): DeDiClient {
  return new DeDiClient({
    baseUrl: dediBaseUrl,
    auth: dediCredentials,
    defaultNamespace,
    timeoutMs: 30_000,
    circuitBreakerThreshold: 5,
    maxRetries: 2,
  });
}

/**
 * Attempt to publish all pending revocations to the issuer's DeDi registry.
 *
 * The issuer provides their own DeDi credentials for each publish request.
 * A temporary DeDi client is created, used to publish hashes, and then
 * discarded — credentials are never persisted.
 *
 * Items that have reached the maximum retry count ({@link MAX_PUBLISH_ATTEMPTS})
 * are skipped — they are considered permanently failed.
 *
 * @param dediCredentials - The issuer's DeDi authentication credentials.
 * @param dediBaseUrl - The base URL of the DeDi revocation registry.
 * @returns An array of results for each item that was attempted.
 */
export async function publishPendingRevocations(
  dediCredentials: DeDiCredentials,
  dediBaseUrl: string,
): Promise<Array<{ queueId: string; success: boolean; error?: string }>> {
  const pending = getQueueItemsByStatus("pending");
  const failed = getQueueItemsByStatus("failed");
  const toPublish = [...pending, ...failed].filter(
    (item) => item.attemptCount < MAX_PUBLISH_ATTEMPTS,
  );
  const results: Array<{ queueId: string; success: boolean; error?: string }> = [];

  if (toPublish.length === 0) {
    return results;
  }

  // Resolve the DeDi namespace from stored config — this is the actual
  // namespace name (e.g., "issuers.opencred.world"), NOT a URL.
  const store = getStore();
  const dediConfig = store.get("dediConfig") as { namespace?: string } | undefined;
  const namespace = dediConfig?.namespace;
  if (!namespace) {
    for (const item of toPublish) {
      results.push({
        queueId: item.queueId,
        success: false,
        error: "DeDi namespace not configured — set up DeDi in Settings first",
      });
    }
    return results;
  }

  // Check connectivity before creating the client
  try {
    const dns = await import("node:dns/promises");
    await dns.lookup("dns.google");
  } catch {
    // Offline — mark every item as failed but do not waste an attempt
    for (const item of toPublish) {
      results.push({
        queueId: item.queueId,
        success: false,
        error: "No network connectivity",
      });
    }
    return results;
  }

  // Create a single DeDi client for the publish cycle using the configured
  // namespace. The client is ephemeral — discarded after this batch.
  const client = createDeDiClient(dediBaseUrl, dediCredentials, namespace);

  for (const item of toPublish) {
    updateQueueItemStatus(item.queueId, "publishing");

    try {
      if (!item.revocationHash) {
        throw new Error("Revocation hash is missing");
      }

      await client.publishRevocationHash(item.revocationHash);
      updateQueueItemStatus(item.queueId, "published");
      results.push({ queueId: item.queueId, success: true });
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Publication failed";
      updateQueueItemStatus(item.queueId, "failed", errorMsg);
      results.push({ queueId: item.queueId, success: false, error: errorMsg });
    }
  }

  return results;
}
