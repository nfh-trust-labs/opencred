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
import { getStore } from "./store.js";

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

/**
 * Attempt to publish all pending revocations.
 *
 * This is a placeholder for the actual DeDi client integration.
 * In the real implementation, each pending item would be published
 * to its revocation registry URL using the DeDi client.
 *
 * @returns An array of results for each item that was attempted.
 */
export async function publishPendingRevocations(): Promise<
  Array<{ queueId: string; success: boolean; error?: string }>
> {
  const pending = getQueueItemsByStatus("pending");
  const failed = getQueueItemsByStatus("failed");
  const toPublish = [...pending, ...failed];
  const results: Array<{ queueId: string; success: boolean; error?: string }> = [];

  for (const item of toPublish) {
    updateQueueItemStatus(item.queueId, "publishing");

    try {
      // Check connectivity first
      const dns = await import("node:dns/promises");
      await dns.lookup("dns.google");

      // TODO: Actual DeDi client integration will go here.
      // For now, we mark items as published to validate the queue flow.
      // In production, this would call:
      //   dediClient.revokeCredential(item.registryUrl, item.revocationHash)
      updateQueueItemStatus(item.queueId, "published");
      results.push({ queueId: item.queueId, success: true });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Publication failed";
      updateQueueItemStatus(item.queueId, "failed", errorMsg);
      results.push({ queueId: item.queueId, success: false, error: errorMsg });
    }
  }

  return results;
}
