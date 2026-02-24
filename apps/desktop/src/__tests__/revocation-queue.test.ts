/**
 * Tests for the revocation queue.
 *
 * Validates queue operations, persistence, and status tracking.
 * Uses a mocked electron-store to simulate persistence.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock electron-store
const storeData: Record<string, unknown> = {};
const mockGet = vi.fn((key: string) => storeData[key]);
const mockSet = vi.fn((key: string, value: unknown) => {
  storeData[key] = value;
});
const mockStore = { get: mockGet, set: mockSet, store: {} };

vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => mockStore),
}));

// Import and initialize store before importing revocation-queue
const { initStore } = await import("../main/store");
initStore();

const {
  queueRevocation,
  getQueueItems,
  getQueueItemsByStatus,
  getQueueItem,
  updateQueueItemStatus,
  purgePublished,
} = await import("../main/revocation-queue");

describe("Revocation Queue", () => {
  beforeEach(() => {
    // Clear the store between tests
    for (const key of Object.keys(storeData)) {
      delete storeData[key];
    }
    vi.clearAllMocks();
  });

  describe("queueRevocation", () => {
    it("should queue a revocation with correct initial state", () => {
      const item = queueRevocation(
        "urn:uuid:test-credential-1",
        "https://dedi.example/revocations/test",
      );

      expect(item.queueId).toBeDefined();
      expect(item.queueId.length).toBe(32); // 16 bytes hex
      expect(item.credentialId).toBe("urn:uuid:test-credential-1");
      expect(item.registryUrl).toBe("https://dedi.example/revocations/test");
      expect(item.status).toBe("pending");
      expect(item.queuedAt).toBeDefined();
      expect(item.attemptCount).toBe(0);
    });

    it("should accept optional revocation hash and reason", () => {
      const item = queueRevocation(
        "urn:uuid:test-credential-2",
        "https://dedi.example/revocations/test",
        {
          revocationHash: "abc123",
          reason: "Key compromised",
        },
      );

      expect(item.revocationHash).toBe("abc123");
      expect(item.reason).toBe("Key compromised");
    });

    it("should persist items to the store", () => {
      queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");

      // Store should have been called with the queue
      expect(mockSet).toHaveBeenCalled();
      const lastCall = mockSet.mock.calls[mockSet.mock.calls.length - 1];
      expect(lastCall[0]).toBe("revocationQueue");
      const savedQueue = lastCall[1] as unknown[];
      expect(savedQueue).toBeInstanceOf(Array);
      expect(savedQueue.length).toBeGreaterThan(0);
    });

    it("should accumulate multiple items", () => {
      queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");
      queueRevocation("urn:uuid:test-2", "https://dedi.example/revocations/test");
      queueRevocation("urn:uuid:test-3", "https://dedi.example/revocations/test");

      const items = getQueueItems();
      expect(items.length).toBe(3);
    });
  });

  describe("getQueueItems", () => {
    it("should return an empty array when no items are queued", () => {
      const items = getQueueItems();
      expect(items).toEqual([]);
    });

    it("should return all queued items", () => {
      queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");
      queueRevocation("urn:uuid:test-2", "https://dedi.example/revocations/test");

      const items = getQueueItems();
      expect(items.length).toBe(2);
    });
  });

  describe("getQueueItem", () => {
    it("should find a specific item by queue ID", () => {
      const created = queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");
      const found = getQueueItem(created.queueId);

      expect(found).toBeDefined();
      expect(found?.credentialId).toBe("urn:uuid:test-1");
    });

    it("should return undefined for unknown IDs", () => {
      const found = getQueueItem("nonexistent");
      expect(found).toBeUndefined();
    });
  });

  describe("getQueueItemsByStatus", () => {
    it("should filter items by status", () => {
      const item1 = queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");
      queueRevocation("urn:uuid:test-2", "https://dedi.example/revocations/test");

      // Update one item's status
      updateQueueItemStatus(item1.queueId, "published");

      const pending = getQueueItemsByStatus("pending");
      const published = getQueueItemsByStatus("published");

      expect(pending.length).toBe(1);
      expect(published.length).toBe(1);
      expect(published[0].credentialId).toBe("urn:uuid:test-1");
    });
  });

  describe("updateQueueItemStatus", () => {
    it("should update the status of a queue item", () => {
      const item = queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");

      const updated = updateQueueItemStatus(item.queueId, "publishing");

      expect(updated).toBeDefined();
      expect(updated?.status).toBe("publishing");
      expect(updated?.lastAttemptAt).toBeDefined();
      expect(updated?.attemptCount).toBe(1);
    });

    it("should track error messages", () => {
      const item = queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");

      const updated = updateQueueItemStatus(item.queueId, "failed", "Network timeout");

      expect(updated?.status).toBe("failed");
      expect(updated?.lastError).toBe("Network timeout");
    });

    it("should increment attempt count", () => {
      const item = queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");

      updateQueueItemStatus(item.queueId, "publishing");
      updateQueueItemStatus(item.queueId, "failed", "Error 1");
      const updated = updateQueueItemStatus(item.queueId, "publishing");

      expect(updated?.attemptCount).toBe(3);
    });

    it("should return undefined for unknown IDs", () => {
      const result = updateQueueItemStatus("nonexistent", "failed");
      expect(result).toBeUndefined();
    });
  });

  describe("purgePublished", () => {
    it("should remove published items from the queue", () => {
      const item1 = queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");
      queueRevocation("urn:uuid:test-2", "https://dedi.example/revocations/test");
      const item3 = queueRevocation("urn:uuid:test-3", "https://dedi.example/revocations/test");

      updateQueueItemStatus(item1.queueId, "published");
      updateQueueItemStatus(item3.queueId, "published");

      const purged = purgePublished();

      expect(purged).toBe(2);

      const remaining = getQueueItems();
      expect(remaining.length).toBe(1);
      expect(remaining[0].credentialId).toBe("urn:uuid:test-2");
    });

    it("should return 0 when no published items exist", () => {
      queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");

      const purged = purgePublished();
      expect(purged).toBe(0);
    });
  });

  describe("Persistence", () => {
    it("should persist queue state to electron-store", () => {
      queueRevocation("urn:uuid:test-1", "https://dedi.example/revocations/test");

      // Verify the store was called
      expect(mockSet).toHaveBeenCalledWith("revocationQueue", expect.any(Array));
    });

    it("should load queue state from electron-store", () => {
      // Pre-populate the store
      storeData["revocationQueue"] = [
        {
          queueId: "pre-existing-id",
          credentialId: "urn:uuid:pre-existing",
          registryUrl: "https://dedi.example/revocations/test",
          status: "pending",
          queuedAt: "2025-01-01T00:00:00Z",
          attemptCount: 0,
        },
      ];

      const items = getQueueItems();
      expect(items.length).toBe(1);
      expect(items[0].queueId).toBe("pre-existing-id");
    });

    it("should handle corrupted store data gracefully", () => {
      storeData["revocationQueue"] = "not an array";

      const items = getQueueItems();
      expect(items).toEqual([]);
    });
  });
});
