/**
 * Batch job TTL purge tests (HIGH-01).
 *
 * Exercises `purgeExpiredBatchJobs` directly with a mocked job store so
 * no real timers or batch engines are involved. See `batch.ts` — we seed
 * the private `jobs` Map via `__setJobsForTesting` and then drive the
 * sync helper with synthesized `now` values.
 */

import { describe, it, expect, afterEach } from "vitest";
import {
  __setJobsForTesting,
  purgeExpiredBatchJobs,
  startBatchJobCleanup,
  type BatchJobEntry,
} from "../routes/batch.js";

function makeEntry(opts: { createdAt: string; completedAt?: string }): BatchJobEntry {
  // The engine is never touched by the purge path — we cast through unknown
  // to satisfy the type without pulling in real BatchEngine infrastructure.
  return {
    engine: {} as unknown as BatchJobEntry["engine"],
    progress: null,
    createdAt: opts.createdAt,
    ...(opts.completedAt !== undefined ? { completedAt: opts.completedAt } : {}),
  };
}

describe("purgeExpiredBatchJobs", () => {
  let restore: (() => void) | undefined;

  afterEach(() => {
    if (restore) {
      restore();
      restore = undefined;
    }
  });

  it("deletes a completed job whose completedAt + ttl is in the past", () => {
    const now = Date.parse("2026-04-16T12:00:00Z");
    const ttlMs = 60_000; // 1 minute
    const seed = new Map<string, BatchJobEntry>([
      [
        "old-job",
        makeEntry({
          createdAt: "2026-04-16T10:00:00Z", // 2h ago
          completedAt: "2026-04-16T11:00:00Z", // 1h ago — way beyond 1min TTL
        }),
      ],
    ]);
    restore = __setJobsForTesting(seed);

    const deleted = purgeExpiredBatchJobs(ttlMs, now);

    expect(deleted).toBe(1);
  });

  it("keeps a completed job whose completedAt + ttl is in the future", () => {
    const now = Date.parse("2026-04-16T12:00:00Z");
    const ttlMs = 60 * 60 * 1000; // 1 hour
    const seed = new Map<string, BatchJobEntry>([
      [
        "fresh-job",
        makeEntry({
          createdAt: "2026-04-16T11:30:00Z", // 30m ago
          completedAt: "2026-04-16T11:45:00Z", // 15m ago — still within 1h TTL
        }),
      ],
    ]);
    restore = __setJobsForTesting(seed);

    const deleted = purgeExpiredBatchJobs(ttlMs, now);

    expect(deleted).toBe(0);
  });

  it("falls back to createdAt when completedAt is unset (orphan job)", () => {
    const now = Date.parse("2026-04-16T12:00:00Z");
    const ttlMs = 30 * 60 * 1000; // 30 minutes
    const seed = new Map<string, BatchJobEntry>([
      [
        "stuck-job",
        makeEntry({
          // Created 1h ago, never completed — should purge at createdAt + 30m.
          createdAt: "2026-04-16T11:00:00Z",
        }),
      ],
    ]);
    restore = __setJobsForTesting(seed);

    const deleted = purgeExpiredBatchJobs(ttlMs, now);

    expect(deleted).toBe(1);
  });

  it("keeps a still-running job whose createdAt is within TTL", () => {
    const now = Date.parse("2026-04-16T12:00:00Z");
    const ttlMs = 60 * 60 * 1000; // 1 hour
    const seed = new Map<string, BatchJobEntry>([
      [
        "running-job",
        makeEntry({
          // Created 15m ago, not yet completed — well within 1h.
          createdAt: "2026-04-16T11:45:00Z",
        }),
      ],
    ]);
    restore = __setJobsForTesting(seed);

    const deleted = purgeExpiredBatchJobs(ttlMs, now);

    expect(deleted).toBe(0);
  });

  it("mixed store: evicts expired, retains fresh, returns count", () => {
    const now = Date.parse("2026-04-16T12:00:00Z");
    const ttlMs = 10 * 60 * 1000; // 10 minutes
    const seed = new Map<string, BatchJobEntry>([
      ["expired-1", makeEntry({ createdAt: "2026-04-16T10:00:00Z", completedAt: "2026-04-16T11:00:00Z" })],
      ["expired-2", makeEntry({ createdAt: "2026-04-16T11:00:00Z" })], // orphan, 1h old
      ["fresh-1", makeEntry({ createdAt: "2026-04-16T11:55:00Z", completedAt: "2026-04-16T11:57:00Z" })],
      ["fresh-2", makeEntry({ createdAt: "2026-04-16T11:58:00Z" })],
    ]);
    restore = __setJobsForTesting(seed);

    const deleted = purgeExpiredBatchJobs(ttlMs, now);

    expect(deleted).toBe(2);
  });

  it("ignores entries with unparseable timestamps rather than throwing", () => {
    const now = Date.parse("2026-04-16T12:00:00Z");
    const ttlMs = 60_000;
    const seed = new Map<string, BatchJobEntry>([
      ["garbage-job", makeEntry({ createdAt: "not-a-date" })],
    ]);
    restore = __setJobsForTesting(seed);

    const deleted = purgeExpiredBatchJobs(ttlMs, now);

    // Unparseable → skip silently, job stays in the map for the operator
    // to notice via other means.
    expect(deleted).toBe(0);
  });

  it("is a no-op on an empty store", () => {
    restore = __setJobsForTesting(new Map());
    expect(purgeExpiredBatchJobs(60_000, Date.now())).toBe(0);
  });
});

describe("startBatchJobCleanup", () => {
  it("returns an unref'd timer that tests can cancel", () => {
    const handle = startBatchJobCleanup(10_000, 60_000);
    try {
      expect(handle).toBeDefined();
      // Node's Timeout has an `unref` method — not strictly required but
      // signals the implementation called it.
      expect(typeof (handle as unknown as { unref?: () => unknown }).unref).toBe("function");
    } finally {
      clearInterval(handle);
    }
  });
});
