/**
 * Tests for the stale-job detection helper (Tier 2 #6 of
 * nfh-trust-labs/opencred#446).
 *
 * The helper is observation-only: it returns the subset of running /
 * queued jobs whose `lastSeenAt` heartbeat is older than
 * `staleMultiplier × heartbeatIntervalSeconds`. It does NOT auto-
 * transition records (that's a queue-engine concern, Tier 3 #8 / #583).
 *
 * Coverage:
 *  - Records with no `lastSeenAt` are ignored — "no signal" must not be
 *    silently treated as stale.
 *  - Settled records (`completed`, `failed`, `cancelled`, `interrupted`)
 *    are never reported.
 *  - The default 2× multiplier with the default 5 s interval flags any
 *    heartbeat older than 10 s.
 *  - The helper works across both backing-store implementations (memory
 *    and Redis fake).
 */

import { describe, it, expect } from "vitest";
import { MemoryJobStore } from "../memory.js";
import { RedisJobStore, type RedisLike } from "../redis.js";
import { findStaleRunningJobs } from "../types.js";
import type { JobRecord } from "../types.js";

// ---------------------------------------------------------------------------
// Inline FakeRedis (same shape as redis.test.ts; kept local so test files
// stay independent)
// ---------------------------------------------------------------------------

interface FakeEntry {
  value: string;
  expiresAt: number;
}

class FakeRedis implements RedisLike {
  private readonly data = new Map<string, FakeEntry>();
  public status = "ready";
  constructor(private now: () => number = () => Date.now()) {}

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, _mode: "EX", ttlSeconds: number): Promise<"OK" | null> {
    this.data.set(key, { value, expiresAt: this.now() + ttlSeconds * 1000 });
    return "OK";
  }

  async del(...keys: string[]): Promise<number> {
    let n = 0;
    for (const k of keys) if (this.data.delete(k)) n += 1;
    return n;
  }

  async scan(
    cursor: string | number,
    _mo: "MATCH",
    pattern: string,
    _co: "COUNT",
    _count: number,
  ): Promise<[string, string[]]> {
    if (cursor !== "0" && cursor !== 0) return ["0", []];
    const prefix = pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
    const out: string[] = [];
    const now = this.now();
    for (const [k, v] of this.data) {
      if (!k.startsWith(prefix)) continue;
      if (v.expiresAt <= now) continue;
      out.push(k);
    }
    return ["0", out];
  }

  async quit(): Promise<unknown> {
    return "OK";
  }
  disconnect(): void {
    /* no-op */
  }
}

// ---------------------------------------------------------------------------
// Shared record helper
// ---------------------------------------------------------------------------

function makeRecord(jobId: string, overrides: Partial<JobRecord> = {}): JobRecord {
  return {
    jobId,
    status: "running",
    progress: null,
    createdAt: new Date(1_700_000_000_000).toISOString(),
    ownerReplica: "host-A:42",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

const stores = [
  { name: "MemoryJobStore", make: () => new MemoryJobStore({ purgeIntervalMs: 0 }) },
  { name: "RedisJobStore", make: () => new RedisJobStore({ client: new FakeRedis() }) },
] as const;

for (const variant of stores) {
  describe(`findStaleRunningJobs — ${variant.name}`, () => {
    it("ignores records without a lastSeenAt field", async () => {
      const store = variant.make();
      // Running job, no heartbeat ever written. Even arbitrarily far in
      // the future, the helper must not surface it — "no signal" is not
      // the same as "stale".
      await store.set("job-no-hb", makeRecord("job-no-hb"), 600);

      const reports = await findStaleRunningJobs(store, {
        heartbeatIntervalSeconds: 5,
        // observer clock is one hour ahead of the record's `lastSeenAt`
        // (which doesn't exist) — still must be ignored.
        now: () => 1_700_000_000_000 + 3_600_000,
      });
      expect(reports).toHaveLength(0);
    });

    it("flags a record whose lastSeenAt is older than 2× interval", async () => {
      const store = variant.make();
      const baseMs = 1_700_000_000_000;
      // Heartbeat 11 s ago — past the 10 s window for default 5 s interval.
      await store.set(
        "stale-running",
        makeRecord("stale-running", { lastSeenAt: new Date(baseMs - 11_000).toISOString() }),
        600,
      );
      // Heartbeat 3 s ago — well inside the window.
      await store.set(
        "fresh-running",
        makeRecord("fresh-running", { lastSeenAt: new Date(baseMs - 3_000).toISOString() }),
        600,
      );

      const reports = await findStaleRunningJobs(store, {
        heartbeatIntervalSeconds: 5,
        now: () => baseMs,
      });
      expect(reports.map((r) => r.jobId)).toEqual(["stale-running"]);
      expect(reports[0]!.staleForMs).toBeGreaterThanOrEqual(11_000);
      expect(reports[0]!.ownerReplica).toBe("host-A:42");
    });

    it("never reports settled records, even with very stale heartbeats", async () => {
      const store = variant.make();
      const baseMs = 1_700_000_000_000;
      const veryStale = new Date(baseMs - 1_000_000).toISOString();
      for (const status of ["completed", "failed", "cancelled", "interrupted"] as const) {
        await store.set(
          `settled-${status}`,
          makeRecord(`settled-${status}`, { status, lastSeenAt: veryStale }),
          600,
        );
      }

      const reports = await findStaleRunningJobs(store, {
        heartbeatIntervalSeconds: 5,
        now: () => baseMs,
      });
      expect(reports).toHaveLength(0);
    });

    it("includes queued records — a job that never started signing is also a candidate", async () => {
      const store = variant.make();
      const baseMs = 1_700_000_000_000;
      await store.set(
        "stale-queued",
        makeRecord("stale-queued", {
          status: "queued",
          lastSeenAt: new Date(baseMs - 11_000).toISOString(),
        }),
        600,
      );
      const reports = await findStaleRunningJobs(store, {
        heartbeatIntervalSeconds: 5,
        now: () => baseMs,
      });
      expect(reports.map((r) => r.jobId)).toEqual(["stale-queued"]);
      expect(reports[0]!.status).toBe("queued");
    });

    it("honours a custom staleMultiplier", async () => {
      const store = variant.make();
      const baseMs = 1_700_000_000_000;
      // 11 s old — stale at 2×5s, but not at 3×5s.
      await store.set(
        "borderline",
        makeRecord("borderline", { lastSeenAt: new Date(baseMs - 11_000).toISOString() }),
        600,
      );
      const stricter = await findStaleRunningJobs(store, {
        heartbeatIntervalSeconds: 5,
        staleMultiplier: 2,
        now: () => baseMs,
      });
      expect(stricter.map((r) => r.jobId)).toEqual(["borderline"]);
      const lenient = await findStaleRunningJobs(store, {
        heartbeatIntervalSeconds: 5,
        staleMultiplier: 3,
        now: () => baseMs,
      });
      expect(lenient).toHaveLength(0);
    });

    it("ignores records whose lastSeenAt is unparseable", async () => {
      const store = variant.make();
      await store.set("bad-ts", makeRecord("bad-ts", { lastSeenAt: "not-a-date" }), 600);
      const reports = await findStaleRunningJobs(store, {
        heartbeatIntervalSeconds: 5,
      });
      expect(reports.find((r) => r.jobId === "bad-ts")).toBeUndefined();
    });
  });
}
