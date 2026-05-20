/**
 * Batch job TTL tests.
 *
 * Pre-Tier-2 these tests exercised the inline `purgeExpiredBatchJobs`
 * helper on the in-process Map. After Tier 2 #5 (PR for nfh-trust-labs/opencred#446
 * sub-issue) the equivalent behaviour lives on `MemoryJobStore` — the
 * `set()`/`get()` contract MUST return null once the entry's TTL is
 * past, and `purge()` is the bulk sweep used by the internal interval.
 *
 * The Redis path uses Redis-managed TTL (`SET ... EX`) and is exercised
 * in `job-store/__tests__/redis.test.ts` against a `RedisLike` mock.
 */

import { describe, it, expect } from "vitest";
import { MemoryJobStore } from "../batch/job-store/memory.js";
import type { JobRecord } from "../batch/job-store/types.js";

function makeRecord(jobId: string, status: JobRecord["status"] = "completed"): JobRecord {
  return {
    jobId,
    status,
    progress: null,
    createdAt: new Date(0).toISOString(),
  };
}

describe("MemoryJobStore TTL", () => {
  it("returns the record while it is within ttl", async () => {
    let now = 1_000_000;
    const store = new MemoryJobStore({ now: () => now, purgeIntervalMs: 0 });
    await store.set("job-1", makeRecord("job-1"), 60);
    now += 30_000; // 30 s — still within 60 s TTL
    expect(await store.get("job-1")).not.toBeNull();
  });

  it("returns null once the entry's ttl elapses", async () => {
    let now = 1_000_000;
    const store = new MemoryJobStore({ now: () => now, purgeIntervalMs: 0 });
    await store.set("job-1", makeRecord("job-1"), 60);
    now += 60_001; // 60.001 s — past TTL
    expect(await store.get("job-1")).toBeNull();
  });

  it("purge() evicts every expired entry and reports the count", async () => {
    let now = 1_000_000;
    const store = new MemoryJobStore({ now: () => now, purgeIntervalMs: 0 });

    await store.set("expired-1", makeRecord("expired-1"), 10);
    await store.set("expired-2", makeRecord("expired-2"), 10);
    await store.set("fresh", makeRecord("fresh"), 600);

    now += 11_000; // 11 s — expired-* are past 10 s TTL, fresh is well within 600 s
    const deleted = store.purge();

    expect(deleted).toBe(2);
    expect(await store.get("expired-1")).toBeNull();
    expect(await store.get("expired-2")).toBeNull();
    expect(await store.get("fresh")).not.toBeNull();
  });

  it("update() re-arms the TTL on each successful write", async () => {
    let now = 1_000_000;
    const store = new MemoryJobStore({ now: () => now, purgeIntervalMs: 0 });
    await store.set("job-1", makeRecord("job-1"), 60);

    // Advance to just before TTL, then update → expect another full 60s.
    now += 55_000;
    const updated = await store.update(
      "job-1",
      (cur) => ({ ...cur, status: "running" }),
      60,
    );
    expect(updated).not.toBeNull();
    expect(updated?.status).toBe("running");

    // 55s after the update → still well within the renewed TTL.
    now += 55_000;
    expect(await store.get("job-1")).not.toBeNull();
  });

  it("update() on a missing record returns null and does not write", async () => {
    const store = new MemoryJobStore({ purgeIntervalMs: 0 });
    const out = await store.update("missing", (cur) => cur, 60);
    expect(out).toBeNull();
  });

  it("list() filters by status and skips expired entries", async () => {
    let now = 1_000_000;
    const store = new MemoryJobStore({ now: () => now, purgeIntervalMs: 0 });
    await store.set("queued-1", makeRecord("queued-1", "queued"), 600);
    await store.set("running-1", makeRecord("running-1", "running"), 600);
    await store.set("expired", makeRecord("expired", "completed"), 5);

    now += 6_000; // expired is past TTL
    const queued = await store.list({ status: "queued" });
    expect(queued.map((s) => s.jobId)).toEqual(["queued-1"]);

    const all = await store.list();
    expect(all.map((s) => s.jobId).sort()).toEqual(["queued-1", "running-1"]);
  });

  it("close() clears the internal timer and the in-memory map", async () => {
    const store = new MemoryJobStore();
    await store.set("job-1", makeRecord("job-1"), 60);
    await store.close();
    expect(await store.get("job-1")).toBeNull();
  });

  it("structural cloning prevents callers from mutating stored state", async () => {
    const store = new MemoryJobStore({ purgeIntervalMs: 0 });
    const record = makeRecord("job-1", "running");
    await store.set("job-1", record, 60);
    const fetched = await store.get("job-1");
    expect(fetched).not.toBeNull();
    if (!fetched) throw new Error("unreachable");
    // Mutate the fetched copy — must not affect the stored entry.
    fetched.status = "failed";
    const refetched = await store.get("job-1");
    expect(refetched?.status).toBe("running");
  });
});
