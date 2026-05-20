/**
 * RedisJobStore unit tests.
 *
 * These tests run against an in-process `RedisLike` fake — not a real
 * Redis. The fake implements only the commands we use (GET / SET EX /
 * DEL / SCAN MATCH / QUIT) and respects TTL via a synthesized clock.
 *
 * Why not `ioredis-mock`? It would be a 1MB+ devDependency just to
 * cover four commands. The fake here is ~80 lines, exercises the same
 * code paths, and lets each test drive the clock deterministically.
 *
 * For end-to-end cross-replica behaviour we share a single fake between
 * two `RedisJobStore` instances so a write from one and a read from the
 * other land on the same shared map — that's the closest unit-test
 * stand-in for the "Replica A writes, Replica B reads" production path.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { RedisJobStore, type RedisLike } from "../redis.js";
import type { JobRecord } from "../types.js";

// ---------------------------------------------------------------------------
// Fake Redis
// ---------------------------------------------------------------------------

interface FakeEntry {
  value: string;
  expiresAt: number;
}

class FakeRedis implements RedisLike {
  private readonly data = new Map<string, FakeEntry>();
  public status: string = "ready";
  public quitCalls = 0;
  public disconnectCalls = 0;
  public failNextSet = false;

  constructor(private now: () => number = () => Date.now()) {}

  /** Convenience for tests — advance the synthetic clock. */
  setClock(now: () => number): void {
    this.now = now;
  }

  /** Convenience for cross-replica tests — share the same Map between fakes. */
  static linked(): { a: FakeRedis; b: FakeRedis } {
    const a = new FakeRedis();
    const b = new FakeRedis();
    // Share storage: assign b.data → a.data so both instances see the
    // same entries. The clocks remain independent (each fake's `now`).
    Object.assign(b, { data: (a as unknown as { data: Map<string, FakeEntry> }).data });
    return { a, b };
  }

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(
    key: string,
    value: string,
    _expireMode: "EX",
    ttlSeconds: number,
  ): Promise<"OK" | null> {
    if (this.failNextSet) {
      this.failNextSet = false;
      throw new Error("simulated SET failure");
    }
    this.data.set(key, {
      value,
      expiresAt: this.now() + ttlSeconds * 1000,
    });
    return "OK";
  }

  async del(...keys: string[]): Promise<number> {
    let n = 0;
    for (const k of keys) {
      if (this.data.delete(k)) n += 1;
    }
    return n;
  }

  async scan(
    cursor: string | number,
    _matchOption: "MATCH",
    pattern: string,
    _countOption: "COUNT",
    _count: number,
  ): Promise<[string, string[]]> {
    // Single-shot scan — the fake doesn't honour cursor; the real Redis
    // does, but for our tests the dataset is < 100 keys so a one-page
    // response is equivalent.
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
    this.quitCalls += 1;
    return "OK";
  }

  disconnect(): void {
    this.disconnectCalls += 1;
  }
}

function makeRecord(jobId: string, overrides: Partial<JobRecord> = {}): JobRecord {
  return {
    jobId,
    status: "queued",
    progress: null,
    createdAt: new Date(1_000_000).toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Basic CRUD
// ---------------------------------------------------------------------------

describe("RedisJobStore — basic CRUD", () => {
  let clock = 0;
  let fake: FakeRedis;
  let store: RedisJobStore;

  beforeEach(() => {
    clock = 1_000_000;
    fake = new FakeRedis(() => clock);
    store = new RedisJobStore({ client: fake });
  });

  it("set then get round-trips a record", async () => {
    await store.set("job-1", makeRecord("job-1"), 60);
    const out = await store.get("job-1");
    expect(out).not.toBeNull();
    expect(out?.jobId).toBe("job-1");
    expect(out?.status).toBe("queued");
  });

  it("get returns null for an unknown id", async () => {
    expect(await store.get("missing")).toBeNull();
  });

  it("delete removes the key", async () => {
    await store.set("job-1", makeRecord("job-1"), 60);
    await store.delete("job-1");
    expect(await store.get("job-1")).toBeNull();
  });

  it("rejects ttlSeconds <= 0 to mirror Redis SETEX semantics", async () => {
    await expect(store.set("job-1", makeRecord("job-1"), 0)).rejects.toThrow(/ttlSeconds/);
    await expect(store.set("job-1", makeRecord("job-1"), -5)).rejects.toThrow(/ttlSeconds/);
  });
});

// ---------------------------------------------------------------------------
// TTL
// ---------------------------------------------------------------------------

describe("RedisJobStore — TTL", () => {
  it("returns null after the TTL elapses", async () => {
    let clock = 1_000_000;
    const fake = new FakeRedis(() => clock);
    const store = new RedisJobStore({ client: fake });
    await store.set("job-1", makeRecord("job-1"), 60);
    clock += 60_001;
    expect(await store.get("job-1")).toBeNull();
  });

  it("update() re-arms the TTL on each successful write", async () => {
    let clock = 1_000_000;
    const fake = new FakeRedis(() => clock);
    const store = new RedisJobStore({ client: fake });
    await store.set("job-1", makeRecord("job-1"), 60);
    clock += 55_000; // just before the original 60s TTL
    const updated = await store.update(
      "job-1",
      (cur) => ({ ...cur, status: "running" }),
      60,
    );
    expect(updated?.status).toBe("running");
    clock += 55_000; // 55s after the update — still inside the refreshed TTL
    expect(await store.get("job-1")).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Multi-instance (cross-replica)
// ---------------------------------------------------------------------------

describe("RedisJobStore — multi-instance", () => {
  it("a write from replica A is visible to a read from replica B", async () => {
    // Linked fakes share the same underlying Map — the closest stand-in
    // for "two ioredis clients pointed at the same server".
    const { a: fakeA, b: fakeB } = FakeRedis.linked();
    const storeA = new RedisJobStore({ client: fakeA });
    const storeB = new RedisJobStore({ client: fakeB });

    await storeA.set("job-1", makeRecord("job-1", { ownerReplica: "host-A:42" }), 600);
    const read = await storeB.get("job-1");
    expect(read).not.toBeNull();
    expect(read?.ownerReplica).toBe("host-A:42");
  });

  it("an update by replica A is observed by replica B on the next read", async () => {
    const { a: fakeA, b: fakeB } = FakeRedis.linked();
    const storeA = new RedisJobStore({ client: fakeA });
    const storeB = new RedisJobStore({ client: fakeB });

    await storeA.set("job-1", makeRecord("job-1"), 600);
    await storeA.update("job-1", (cur) => ({ ...cur, status: "running" }), 600);

    const read = await storeB.get("job-1");
    expect(read?.status).toBe("running");
  });
});

// ---------------------------------------------------------------------------
// Reconnect-on-disconnect / retry semantics
// ---------------------------------------------------------------------------

describe("RedisJobStore — retry semantics", () => {
  it("update() retries a transient SET failure and eventually succeeds", async () => {
    const fake = new FakeRedis();
    const store = new RedisJobStore({ client: fake });
    await store.set("job-1", makeRecord("job-1"), 60);

    // Cause the *first* SET inside the update loop to fail.
    fake.failNextSet = true;
    const out = await store.update(
      "job-1",
      (cur) => ({ ...cur, status: "running" }),
      60,
    );
    expect(out?.status).toBe("running");
  });

  it("update() surfaces a persistent SET failure rather than silently dropping it", async () => {
    const fake = new FakeRedis();
    const store = new RedisJobStore({ client: fake });
    await store.set("job-1", makeRecord("job-1"), 60);

    // Force every SET to fail. The store may retry, but eventually
    // throws — the caller decides whether to fall back.
    const setSpy = vi.spyOn(fake, "set").mockRejectedValue(new Error("connection lost"));
    await expect(
      store.update("job-1", (cur) => ({ ...cur, status: "running" }), 60),
    ).rejects.toThrow(/connection lost/);
    setSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// list() + delete() + close()
// ---------------------------------------------------------------------------

describe("RedisJobStore — list and close", () => {
  it("list returns a JobSummary for every live entry, optionally filtered by status", async () => {
    const fake = new FakeRedis();
    const store = new RedisJobStore({ client: fake });
    await store.set("a", makeRecord("a", { status: "queued" }), 60);
    await store.set("b", makeRecord("b", { status: "running" }), 60);
    await store.set("c", makeRecord("c", { status: "completed" }), 60);

    const all = await store.list();
    expect(all.map((s) => s.jobId).sort()).toEqual(["a", "b", "c"]);

    const onlyQueued = await store.list({ status: "queued" });
    expect(onlyQueued.map((s) => s.jobId)).toEqual(["a"]);
  });

  it("close() prefers quit(); falls back to disconnect() if quit throws", async () => {
    const fake = new FakeRedis();
    const store = new RedisJobStore({ client: fake });
    await store.close();
    expect(fake.quitCalls).toBe(1);
    expect(fake.disconnectCalls).toBe(0);
  });

  it("close() falls back to disconnect() when quit rejects", async () => {
    const fake = new FakeRedis();
    vi.spyOn(fake, "quit").mockRejectedValueOnce(new Error("socket dead"));
    const store = new RedisJobStore({ client: fake });
    await store.close();
    expect(fake.disconnectCalls).toBe(1);
  });

  it("operations after close() are no-ops or fail loudly", async () => {
    const fake = new FakeRedis();
    const store = new RedisJobStore({ client: fake });
    await store.close();

    // get/list are best-effort → null/empty
    expect(await store.get("anything")).toBeNull();
    expect(await store.list()).toEqual([]);

    // set must throw — silently swallowing a write would create a
    // post-shutdown ghost record visible to other replicas.
    await expect(store.set("job-1", makeRecord("job-1"), 60)).rejects.toThrow(/closed/);
  });
});

// ---------------------------------------------------------------------------
// Defensive parsing
// ---------------------------------------------------------------------------

describe("RedisJobStore — defensive parsing", () => {
  it("returns null when Redis hands back an unparseable JSON blob", async () => {
    const fake = new FakeRedis();
    const store = new RedisJobStore({ client: fake });
    // Inject a malformed key directly so we exercise the parse-error branch.
    await fake.set("opencred:job:bad", "not-json{", "EX", 60);
    expect(await store.get("bad")).toBeNull();
  });

  it("returns null when the stored record is missing required fields", async () => {
    const fake = new FakeRedis();
    const store = new RedisJobStore({ client: fake });
    await fake.set(
      "opencred:job:half",
      JSON.stringify({ jobId: "half" }), // missing status, createdAt
      "EX",
      60,
    );
    expect(await store.get("half")).toBeNull();
  });
});
