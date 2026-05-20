/**
 * End-to-end batch-route tests parameterized over both JobStore
 * implementations.
 *
 * Same Hono app, same request shapes, same expected responses —
 * regardless of whether the underlying state lives in a Map or in a
 * RedisLike fake. If a future refactor breaks the contract on one
 * implementation, this suite catches it.
 *
 * The Redis half uses the same `FakeRedis` shim as `redis.test.ts`
 * (duplicated here to keep test files independent — under 100 lines so
 * the cost is small).
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import {
  createTestApp,
  generateTestKey,
  type TestKeyPair,
} from "./helpers.js";
import {
  setJobStore,
  __resetBatchStateForTesting,
} from "../routes/batch.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { MemoryJobStore } from "../batch/job-store/memory.js";
import { RedisJobStore, type RedisLike } from "../batch/job-store/redis.js";
import type { Hono } from "hono";

// ---------------------------------------------------------------------------
// Inline FakeRedis (kept independent of redis.test.ts so each file owns its
// own fake)
// ---------------------------------------------------------------------------

interface FakeEntry {
  value: string;
  expiresAt: number;
}

class FakeRedis implements RedisLike {
  public data = new Map<string, FakeEntry>();
  public status = "ready";

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(
    key: string,
    value: string,
    _mode: "EX",
    ttlSeconds: number,
  ): Promise<"OK" | null> {
    this.data.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
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
    const now = Date.now();
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
// Test matrix
// ---------------------------------------------------------------------------

const stores = [
  {
    name: "MemoryJobStore",
    make() {
      return new MemoryJobStore({ purgeIntervalMs: 0 });
    },
  },
  {
    name: "RedisJobStore (against in-process fake)",
    make() {
      return new RedisJobStore({ client: new FakeRedis() });
    },
  },
] as const;

for (const variant of stores) {
  describe(`POST /credentials/batch — ${variant.name}`, () => {
    let app: Hono;
    let testKey: TestKeyPair;

    beforeAll(() => {
      testKey = generateTestKey();
    });

    beforeEach(() => {
      app = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);
      __resetBatchStateForTesting();
      setJobStore(variant.make());
    });

    const csv = (rows: number) => {
      const header = "name,role,validFrom";
      const lines = Array.from(
        { length: rows },
        (_, i) => `Alice${i},Medical Practitioner,2025-06-01T00:00:00Z`,
      );
      return [header, ...lines].join("\n");
    };

    async function startBatch(rows: number): Promise<{ jobId: string }> {
      const res = await app.request("/credentials/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          csvContent: csv(rows),
          schemaId: "functional-identity/v1",
          issuerDid: testKey.signer.id.split("#")[0],
          validFrom: "2025-06-01T00:00:00Z",
          proofFormat: "vc-jwt",
        }),
      });
      expect(res.status).toBe(202);
      const body = (await res.json()) as { jobId: string };
      return body;
    }

    it("returns a jobId in the 202 response", async () => {
      const { jobId } = await startBatch(2);
      expect(typeof jobId).toBe("string");
      expect(jobId.length).toBeGreaterThan(0);
    });

    it("GET /credentials/batch/:jobId returns progress and converges to completed", async () => {
      const { jobId } = await startBatch(2);

      // Poll until completed (cap at ~2s so a slow CI doesn't hang).
      let body: Record<string, unknown> = {};
      for (let i = 0; i < 40; i += 1) {
        await new Promise((r) => setTimeout(r, 50));
        const res = await app.request(`/credentials/batch/${jobId}`);
        expect(res.status).toBe(200);
        body = (await res.json()) as Record<string, unknown>;
        if (body.status === "completed") break;
      }
      expect(body.status).toBe("completed");
      expect(body.total).toBe(2);
      expect(body.completed).toBe(2);
    });

    it("GET /credentials/batch/:jobId/results returns the row outputs after completion", async () => {
      const { jobId } = await startBatch(2);

      for (let i = 0; i < 40; i += 1) {
        await new Promise((r) => setTimeout(r, 50));
        const res = await app.request(`/credentials/batch/${jobId}`);
        const body = (await res.json()) as { status: string };
        if (body.status === "completed") break;
      }

      const res = await app.request(`/credentials/batch/${jobId}/results`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { results: Array<{ status: string }> };
      expect(body.results).toHaveLength(2);
      for (const r of body.results) expect(r.status).toBe("success");
    });

    it("returns 404 for an unknown jobId", async () => {
      const res = await app.request("/credentials/batch/00000000-0000-0000-0000-000000000000");
      expect(res.status).toBe(404);
    });
  });
}

// ---------------------------------------------------------------------------
// Cross-instance read — simulates Replica B answering for Replica A's job
// ---------------------------------------------------------------------------
//
// Two `RedisJobStore` instances share the same `FakeRedis` Map. Replica A
// (storeA) writes; Replica B (storeB) reads. We don't drive a full Hono
// app for both because the route currently couples engine state to the
// local replica — the contract this test asserts is the JobStore layer
// the route depends on.

describe("RedisJobStore — cross-replica visibility (route-level integration sketch)", () => {
  it("replica B can observe a record written by replica A", async () => {
    const fake = new FakeRedis();
    const storeA = new RedisJobStore({ client: fake });
    const storeB = new RedisJobStore({ client: fake });

    await storeA.set(
      "abc",
      {
        jobId: "abc",
        status: "running",
        progress: null,
        createdAt: new Date().toISOString(),
        ownerReplica: "host-A:42",
      },
      60,
    );

    const onB = await storeB.get("abc");
    expect(onB?.jobId).toBe("abc");
    expect(onB?.ownerReplica).toBe("host-A:42");
  });
});
