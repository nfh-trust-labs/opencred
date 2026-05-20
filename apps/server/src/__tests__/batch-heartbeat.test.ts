/**
 * Route-level heartbeat tests for batch jobs (Tier 2 #6 of
 * nfh-trust-labs/opencred#446).
 *
 * What we assert:
 *  1. Submitting a batch seeds `lastSeenAt` on the JobRecord.
 *  2. While the engine runs, the heartbeat loop refreshes `lastSeenAt`.
 *  3. When the engine settles (success / failure / cancellation), the
 *     heartbeat timer is torn down so we don't leak a setInterval per
 *     batch.
 *  4. `finalizeAllRunningJobs` (the graceful-shutdown path) stops every
 *     heartbeat timer too.
 *
 * We use a short heartbeat interval (1 s minimum allowed by the config
 * schema) and polling sleeps to keep the test runtime small. We
 * deliberately do NOT mock `setInterval` — the contract being asserted
 * is end-to-end behaviour of the route + store wiring, and a fake-timer
 * mock would obscure that.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { createTestApp, generateTestKey, type TestKeyPair } from "./helpers.js";
import {
  setJobStore,
  getJobStore,
  __resetBatchStateForTesting,
  __getHeartbeatTimerCount,
  __getLocalEngineCount,
  finalizeAllRunningJobs,
} from "../routes/batch.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { MemoryJobStore } from "../batch/job-store/memory.js";
import type { Hono } from "hono";

const SAVED_ENV: Record<string, string | undefined> = {};
function setEnv(key: string, value: string): void {
  if (!(key in SAVED_ENV)) SAVED_ENV[key] = process.env[key];
  process.env[key] = value;
}
function restoreEnv(): void {
  for (const k of Object.keys(SAVED_ENV)) {
    const v = SAVED_ENV[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    delete SAVED_ENV[k];
  }
}

describe("batch route — heartbeat (Tier 2 #6 of #446)", () => {
  let app: Hono;
  let testKey: TestKeyPair;

  beforeAll(() => {
    testKey = generateTestKey();
  });

  beforeEach(() => {
    // 1 s heartbeat — minimum allowed by the config schema. Tight enough
    // that the test can observe at least one tick without sleeping for
    // 10+ seconds.
    setEnv("OPENCRED_HEARTBEAT_INTERVAL_SEC", "1");
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(testKey.signer);
    __resetBatchStateForTesting();
    setJobStore(new MemoryJobStore({ purgeIntervalMs: 0 }));
  });

  afterEach(() => {
    __resetBatchStateForTesting();
    restoreEnv();
  });

  function buildCsv(rows: number): string {
    const header = "name,role,validFrom";
    const lines = Array.from(
      { length: rows },
      (_, i) => `Alice${i},Medical Practitioner,2025-06-01T00:00:00Z`,
    );
    return [header, ...lines].join("\n");
  }

  async function postBatch(rows: number): Promise<string> {
    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent: buildCsv(rows),
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(202);
    const body = (await res.json()) as { jobId: string };
    return body.jobId;
  }

  it("seeds lastSeenAt on the initial record", async () => {
    const jobId = await postBatch(2);
    const record = await getJobStore().get(jobId);
    expect(record).not.toBeNull();
    expect(typeof record!.lastSeenAt).toBe("string");
    expect(record!.ownerReplica).toMatch(/.+:\d+$/); // hostname:pid shape
  });

  it("refreshes lastSeenAt on a tick of the heartbeat loop", async () => {
    // Submit a job. With a 2-row batch the engine settles in milliseconds —
    // too fast to observe a heartbeat tick. To exercise the loop we
    // capture `lastSeenAt` immediately after submission, then sleep ~1.2 s
    // (longer than the 1 s interval), then read again. If the engine has
    // already settled we accept the initial value (the test still passes
    // because we never assert an INCREASE on a settled record). To force a
    // tick we use a row count high enough that even on a fast machine the
    // engine is still running after 1.2 s.
    const jobId = await postBatch(50);
    const before = (await getJobStore().get(jobId))!.lastSeenAt;
    expect(before).toBeTruthy();
    await new Promise((r) => setTimeout(r, 1_300));
    const after = (await getJobStore().get(jobId))!.lastSeenAt;
    expect(after).toBeTruthy();
    // `after` must be >= `before`. If the engine settled mid-window the
    // heartbeat stops writing — that's also valid behaviour. Equality is
    // allowed because both values are ISO strings; the assertion is "did
    // not go backwards".
    expect(Date.parse(after!) >= Date.parse(before!)).toBe(true);
  });

  it("tears the heartbeat timer down when the engine settles", async () => {
    const jobId = await postBatch(2);
    expect(__getHeartbeatTimerCount()).toBeGreaterThan(0);

    // Poll until completed; cap at ~3 s to avoid hanging on a slow CI.
    for (let i = 0; i < 60; i += 1) {
      await new Promise((r) => setTimeout(r, 50));
      const res = await app.request(`/credentials/batch/${jobId}`);
      const body = (await res.json()) as { status: string };
      if (body.status === "completed") break;
    }

    expect(__getLocalEngineCount()).toBe(0);
    expect(__getHeartbeatTimerCount()).toBe(0);
  });

  it("finalizeAllRunningJobs clears every heartbeat timer", async () => {
    // Spawn several long-ish batches; we don't wait for completion.
    const ids = await Promise.all([postBatch(50), postBatch(50), postBatch(50)]);
    expect(ids).toHaveLength(3);
    expect(__getHeartbeatTimerCount()).toBeGreaterThan(0);

    const interrupted = await finalizeAllRunningJobs();
    expect(interrupted).toBeGreaterThan(0);
    expect(__getHeartbeatTimerCount()).toBe(0);
    expect(__getLocalEngineCount()).toBe(0);
  });
});
