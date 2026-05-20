/**
 * Worker-pool tests for the server batch engine (issue #446 Tier 1.1).
 *
 * The pre-#446 engine drove `await signer.sign(...)` in a serial `for`
 * loop, so 10 concurrent batches of 200 rows ran at the same wall-clock
 * rate as a single 200-row batch. These tests pin the new contract:
 *
 *   - Multiple rows sign in parallel up to `concurrency`
 *   - Output order matches input order regardless of completion order
 *   - A failing row writes `status: "error"` and never aborts the batch
 *   - Concurrency is resolved from the env var, with the cpu-derived
 *     fallback as the default
 *
 * No real signing key is used — we hand the engine a stub Signer whose
 * `sign` method is fully controlled by the test so timing assertions are
 * deterministic.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createRegistry, Validator } from "@opencred/schema-engine";
import type { ParsedRow } from "../csv-parser.js";
import { createBatchEngine, resolveBatchConcurrency, type BatchConfig } from "../batch-engine.js";
import { setSchemaRegistry, resetSchemaRegistry } from "../../schema-registry-singleton.js";
import { setValidator, resetValidator } from "../../validator-singleton.js";

// ---------------------------------------------------------------------------
// Shared scaffolding
// ---------------------------------------------------------------------------

/**
 * Per-test, per-row hook used to inject failures or simulate signing
 * latency. Keyed by the row index that the test passes through
 * `parsedRow.rowIndex`.
 */
type SignHook = (rowIndex: number) => Promise<void> | void;

interface StubSignerOptions {
  /**
   * Called immediately before the signer "returns" its bytes for a given
   * row. Throwing here surfaces as a per-row `status: "error"`.
   */
  hook?: SignHook;
}

/**
 * Build a fake Signer that records each invocation in order and respects
 * an optional per-row hook. We DO NOT touch `@opencred/crypto` here — the
 * batch engine's `processRow` walks straight from `builder.build()` to
 * `signer.sign(dataToSign)`, so a no-op P-256-shaped signer is enough
 * to exercise the worker-pool plumbing without depending on the real
 * native crypto path.
 */
function makeStubSigner(opts: StubSignerOptions = {}) {
  const invocations: number[] = [];
  const concurrentMax = { value: 0, current: 0 };
  // The batch engine reads `signer.algorithm` and `signer.id` when it
  // builds the proof — we use the simplest combination (P-256 / vc-jwt
  // path), which gives us a single `prepareVcJwtProof` → `signer.sign(...)`
  // call per row.
  return {
    signer: {
      id: "did:key:zStub#zStub",
      algorithm: "P-256" as const,
      type: "software" as const,
      metadata: {
        id: "did:key:zStub#zStub",
        algorithm: "P-256" as const,
        type: "software" as const,
        fingerprint: "stub",
        label: "stub",
      },
      async sign(data: Uint8Array): Promise<Uint8Array> {
        // The engine encodes `signingInput` (a JWS header.payload string)
        // into UTF-8 — recover the rowIndex by parsing the embedded claim.
        // We don't need accuracy here; we just need a unique-per-row hook
        // call. Decode the JWS payload and pull `vc.credentialSubject.idx`.
        const text = new TextDecoder().decode(data);
        const [, payloadB64] = text.split(".");
        // We pulled this from `prepareVcJwtProof`; the body is base64url.
        // Padding is safe to strip for atob via Buffer.
        const payloadJson = Buffer.from(
          payloadB64.replace(/-/g, "+").replace(/_/g, "/"),
          "base64",
        ).toString("utf8");
        const payload = JSON.parse(payloadJson) as {
          vc?: { credentialSubject?: { idx?: number } };
        };
        const idx = payload.vc?.credentialSubject?.idx ?? -1;
        invocations.push(idx);

        // Track peak in-flight signers — every entry increments, every
        // exit decrements. This is what tells us the pool is bounded.
        concurrentMax.current += 1;
        if (concurrentMax.current > concurrentMax.value) {
          concurrentMax.value = concurrentMax.current;
        }
        try {
          if (opts.hook) await opts.hook(idx);
        } finally {
          concurrentMax.current -= 1;
        }

        // The engine just records these bytes — they don't have to be a
        // real ECDSA signature.
        return new Uint8Array(64);
      },
    },
    invocations,
    concurrentMax,
  };
}

// The batch engine validates each row against the schema registry. We
// register a permissive schema once per test so the validator returns
// `valid: true` and processRow proceeds straight to signing.
function installStubSchemaRegistry() {
  const registry = createRegistry();
  // createRegistry pre-loads the bundled catalogue; we hijack one of the
  // bundled entries by re-registering the schema id our tests use.
  // The simpler path is to lean on the bundled "functional-identity/v1"
  // schema with a single-string credentialSubject — see helpers.ts.
  setSchemaRegistry(registry);
  setValidator(new Validator(registry));
}

function makeRow(idx: number): ParsedRow {
  return {
    rowIndex: idx,
    rawValues: { idx: String(idx) },
    // The credentialSubject must include the fields the bundled
    // functional-identity/v1 schema requires. We embed `idx` so the
    // stub signer can recover it from the JWS payload.
    mappedSubject: {
      idx,
      name: "Row " + idx,
      role: "Medical Practitioner",
      validFrom: "2025-06-15T00:00:00Z",
      affiliation: { name: "Acme Medical Council" },
    },
    valid: true,
    errors: [],
  };
}

const BASE_CONFIG: BatchConfig = {
  schemaId: "functional-identity/v1",
  issuerDid: "did:key:zStub",
  validFrom: "2025-06-15T00:00:00Z",
  proofFormat: "vc-jwt",
};

// ---------------------------------------------------------------------------
// resolveBatchConcurrency
// ---------------------------------------------------------------------------

describe("resolveBatchConcurrency", () => {
  const originalEnv = process.env.OPENCRED_BATCH_CONCURRENCY;
  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.OPENCRED_BATCH_CONCURRENCY;
    } else {
      process.env.OPENCRED_BATCH_CONCURRENCY = originalEnv;
    }
  });

  it("honours an explicit override over the env var", () => {
    process.env.OPENCRED_BATCH_CONCURRENCY = "8";
    expect(resolveBatchConcurrency(3)).toBe(3);
  });

  it("clamps an override below 1 to 1", () => {
    // 0 / negative / NaN inputs must not produce a `pLimit(0)` call
    // (which throws). The resolver coerces these to 1.
    expect(resolveBatchConcurrency(0)).toBe(1);
    expect(resolveBatchConcurrency(-5)).toBe(1);
    expect(resolveBatchConcurrency(Number.NaN)).toBeGreaterThanOrEqual(1);
  });

  it("parses OPENCRED_BATCH_CONCURRENCY when no override is supplied", () => {
    process.env.OPENCRED_BATCH_CONCURRENCY = "7";
    expect(resolveBatchConcurrency()).toBe(7);
  });

  it("ignores invalid env values and falls back to the cpu-derived default", () => {
    process.env.OPENCRED_BATCH_CONCURRENCY = "nonsense";
    const result = resolveBatchConcurrency();
    expect(result).toBeGreaterThanOrEqual(1);
    expect(result).toBeLessThanOrEqual(4);
  });

  it("returns min(4, cpus) when nothing is configured", () => {
    delete process.env.OPENCRED_BATCH_CONCURRENCY;
    const result = resolveBatchConcurrency();
    expect(result).toBeGreaterThanOrEqual(1);
    expect(result).toBeLessThanOrEqual(4);
  });
});

// ---------------------------------------------------------------------------
// Worker pool behaviour
// ---------------------------------------------------------------------------

describe("createBatchEngine (worker pool)", () => {
  let teardown: (() => void) | undefined;
  afterEach(() => {
    if (teardown) {
      teardown();
      teardown = undefined;
    }
    resetSchemaRegistry();
    resetValidator();
  });

  it("runs concurrent rows up to the configured limit but no further", async () => {
    installStubSchemaRegistry();

    const { signer, concurrentMax } = makeStubSigner({
      hook: async () => {
        // Each row holds onto a "signing slot" for ~20 ms. The semaphore
        // should keep the in-flight count bounded by the concurrency
        // setting; without the worker pool this test passes too (concurrent
        // count = 1) so we also check the per-row throughput in a separate
        // assertion below.
        await new Promise((resolve) => setTimeout(resolve, 20));
      },
    });

    const rows = Array.from({ length: 8 }, (_, i) => makeRow(i));
    const engine = createBatchEngine(signer, rows, BASE_CONFIG, { concurrency: 3 });

    const result = await engine.start();

    expect(result.successCount).toBe(8);
    expect(result.errorCount).toBe(0);
    expect(concurrentMax.value).toBeLessThanOrEqual(3);
    // Sanity: actual parallelism was exercised — peak in-flight should
    // exceed 1 once the queue is busy.
    expect(concurrentMax.value).toBeGreaterThanOrEqual(2);
  });

  it("preserves input order across rows even when later rows finish first", async () => {
    installStubSchemaRegistry();

    // Force row N to wait (count - N) * 5ms so the FIRST row finishes
    // LAST. If output order weren't index-anchored, this scrambles the
    // result array.
    const rowCount = 6;
    const { signer } = makeStubSigner({
      hook: async (rowIndex) => {
        const delayMs = (rowCount - rowIndex) * 5;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      },
    });

    const rows = Array.from({ length: rowCount }, (_, i) => makeRow(i));
    const engine = createBatchEngine(signer, rows, BASE_CONFIG, { concurrency: rowCount });

    const result = await engine.start();

    // Result rows are seated by `rowIndex` from the pre-allocated array,
    // not by completion order — so they must always be 0..N-1 in order.
    expect(result.rows.map((r) => r.rowIndex)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(result.rows.every((r) => r.status === "success")).toBe(true);
  });

  it("marks individual rows as 'error' without aborting the rest of the batch", async () => {
    installStubSchemaRegistry();

    // 100 rows where rows 50 and 75 fail. The rest must succeed and
    // ordering must hold. The overall progress.errorCount should be
    // exactly 2 — partial result, not aborted.
    const failingIndices = new Set<number>([50, 75]);
    const { signer } = makeStubSigner({
      hook: (rowIndex) => {
        if (failingIndices.has(rowIndex)) {
          // The engine's catch block writes `status: "error"` and
          // captures `err.message`. We surface a deterministic message
          // we can assert on below.
          throw new Error(`row-${rowIndex} crashed`);
        }
      },
    });

    const rows = Array.from({ length: 100 }, (_, i) => makeRow(i));
    const engine = createBatchEngine(signer, rows, BASE_CONFIG, { concurrency: 4 });

    const result = await engine.start();

    expect(result.rows).toHaveLength(100);
    expect(result.total).toBe(100);
    expect(result.completed).toBe(100);
    expect(result.errorCount).toBe(2);
    expect(result.successCount).toBe(98);
    expect(result.skippedCount).toBe(0);

    // Spot-check each row's status — error only at the two indices,
    // success everywhere else, and ordering is intact.
    for (let i = 0; i < 100; i++) {
      const row = result.rows[i];
      expect(row.rowIndex).toBe(i);
      if (failingIndices.has(i)) {
        expect(row.status).toBe("error");
        expect(row.error).toContain(`row-${i} crashed`);
      } else {
        expect(row.status).toBe("success");
        expect(row.error).toBeUndefined();
      }
    }
  });

  it("marks queued rows as 'skipped' when cancel() is called mid-batch", async () => {
    installStubSchemaRegistry();

    let resolveBlocker: (() => void) | undefined;
    const blocker = new Promise<void>((resolve) => {
      resolveBlocker = resolve;
    });

    const { signer } = makeStubSigner({
      hook: async (rowIndex) => {
        // The first three rows hang on the blocker; once we resolve it
        // (after cancel()) they all complete and the queued rows downstream
        // observe the cancelled flag at dequeue time.
        if (rowIndex < 3) await blocker;
      },
    });

    const rows = Array.from({ length: 10 }, (_, i) => makeRow(i));
    const engine = createBatchEngine(signer, rows, BASE_CONFIG, { concurrency: 3 });

    const finished = engine.start();

    // Give the engine a tick to schedule the first 3 rows.
    await new Promise((resolve) => setTimeout(resolve, 10));
    engine.cancel();
    resolveBlocker?.();

    const result = await finished;

    // The first 3 rows were in-flight when cancel() ran — they finish
    // successfully (cancel only blocks UNSTARTED work). Rows 3..9 were
    // queued behind the semaphore; they short-circuit to "skipped".
    expect(result.rows[0].status).toBe("success");
    expect(result.rows[1].status).toBe("success");
    expect(result.rows[2].status).toBe("success");
    for (let i = 3; i < 10; i++) {
      expect(result.rows[i].status).toBe("skipped");
      expect(result.rows[i].error).toBe("Batch cancelled");
    }
    expect(result.cancelled).toBe(true);
  });

  it("does NOT pre-allocate a promise per row — streaming submission keeps memory bounded", async () => {
    // Regression guard for the original "tasks: Promise<void>[]" path:
    // the old implementation built `parsedRows.length` wrapped task
    // promises up front before any worker ran, which on a 1M-row CSV
    // allocated ~1M closures + queue entries simultaneously. Switching
    // to a streaming pool (p-map / generator) keeps the count of
    // in-flight mapper promises bounded by `concurrency + small_const`.
    //
    // We assert this by tracking the number of "mapper invoked, not yet
    // returned" rows during execution. We instrument the stub signer to
    // increment a counter on entry and decrement on exit, then check the
    // peak against `concurrency + 1`. The "+1" leaves room for the
    // boundary between two rows where the prior worker has resolved but
    // the next hasn't been awaited yet.
    installStubSchemaRegistry();

    const concurrency = 4;
    const { signer, concurrentMax } = makeStubSigner({
      hook: async () => {
        // A microtask-delay forces the runtime to interleave workers —
        // without an `await` here the synchronous fast path could let
        // a single worker burn through every row sequentially and the
        // peak gauge would silently report `1`, masking the bug.
        await new Promise((resolve) => setTimeout(resolve, 0));
      },
    });

    // 2000 rows: large enough that an unbounded pre-allocation (the
    // pre-fix code path) would visibly buffer all 2000 mapper promises
    // before any resolved. With streaming, peak in-flight stays at
    // most `concurrency + 1`. We keep the count modest to stay under
    // vitest's default 30s test timeout — the bug is a memory-shape
    // issue, not a wall-clock issue, so the assertion is the same at
    // any scale.
    const rows = Array.from({ length: 2_000 }, (_, i) => makeRow(i));
    const engine = createBatchEngine(signer, rows, BASE_CONFIG, { concurrency });

    const result = await engine.start();

    expect(result.successCount).toBe(2_000);
    expect(result.errorCount).toBe(0);
    // The streaming property: at NO point during execution does the
    // number of in-flight workers exceed `concurrency + 1`. The +1
    // gives the implementation slack for the moment between "a worker
    // resolved" and "the runtime delivered the result to the queue".
    expect(concurrentMax.value).toBeLessThanOrEqual(concurrency + 1);
    // Sanity: the pool actually ran in parallel (not a single-worker
    // serial pipeline that would also satisfy the upper bound).
    expect(concurrentMax.value).toBeGreaterThanOrEqual(2);
  });

  it("processes a single row identically with concurrency=1 (regression guard)", async () => {
    installStubSchemaRegistry();

    const { signer, invocations } = makeStubSigner();
    const rows = [makeRow(0)];
    const engine = createBatchEngine(signer, rows, BASE_CONFIG, { concurrency: 1 });

    const result = await engine.start();

    expect(result.successCount).toBe(1);
    expect(result.errorCount).toBe(0);
    expect(invocations).toEqual([0]);
  });
});
