/**
 * Tests for the streaming batch engine (issue #446 Tier 2 #7).
 *
 * Companion to `batch-engine-concurrency.test.ts` which covers the
 * pre-existing array-input `createBatchEngine`. These tests pin the
 * behaviours that are SPECIFIC to the streaming variant:
 *
 *   - Rows are pulled from the AsyncIterable at the worker pool's rate
 *     (backpressure: producer pauses when concurrency saturates)
 *   - Output order matches input order regardless of completion order
 *   - Per-row error semantics: a row that throws records status="error"
 *     and never aborts the batch
 *   - The 100k-row memory-bound assertion required by the issue
 *     acceptance criteria
 */

import { describe, expect, it, afterEach } from "vitest";
import { createRegistry, Validator } from "@opencred/schema-engine";
import type { ParsedRow } from "../csv-parser.js";
import { createStreamingBatchEngine, type BatchConfig } from "../batch-engine.js";
import { setSchemaRegistry, resetSchemaRegistry } from "../../schema-registry-singleton.js";
import { setValidator, resetValidator } from "../../validator-singleton.js";

// ---------------------------------------------------------------------------
// Scaffolding (shares shape with batch-engine-concurrency.test.ts but
// rewired for the streaming engine's source-iterable contract)
// ---------------------------------------------------------------------------

type SignHook = (rowIndex: number) => Promise<void> | void;

interface StubSignerOptions {
  hook?: SignHook;
}

function makeStubSigner(opts: StubSignerOptions = {}) {
  const invocations: number[] = [];
  const concurrentMax = { value: 0, current: 0 };
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
        const text = new TextDecoder().decode(data);
        const [, payloadB64] = text.split(".");
        const payloadJson = Buffer.from(
          payloadB64.replace(/-/g, "+").replace(/_/g, "/"),
          "base64",
        ).toString("utf8");
        const payload = JSON.parse(payloadJson) as {
          vc?: { credentialSubject?: { idx?: number } };
        };
        const idx = payload.vc?.credentialSubject?.idx ?? -1;
        invocations.push(idx);

        concurrentMax.current += 1;
        if (concurrentMax.current > concurrentMax.value) {
          concurrentMax.value = concurrentMax.current;
        }
        try {
          if (opts.hook) await opts.hook(idx);
        } finally {
          concurrentMax.current -= 1;
        }

        return new Uint8Array(64);
      },
    },
    invocations,
    concurrentMax,
  };
}

function installStubSchemaRegistry() {
  const registry = createRegistry();
  setSchemaRegistry(registry);
  setValidator(new Validator(registry));
}

function makeRow(idx: number): ParsedRow {
  return {
    rowIndex: idx,
    rawValues: { idx: String(idx) },
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
// Streaming source helpers
// ---------------------------------------------------------------------------

/**
 * Async-iterable producer that emits a fixed number of valid rows. The
 * shape mirrors what the streaming CSV parser yields — the engine
 * doesn't care that the underlying source is synthesised here.
 */
async function* simpleSource(count: number): AsyncIterable<ParsedRow> {
  for (let i = 0; i < count; i++) {
    yield makeRow(i);
  }
}

/**
 * Source that instruments how many rows the engine has pulled. Used to
 * assert backpressure — when the worker pool is saturated, the engine
 * must NOT race ahead of the consumer.
 */
function instrumentedSource(count: number): {
  source: AsyncIterable<ParsedRow>;
  pulledRef: { value: number };
} {
  const pulledRef = { value: 0 };
  async function* gen(): AsyncIterable<ParsedRow> {
    for (let i = 0; i < count; i++) {
      pulledRef.value = i + 1;
      yield makeRow(i);
    }
  }
  return { source: gen(), pulledRef };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createStreamingBatchEngine", () => {
  afterEach(() => {
    resetSchemaRegistry();
    resetValidator();
  });

  it("processes every row in input order", async () => {
    installStubSchemaRegistry();
    const { signer, invocations } = makeStubSigner();
    const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
      source: simpleSource(8),
      concurrency: 1,
    });

    const result = await engine.start();

    expect(result.successCount).toBe(8);
    expect(result.errorCount).toBe(0);
    expect(result.skippedCount).toBe(0);
    expect(result.total).toBe(8);
    expect(invocations).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(result.rows.map((r) => r.rowIndex)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it("runs concurrent rows up to the configured limit but no further", async () => {
    installStubSchemaRegistry();
    const { signer, concurrentMax } = makeStubSigner({
      hook: async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
      },
    });
    const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
      source: simpleSource(8),
      concurrency: 3,
    });

    const result = await engine.start();

    expect(result.successCount).toBe(8);
    expect(concurrentMax.value).toBeLessThanOrEqual(3);
    expect(concurrentMax.value).toBeGreaterThanOrEqual(2);
  });

  it("marks individual rows as 'error' without aborting the rest of the batch", async () => {
    installStubSchemaRegistry();

    const failingIndices = new Set<number>([7, 11]);
    const { signer } = makeStubSigner({
      hook: (rowIndex) => {
        if (failingIndices.has(rowIndex)) {
          throw new Error(`row-${rowIndex} crashed`);
        }
      },
    });

    const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
      source: simpleSource(20),
      concurrency: 4,
    });

    const result = await engine.start();

    expect(result.total).toBe(20);
    expect(result.errorCount).toBe(2);
    expect(result.successCount).toBe(18);
    expect(result.skippedCount).toBe(0);

    for (const row of result.rows) {
      if (failingIndices.has(row.rowIndex)) {
        expect(row.status).toBe("error");
        expect(row.error).toContain(`row-${row.rowIndex} crashed`);
      } else {
        expect(row.status).toBe("success");
      }
    }
  });

  it("respects backpressure — pull rate tracks the worker drain rate", async () => {
    // Backpressure assertion: when the FIRST row arrives at the
    // mapper, the producer should NOT have raced ahead and pulled all
    // rows. With a streaming source + p-map, the producer is
    // suspended at each `yield` until the consumer takes the previous
    // value.
    //
    // We measure by recording `pulledRef.value` at the moment the
    // mapper enters processing for row 0. Under proper backpressure
    // this reads at most `concurrency` (the parallel `next()` chains
    // p-map kicks off at startup); without backpressure it would
    // read the full row count.
    installStubSchemaRegistry();

    const pullAtRow0 = { value: -1 };
    const { signer } = makeStubSigner({
      hook: async (rowIndex) => {
        if (rowIndex === 0 && pullAtRow0.value === -1) {
          // First time row 0 hits the signer — read the producer
          // cursor and freeze it. We then block long enough that
          // backpressure can't be masked by lucky scheduling.
          pullAtRow0.value = pulledRef.value;
        }
        await new Promise((resolve) => setTimeout(resolve, 5));
      },
    });

    const concurrency = 3;
    const { source, pulledRef } = instrumentedSource(50);
    const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
      source,
      concurrency,
    });

    const result = await engine.start();

    expect(result.successCount).toBe(50);
    // At the moment row 0 starts processing, p-map has launched
    // `concurrency` parallel `next()` chains — each of which has
    // pulled exactly one row. So the producer's pull count should
    // be `concurrency`, not 50.
    //
    // We assert `<= concurrency + 1` to leave room for the tiny
    // window where p-map's startup loop is mid-flight; the bug
    // signal would be `pullAtRow0 === 50`.
    expect(pullAtRow0.value).toBeGreaterThan(0);
    expect(pullAtRow0.value).toBeLessThanOrEqual(concurrency + 1);
  });

  it("preserves the parser-assigned rowIndex on every result row", async () => {
    installStubSchemaRegistry();
    const { signer } = makeStubSigner();

    // Synthesise rows with non-sequential rowIndex values — the engine
    // must record whatever the parser handed it, not re-number on
    // arrival order.
    async function* skipping(): AsyncIterable<ParsedRow> {
      for (const i of [0, 2, 5, 100, 999]) {
        yield makeRow(i);
      }
    }
    const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
      source: skipping(),
      concurrency: 2,
    });
    const result = await engine.start();
    expect(result.rows.map((r) => r.rowIndex).sort((a, b) => a - b)).toEqual([0, 2, 5, 100, 999]);
  });

  it("100,000 rows: peak in-flight stays bounded by concurrency", async () => {
    // Issue acceptance criterion: a 100k-row CSV must not buffer the
    // whole row array up-front. We synthesise the source as a
    // generator (no full materialised array in memory) and assert
    // the peak in-flight gauge.
    //
    // We use a microtask-only hook (no setTimeout) so the bottleneck
    // is the engine's own pipeline cost (CredentialBuilder + JWS
    // prepare) rather than added test latency — at 100k rows even a
    // 1ms-per-row delay would blow the test timeout.
    installStubSchemaRegistry();

    const concurrency = 4;
    const { signer, concurrentMax } = makeStubSigner({
      hook: async () => {
        // A `Promise.resolve()` is enough to force a microtask break
        // so multiple workers genuinely interleave. Without ANY await
        // a single worker could burn through every row synchronously
        // and `concurrentMax` would silently read `1`.
        await Promise.resolve();
      },
    });

    const rowCount = 100_000;
    async function* generator(): AsyncIterable<ParsedRow> {
      for (let i = 0; i < rowCount; i++) {
        yield makeRow(i);
      }
    }

    const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
      source: generator(),
      concurrency,
    });

    const result = await engine.start();

    expect(result.successCount).toBe(rowCount);
    expect(result.errorCount).toBe(0);
    // Peak in-flight workers must never exceed `concurrency + small_const`.
    // `p-map` may have at most one prefetched row beyond the active
    // worker set, so the bound is `concurrency + 1`.
    expect(concurrentMax.value).toBeLessThanOrEqual(concurrency + 1);
    expect(concurrentMax.value).toBeGreaterThanOrEqual(2);
  }, 120_000);

  // ---------------------------------------------------------------------
  // onProgress hook (Tier 3 #8 of #446)
  // ---------------------------------------------------------------------
  //
  // The hook is the integration seam that lets the BullMQ worker push
  // progress frames into the JobStore without polling. The throttle is
  // deliberately observable in tests — a fast batch may emit just one
  // frame; the only invariant we care about is that the FINAL frame
  // always reaches every registered observer.

  describe("onProgress", () => {
    it("delivers a terminal frame to every observer even when the throttle would otherwise drop it", async () => {
      installStubSchemaRegistry();
      const { signer } = makeStubSigner();
      const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
        source: simpleSource(3),
        concurrency: 1,
      });

      const frames: number[] = [];
      engine.onProgress((frame) => {
        frames.push(frame.completed);
      });

      const final = await engine.start();

      // The throttle may collapse intermediate frames into one trailing
      // emission, but the final flush MUST fire. We assert on the LAST
      // frame, not the count.
      expect(frames.length).toBeGreaterThanOrEqual(1);
      expect(frames[frames.length - 1]).toBe(final.completed);
      expect(final.successCount).toBe(3);
    });

    it("swallows observer errors so a broken observer cannot abort signing", async () => {
      installStubSchemaRegistry();
      const { signer } = makeStubSigner();
      const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
        source: simpleSource(2),
        concurrency: 1,
      });
      // Observer throws on every frame. Engine must still settle
      // successfully — the observer is best-effort.
      engine.onProgress(() => {
        throw new Error("observer crashed");
      });
      const result = await engine.start();
      expect(result.successCount).toBe(2);
      expect(result.errorCount).toBe(0);
    });

    it("returns an unsubscribe function that stops further deliveries", async () => {
      installStubSchemaRegistry();
      const { signer } = makeStubSigner();
      const engine = createStreamingBatchEngine(signer, BASE_CONFIG, {
        source: simpleSource(5),
        concurrency: 1,
      });
      let callCount = 0;
      const off = engine.onProgress(() => {
        callCount++;
      });
      off();
      await engine.start();
      expect(callCount).toBe(0);
    });
  });
});
