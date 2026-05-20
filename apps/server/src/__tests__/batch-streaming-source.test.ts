/**
 * Tests for the #580 refactor that feeds the streaming CSV parser
 * DIRECTLY to the batch engine (no intermediate `ParsedRow[]` drain
 * inside the route).
 *
 * Three guarantees we lock in here:
 *
 *   1. **Streaming source path is wired**: a CSV body submitted to
 *      POST /credentials/batch produces a 202 with the same shape as
 *      before (validCount/invalidCount/totalCount/parseErrors), AND
 *      the engine processes every valid row to completion. This is
 *      end-to-end coverage that the passthrough generator hand-off
 *      between parser and engine actually works.
 *
 *   2. **parseErrors are bounded** to PARSE_ERRORS_LIMIT (100). A CSV
 *      with >100 invalid rows must NOT echo every error back into the
 *      202 response body — CLAUDE.md rule 5 + DoS-shape concern. We
 *      assert the cap and the `_truncated` sentinel marker that lets
 *      callers detect truncation occurred.
 *
 *   3. **OPENCRED_MAX_BATCH_BODY_BYTES still enforced**: the upstream
 *      `bodyLimit` middleware was the defense the streaming refactor
 *      promised not to disturb. We submit a body just past the cap
 *      and confirm 413 PAYLOAD_TOO_LARGE — proving the route never
 *      reads byte-1 of a body the middleware already rejected.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { createTestApp, generateTestKey, type TestKeyPair } from "./helpers.js";
import { __resetBatchStateForTesting } from "../routes/batch.js";
import { setActiveSigner } from "../signing/key-manager.js";
import type { Hono } from "hono";

describe("POST /credentials/batch — streaming source path (#580)", () => {
  let app: Hono;
  let testKey: TestKeyPair;

  beforeAll(() => {
    testKey = generateTestKey();
  });

  beforeEach(() => {
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(testKey.signer);
    __resetBatchStateForTesting();
  });

  // -------------------------------------------------------------------------
  // 1. Streaming source path is wired end-to-end
  // -------------------------------------------------------------------------

  it("counts validCount/invalidCount/totalCount via the streaming pass (no ParsedRow[] drain)", async () => {
    // Mix of valid and invalid rows. Pre-#580 the route would have
    // buffered every row into an array before counting; post-#580 the
    // counters tick inside a passthrough generator while the engine
    // pulls each row.
    const csv = [
      "name,role,validFrom",
      "Alice,Medical Practitioner,2025-06-01T00:00:00Z",
      ",Medical Practitioner,2025-06-01T00:00:00Z", // missing name
      "Bob,Registered Nurse,2025-06-01T00:00:00Z",
      ",Registered Nurse,2025-06-01T00:00:00Z", // missing name
      "Carol,Medical Practitioner,2025-06-01T00:00:00Z",
    ].join("\n");

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent: csv,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
      }),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      jobId: string;
      validCount: number;
      invalidCount: number;
      totalCount: number;
      parseErrors?: Array<{ rowIndex: number }>;
    };
    expect(body.validCount).toBe(3);
    expect(body.invalidCount).toBe(2);
    expect(body.totalCount).toBe(5);
    expect(body.parseErrors).toBeDefined();
    expect(body.parseErrors).toHaveLength(2);
  });

  it("engine drains the streaming source and produces results for every valid row", async () => {
    const csv = [
      "name,role,validFrom",
      "Alice,Medical Practitioner,2025-06-01T00:00:00Z",
      "Bob,Registered Nurse,2025-06-01T00:00:00Z",
      "Carol,Medical Practitioner,2025-06-01T00:00:00Z",
    ].join("\n");

    const startRes = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent: csv,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
      }),
    });
    expect(startRes.status).toBe(202);
    const { jobId } = (await startRes.json()) as { jobId: string };

    // Poll for completion. The engine consumes the streaming source
    // concurrently with the route's parseCompletion await; by the
    // time we begin polling here, every row has been pulled from the
    // parser (the route only returns 202 once the parser drained).
    let progress: Record<string, unknown> = {};
    for (let i = 0; i < 40; i += 1) {
      await new Promise((r) => setTimeout(r, 50));
      const p = await app.request(`/credentials/batch/${jobId}`);
      progress = (await p.json()) as Record<string, unknown>;
      if (progress.status === "completed") break;
    }
    expect(progress.status).toBe("completed");
    expect(progress.total).toBe(3);
    expect(progress.successCount).toBe(3);
    expect(progress.errorCount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 2. parseErrors are bounded (PARSE_ERRORS_LIMIT = 100)
  // -------------------------------------------------------------------------

  it("caps parseErrors at 100 entries and emits a _truncated sentinel for the overflow", async () => {
    // Construct 150 invalid rows — every row is missing the required
    // `name` field. Pre-#580 the entire array landed in the 202 body
    // (`parsedRows.filter(!r.valid)` ran with no cap); post-#580 the
    // route stores at most PARSE_ERRORS_LIMIT entries and counts the
    // overflow into a sentinel row at the end.
    const header = "name,role,validFrom";
    const invalidRows = Array.from(
      { length: 150 },
      () => `,Medical Practitioner,2025-06-01T00:00:00Z`,
    );
    const csv = [header, ...invalidRows].join("\n");

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent: csv,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
      }),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      validCount: number;
      invalidCount: number;
      totalCount: number;
      parseErrors?: Array<{ rowIndex: number; errors: Array<{ field: string; message: string }> }>;
    };
    expect(body.validCount).toBe(0);
    expect(body.invalidCount).toBe(150);
    expect(body.totalCount).toBe(150);
    // 100 real error entries + 1 sentinel = 101 entries in the array.
    expect(body.parseErrors).toBeDefined();
    expect(body.parseErrors).toHaveLength(101);
    const sentinel = body.parseErrors![100];
    expect(sentinel.rowIndex).toBe(-1);
    expect(sentinel.errors[0].field).toBe("_truncated");
    expect(sentinel.errors[0].message).toMatch(/\+50 more errors omitted/);
  });

  it("does NOT emit a sentinel when parseErrors fit under the cap", async () => {
    // 50 invalid rows → exactly 50 entries returned, no sentinel.
    const header = "name,role,validFrom";
    const invalidRows = Array.from(
      { length: 50 },
      () => `,Medical Practitioner,2025-06-01T00:00:00Z`,
    );
    const csv = [header, ...invalidRows].join("\n");

    const res = await app.request("/credentials/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csvContent: csv,
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
      }),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      parseErrors?: Array<{ rowIndex: number; errors: Array<{ field: string }> }>;
    };
    expect(body.parseErrors).toBeDefined();
    expect(body.parseErrors).toHaveLength(50);
    // None of them should be the sentinel row.
    for (const entry of body.parseErrors!) {
      expect(entry.rowIndex).toBeGreaterThanOrEqual(0);
      for (const e of entry.errors) {
        expect(e.field).not.toBe("_truncated");
      }
    }
  });

  // -------------------------------------------------------------------------
  // 3. OPENCRED_MAX_BATCH_BODY_BYTES still enforced upstream
  // -------------------------------------------------------------------------

  it("returns 413 PAYLOAD_TOO_LARGE when the request body exceeds OPENCRED_MAX_BATCH_BODY_BYTES", async () => {
    // Force a tight body cap via env so we don't have to construct a
    // 200 MB CSV in memory. The middleware reads the config at app
    // creation time, so we must rebuild the app under the new cap.
    const prev = process.env.OPENCRED_MAX_BATCH_BODY_BYTES;
    process.env.OPENCRED_MAX_BATCH_BODY_BYTES = "1024"; // 1 KiB
    try {
      const tightApp = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);

      // ~3 KiB body — comfortably over the 1 KiB cap. Setting
      // `Content-Length` exercises the bodyLimit middleware's
      // header-based fast path (matches the pattern used by the
      // existing MED-02 tests in endpoints.test.ts) — this is how Hono
      // emits a 413 without needing to fully read the body stream first.
      const padding = "x".repeat(3_000);
      const requestBody = JSON.stringify({
        csvContent: "name,role,validFrom\nAlice,Medical Practitioner,2025-06-01T00:00:00Z",
        schemaId: "functional-identity/v1",
        issuerDid: testKey.signer.id.split("#")[0],
        validFrom: "2025-06-01T00:00:00Z",
        // Pad the body past the cap. The middleware checks total
        // request body length, so any field with this much data trips
        // the limit.
        additionalTypes: [padding],
      });
      const res = await tightApp.request("/credentials/batch", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(Buffer.byteLength(requestBody)),
        },
        body: requestBody,
      });
      expect(res.status).toBe(413);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe("PAYLOAD_TOO_LARGE");
    } finally {
      if (prev === undefined) {
        delete process.env.OPENCRED_MAX_BATCH_BODY_BYTES;
      } else {
        process.env.OPENCRED_MAX_BATCH_BODY_BYTES = prev;
      }
    }
  });

  // -------------------------------------------------------------------------
  // 4. Parser limit still surfaces as 4xx (OPENCRED_BATCH_ROW_LIMIT)
  // -------------------------------------------------------------------------

  it("surfaces StreamingCsvLimitError from the streaming source as a 4xx ValidationError", async () => {
    // Drop the row cap to 3 so we can blow past it with a tiny CSV.
    const prev = process.env.OPENCRED_BATCH_ROW_LIMIT;
    process.env.OPENCRED_BATCH_ROW_LIMIT = "3";
    try {
      const lowCapApp = createTestApp({ devModeNoAuth: true });
      setActiveSigner(testKey.signer);

      const csv = [
        "name,role,validFrom",
        "Alice,Medical Practitioner,2025-06-01T00:00:00Z",
        "Bob,Medical Practitioner,2025-06-01T00:00:00Z",
        "Carol,Medical Practitioner,2025-06-01T00:00:00Z",
        "Dave,Medical Practitioner,2025-06-01T00:00:00Z", // 4th — exceeds cap=3
      ].join("\n");

      const res = await lowCapApp.request("/credentials/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          csvContent: csv,
          schemaId: "functional-identity/v1",
          issuerDid: testKey.signer.id.split("#")[0],
          validFrom: "2025-06-01T00:00:00Z",
        }),
      });

      // ValidationError → 400 (the route maps StreamingCsvLimitError via
      // the same ValidationError path the buffered drain used).
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: { code: string; message: string } };
      expect(body.error.message).toMatch(/exceeds maximum of 3 rows/);
    } finally {
      if (prev === undefined) {
        delete process.env.OPENCRED_BATCH_ROW_LIMIT;
      } else {
        process.env.OPENCRED_BATCH_ROW_LIMIT = prev;
      }
    }
  });
});
