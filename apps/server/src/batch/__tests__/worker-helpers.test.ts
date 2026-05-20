/**
 * Tests for the pure helpers used by the BullMQ worker entry point.
 *
 * The worker module itself has a top-level config + signing-key
 * bootstrap that can't run inside vitest without a real Redis + key
 * file. Splitting the pure logic out of `worker.ts` into
 * `batch/worker-helpers.ts` keeps the worker entry point honest about
 * what it can and cannot be unit-tested in isolation.
 */

import { describe, it, expect } from "vitest";
import { deriveWorkerStatus, wireRowToParsedRow } from "../worker-helpers.js";
import type { BatchProgress } from "../batch-engine.js";
import type { BatchJobRow } from "@opencred/shared";

function progress(p: Partial<BatchProgress>): BatchProgress {
  return {
    total: 0,
    completed: 0,
    successCount: 0,
    errorCount: 0,
    skippedCount: 0,
    rows: [],
    running: false,
    cancelled: false,
    ...p,
  };
}

describe("deriveWorkerStatus", () => {
  it("null progress => queued", () => {
    expect(deriveWorkerStatus(null)).toBe("queued");
  });
  it("running with 0 completed => queued", () => {
    expect(deriveWorkerStatus(progress({ running: true }))).toBe("queued");
  });
  it("running with >0 completed => running", () => {
    expect(deriveWorkerStatus(progress({ running: true, completed: 1, total: 5 }))).toBe(
      "running",
    );
  });
  it("cancelled wins over running", () => {
    expect(
      deriveWorkerStatus(progress({ running: true, completed: 1, cancelled: true })),
    ).toBe("cancelled");
  });
  it("errors only with no successes => failed", () => {
    expect(deriveWorkerStatus(progress({ errorCount: 3 }))).toBe("failed");
  });
  it("any success + completion => completed", () => {
    expect(deriveWorkerStatus(progress({ successCount: 5 }))).toBe("completed");
  });
});

describe("wireRowToParsedRow", () => {
  it("preserves claims as mappedSubject for valid rows", () => {
    const wire: BatchJobRow = {
      rowIndex: 0,
      valid: true,
      claims: { name: "Alice", role: "Medical Practitioner" },
    };
    const parsed = wireRowToParsedRow(wire);
    expect(parsed.valid).toBe(true);
    expect(parsed.mappedSubject).toEqual({ name: "Alice", role: "Medical Practitioner" });
    expect(parsed.errors).toEqual([]);
    expect(parsed.rawValues).toEqual({});
  });

  it("converts flat error strings back to {field, message} for invalid rows", () => {
    const wire: BatchJobRow = {
      rowIndex: 3,
      valid: false,
      errors: ["name: required", "role: must be enum"],
    };
    const parsed = wireRowToParsedRow(wire);
    expect(parsed.valid).toBe(false);
    expect(parsed.errors).toEqual([
      { field: "name", message: "required" },
      { field: "role", message: "must be enum" },
    ]);
  });

  it("falls back to a synthetic field for error strings without a colon", () => {
    const wire: BatchJobRow = {
      rowIndex: 1,
      valid: false,
      errors: ["something went wrong"],
    };
    const parsed = wireRowToParsedRow(wire);
    expect(parsed.errors[0]).toEqual({ field: "row", message: "something went wrong" });
  });

  it("undefined claims on a valid row yields {} (engine reads mappedSubject directly)", () => {
    const wire: BatchJobRow = { rowIndex: 0, valid: true };
    const parsed = wireRowToParsedRow(wire);
    expect(parsed.mappedSubject).toEqual({});
  });
});
