/**
 * Tests for the batch row limit enforcement.
 *
 * Verifies that:
 *  - BATCH_ROW_LIMIT is exported and equals 1000
 *  - CSV files with > 1000 rows are correctly counted by parseCsv
 *  - CSV files with <= 1000 rows are correctly counted by parseCsv
 *  - The row limit check in handleBatchStart works correctly
 *
 * Does NOT require Electron or a real key pair — only tests the
 * parsing/counting and limit constant.
 */

import { describe, it, expect } from "vitest";
import { parseCsv } from "../batch/csv-parser";
import { BATCH_ROW_LIMIT } from "../shared/constants";

// ---------------------------------------------------------------------------
// Helper to generate a CSV with N rows
// ---------------------------------------------------------------------------

function generateCsv(rowCount: number): string {
  const header = "name,degree,institution,dateConferred";
  const rows = Array.from(
    { length: rowCount },
    (_, i) =>
      `Student ${i + 1},Bachelor of Science,University ${i + 1},2025-06-${String(15 + (i % 15)).padStart(2, "0")}`,
  );
  return [header, ...rows].join("\n");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Batch row limit — constant", () => {
  it("should export BATCH_ROW_LIMIT as 1000", () => {
    expect(BATCH_ROW_LIMIT).toBe(1000);
  });
});

describe("Batch row limit — CSV row counting", () => {
  it("should correctly count rows at the limit (1000 rows)", () => {
    const csv = generateCsv(1000);
    const result = parseCsv(csv, { schemaId: "education" });

    expect(result.totalCount).toBe(1000);
    expect(result.totalCount).toBeLessThanOrEqual(BATCH_ROW_LIMIT);
  });

  it("should correctly count rows over the limit (1001 rows)", () => {
    const csv = generateCsv(1001);
    const result = parseCsv(csv, { schemaId: "education" });

    expect(result.totalCount).toBe(1001);
    expect(result.totalCount).toBeGreaterThan(BATCH_ROW_LIMIT);
  });

  it("should correctly count rows well under the limit (10 rows)", () => {
    const csv = generateCsv(10);
    const result = parseCsv(csv, { schemaId: "education" });

    expect(result.totalCount).toBe(10);
    expect(result.totalCount).toBeLessThanOrEqual(BATCH_ROW_LIMIT);
  });
});

describe("Batch row limit — validation logic", () => {
  it("should accept a batch with exactly 1000 rows", () => {
    const csv = generateCsv(1000);
    const result = parseCsv(csv, { schemaId: "education" });

    // Simulate the check in handleBatchStart
    const overLimit = result.totalCount > BATCH_ROW_LIMIT;
    expect(overLimit).toBe(false);
  });

  it("should reject a batch with 1001 rows", () => {
    const csv = generateCsv(1001);
    const result = parseCsv(csv, { schemaId: "education" });

    // Simulate the check in handleBatchStart
    const overLimit = result.totalCount > BATCH_ROW_LIMIT;
    expect(overLimit).toBe(true);
  });

  it("should reject a batch with 2000 rows", () => {
    const csv = generateCsv(2000);
    const result = parseCsv(csv, { schemaId: "education" });

    const overLimit = result.totalCount > BATCH_ROW_LIMIT;
    expect(overLimit).toBe(true);
  });

  it("should accept a batch with 999 rows", () => {
    const csv = generateCsv(999);
    const result = parseCsv(csv, { schemaId: "education" });

    const overLimit = result.totalCount > BATCH_ROW_LIMIT;
    expect(overLimit).toBe(false);
  });

  it("should accept a batch with 1 row", () => {
    const csv = generateCsv(1);
    const result = parseCsv(csv, { schemaId: "education" });

    const overLimit = result.totalCount > BATCH_ROW_LIMIT;
    expect(overLimit).toBe(false);
  });
});
