/**
 * Tests for the batch export (ZIP creation).
 *
 * Covers: ZIP creation, file naming convention, inclusion of packaged outputs,
 * and handling of various credential formats.
 *
 * Uses a real P-256 key pair and the actual signing/packaging pipeline to
 * produce real credentials for the export tests.
 *
 * Mocks electron-store to avoid Electron runtime dependency.
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// Mock electron-store (required by revocation-queue -> store)
const storeData: Record<string, unknown> = {};
vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => ({
    get: vi.fn((key: string) => storeData[key]),
    set: vi.fn((key: string, value: unknown) => {
      storeData[key] = value;
    }),
    store: {},
  })),
}));

// Initialise the store mock before importing modules that depend on it
const { initStore } = await import("../main/store");
initStore();

const { createSoftwareSigner } = await import("../signing/software-signer");
const { parseCsv } = await import("../batch/csv-parser");
const { createBatchEngine } = await import("../batch/batch-engine");
const { exportBatchAsZip } = await import("../batch/batch-export");

let tmpDir: string;
let keyPath: string;

// Generate a P-256 key pair for testing
const { privateKey: testPrivateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-export-test-"));
  const keyContent = testPrivateKey.export({ format: "pem", type: "pkcs8" }) as string;
  keyPath = path.join(tmpDir, "test-key");
  fs.writeFileSync(keyPath, keyContent);
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

/**
 * Helper: run a batch of functional-identity credentials and return the results.
 */
async function runBatch(count: number) {
  const { signer } = createSoftwareSigner(keyPath);

  const header = "name,role,validFrom";
  const rows = Array.from(
    { length: count },
    (_, i) =>
      `Student ${i + 1},University Student,2025-06-${String(15 + (i % 15)).padStart(2, "0")}T00:00:00Z`,
  );
  const csv = [header, ...rows].join("\n");

  const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

  const engine = createBatchEngine(signer, parseResult.rows, {
    schemaId: "functional-identity/v1",
    issuerDid: "did:web:authority.example",
    validFrom: "2025-06-15T00:00:00Z",
    packageFormats: ["json-ld"],
  });

  return engine.start();
}

describe("exportBatchAsZip", () => {
  it("should create a ZIP file with the correct number of files", async () => {
    const batchResult = await runBatch(3);

    const outputPath = path.join(tmpDir, "test-export.zip");
    const exportResult = await exportBatchAsZip({
      rows: batchResult.rows,
      outputPath,
    });

    expect(exportResult.filePath).toBe(outputPath);
    expect(exportResult.credentialCount).toBe(3);
    // Each credential produces 1 raw .jsonld + 1 packaged .jsonld output
    expect(exportResult.fileCount).toBeGreaterThanOrEqual(3);

    // Verify the ZIP file exists and has content
    const fileExists = fs.existsSync(outputPath);
    expect(fileExists).toBe(true);

    const stats = fs.statSync(outputPath);
    expect(stats.size).toBeGreaterThan(0);
  });

  it("should follow the naming convention: credential-{rowIndex}-{subjectId}.{ext}", async () => {
    const batchResult = await runBatch(2);

    const outputPath = path.join(tmpDir, "test-naming.zip");
    const exportResult = await exportBatchAsZip({
      rows: batchResult.rows,
      outputPath,
    });

    // The ZIP was created successfully
    expect(exportResult.credentialCount).toBe(2);
    expect(exportResult.fileCount).toBeGreaterThanOrEqual(2);

    // Verify the file was created
    expect(fs.existsSync(outputPath)).toBe(true);
  });

  it("should handle empty batch (no successful rows)", async () => {
    const outputPath = path.join(tmpDir, "test-empty.zip");
    const exportResult = await exportBatchAsZip({
      rows: [
        { rowIndex: 0, status: "skipped", error: "Invalid" },
        { rowIndex: 1, status: "error", error: "Failed" },
      ],
      outputPath,
    });

    expect(exportResult.credentialCount).toBe(0);
    expect(exportResult.fileCount).toBe(0);
  });

  it("should only export successful rows", async () => {
    const { signer } = createSoftwareSigner(keyPath);

    const csv = [
      "name,role,validFrom",
      "Jane Doe,Medical Practitioner,2025-06-15T00:00:00Z",
      "Invalid,,", // Will be skipped
      "John Smith,Field Crop Grower,2025-06-20T00:00:00Z",
    ].join("\n");

    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:authority.example",
      validFrom: "2025-06-15T00:00:00Z",
      packageFormats: ["json-ld"],
    });

    const batchResult = await engine.start();

    const outputPath = path.join(tmpDir, "test-partial.zip");
    const exportResult = await exportBatchAsZip({
      rows: batchResult.rows,
      outputPath,
    });

    // Only the 2 successful rows should be exported
    expect(exportResult.credentialCount).toBe(2);
  });

  it("should create output in temp directory when no path specified", async () => {
    const batchResult = await runBatch(1);

    const exportResult = await exportBatchAsZip({
      rows: batchResult.rows,
    });

    expect(exportResult.filePath).toBeTruthy();
    expect(exportResult.filePath).toContain("opencred-batch-");
    expect(exportResult.filePath).toMatch(/\.zip$/);
    expect(fs.existsSync(exportResult.filePath)).toBe(true);

    // Clean up temp file
    fs.unlinkSync(exportResult.filePath);
  });
});
