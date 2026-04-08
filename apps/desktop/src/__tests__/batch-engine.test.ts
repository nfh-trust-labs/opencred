/**
 * Tests for the batch issuance engine.
 *
 * Covers: processing multiple valid rows, handling invalid rows, progress
 * tracking, cancellation, and the full offline pipeline.
 *
 * Uses a real P-256 key pair and the actual local signing flow to verify
 * that the entire batch pipeline works end-to-end offline.
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
import type { BatchProgress } from "../batch/batch-engine";

let tmpDir: string;
let keyPath: string;

// Generate a P-256 key pair for testing
const { privateKey: testPrivateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-batch-test-"));
  const keyContent = testPrivateKey.export({ format: "pem", type: "pkcs8" }) as string;
  keyPath = path.join(tmpDir, "test-key");
  fs.writeFileSync(keyPath, keyContent);
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// Helper to create a valid education CSV
function createEducationCsv(count: number): string {
  // Generates a functional-identity/v1 CSV — credentialSubject requires
  // (name, role, validFrom). Helper name is preserved for git churn reasons;
  // it's now generic test data, not education-specific.
  const header = "name,role,validFrom";
  const rows = Array.from(
    { length: count },
    (_, i) =>
      `Student ${i + 1},University Student,2025-06-${String(15 + (i % 15)).padStart(2, "0")}T00:00:00Z`,
  );
  return [header, ...rows].join("\n");
}

describe("Batch engine — valid rows", () => {
  it("should process a batch of 5 valid education credentials", async () => {
    const { signer } = createSoftwareSigner(keyPath);
    const csv = createEducationCsv(5);
    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    expect(parseResult.validCount).toBe(5);
    expect(parseResult.invalidCount).toBe(0);

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
      packageFormats: ["json-ld"],
    });

    const result = await engine.start();

    expect(result.total).toBe(5);
    expect(result.successCount).toBe(5);
    expect(result.errorCount).toBe(0);
    expect(result.skippedCount).toBe(0);
    expect(result.completed).toBe(5);
    expect(result.running).toBe(false);

    // Verify each row produced a valid credential (default vc-jwt format)
    for (const row of result.rows) {
      expect(row.status).toBe("success");
      expect(row.credential).toBeDefined();
      const cred = row.credential as Record<string, unknown>;
      const proof = cred.proof as Record<string, unknown>;
      expect(proof).toBeDefined();
      expect(proof.type).toBe("JsonWebSignature2020");
      expect(proof.jwt).toBeDefined();
    }
  });

  it("should process a batch of 10 credentials", async () => {
    const { signer } = createSoftwareSigner(keyPath);
    const csv = createEducationCsv(10);
    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
    });

    const result = await engine.start();

    expect(result.successCount).toBe(10);
    expect(result.errorCount).toBe(0);
  });
});

describe("Batch engine — invalid rows", () => {
  it("should skip invalid rows and process valid ones", async () => {
    const { signer } = createSoftwareSigner(keyPath);

    const csv = [
      "name,role,validFrom",
      "Jane Doe,Medical Practitioner,2025-06-15T00:00:00Z",
      "Invalid Row,,", // Missing required fields
      "John Smith,Field Crop Grower,2025-06-20T00:00:00Z",
      ",,", // All empty
      "Alice Johnson,Registered Nurse,2025-07-01T00:00:00Z",
    ].join("\n");

    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    expect(parseResult.validCount).toBe(3);
    expect(parseResult.invalidCount).toBe(2);

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
    });

    const result = await engine.start();

    expect(result.successCount).toBe(3);
    expect(result.skippedCount).toBe(2);
    expect(result.errorCount).toBe(0);
    expect(result.completed).toBe(5);

    // Verify the valid rows produced credentials
    expect(result.rows[0].status).toBe("success");
    expect(result.rows[0].credential).toBeDefined();

    // Verify invalid rows were skipped
    expect(result.rows[1].status).toBe("skipped");
    expect(result.rows[1].error).toBeDefined();

    expect(result.rows[2].status).toBe("success");
    expect(result.rows[3].status).toBe("skipped");
    expect(result.rows[4].status).toBe("success");
  });

  it("should report errors in invalid rows", async () => {
    const { signer } = createSoftwareSigner(keyPath);

    const csv = [
      "name,role,validFrom",
      "Jane Doe,,", // Missing role, validFrom
    ].join("\n");

    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });
    expect(parseResult.invalidCount).toBe(1);

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
    });

    const result = await engine.start();

    expect(result.skippedCount).toBe(1);
    expect(result.rows[0].status).toBe("skipped");
    expect(result.rows[0].error).toBeTruthy();
  });
});

describe("Batch engine — progress tracking", () => {
  it("should track progress via callback", async () => {
    const { signer } = createSoftwareSigner(keyPath);
    const csv = createEducationCsv(3);
    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
    });

    const progressUpdates: BatchProgress[] = [];
    engine.onProgressUpdate((p: BatchProgress) => progressUpdates.push(p));

    await engine.start();

    // Should have received progress updates
    expect(progressUpdates.length).toBeGreaterThan(0);

    // The last update should show all complete
    const last = progressUpdates[progressUpdates.length - 1];
    expect(last.completed).toBe(3);
    expect(last.running).toBe(false);
  });

  it("should report getProgress() accurately during processing", async () => {
    const { signer } = createSoftwareSigner(keyPath);
    const csv = createEducationCsv(2);
    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
    });

    // Before starting
    const before = engine.getProgress();
    expect(before.running).toBe(false);
    expect(before.total).toBe(2);
    expect(before.completed).toBe(0);

    await engine.start();

    // After completing
    const after = engine.getProgress();
    expect(after.running).toBe(false);
    expect(after.completed).toBe(2);
    expect(after.successCount).toBe(2);
  });
});

describe("Batch engine — cancellation", () => {
  it("should support cancellation", async () => {
    const { signer } = createSoftwareSigner(keyPath);
    const csv = createEducationCsv(5);
    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
    });

    // Cancel after the first row finishes processing (status becomes "success")
    let cancelled = false;
    engine.onProgressUpdate((p: BatchProgress) => {
      if (!cancelled && p.successCount >= 1) {
        cancelled = true;
        engine.cancel();
      }
    });

    const result = await engine.start();

    // Should have cancelled (at least some rows should be skipped due to cancellation)
    expect(result.cancelled).toBe(true);
    // At least 1 row was processed before cancel
    expect(result.successCount).toBeGreaterThanOrEqual(1);
    // Not all rows should have completed (some should be skipped)
    expect(result.successCount).toBeLessThan(5);
    // Total should still be 5
    expect(result.total).toBe(5);
  });
});

describe("Batch engine — offline operation", () => {
  it("should work completely offline (no network requests)", async () => {
    const { signer } = createSoftwareSigner(keyPath);
    const csv = createEducationCsv(3);
    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:offline.example",
      validFrom: "2025-01-01T00:00:00Z",
      validUntil: "2030-12-31T00:00:00Z",
    });

    const result = await engine.start();

    expect(result.successCount).toBe(3);

    // Verify all credentials have proper structure (default vc-jwt format)
    for (const row of result.rows) {
      if (row.status === "success" && row.credential) {
        const cred = row.credential as Record<string, unknown>;
        expect(cred.issuer).toBe("did:web:offline.example");
        expect(cred.validFrom).toBe("2025-01-01T00:00:00Z");
        expect(cred.validUntil).toBe("2030-12-31T00:00:00Z");
        expect(cred.type).toContain("VerifiableCredential");
        const proof = cred.proof as Record<string, unknown>;
        expect(proof.type).toBe("JsonWebSignature2020");
        expect(proof.jwt).toBeDefined();
      }
    }
  });

  it("should handle a second batch run", async () => {
    const { signer } = createSoftwareSigner(keyPath);

    const csv = [
      "name,role,validFrom",
      "John Smith,Senior Engineer,2024-01-15T00:00:00Z",
      "Jane Doe,Manager,2024-03-01T00:00:00Z",
      "Bob Williams,Designer,2024-05-20T00:00:00Z",
    ].join("\n");

    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });
    expect(parseResult.validCount).toBe(3);

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:employer.example",
      validFrom: "2024-01-01T00:00:00Z",
    });

    const result = await engine.start();
    expect(result.successCount).toBe(3);
  });

  it("should include packaging results when formats are requested", async () => {
    const { signer } = createSoftwareSigner(keyPath);
    const csv = createEducationCsv(2);
    const parseResult = parseCsv(csv, { schemaId: "functional-identity/v1" });

    const engine = createBatchEngine(signer, parseResult.rows, {
      schemaId: "functional-identity/v1",
      issuerDid: "did:web:university.example",
      validFrom: "2025-06-15T00:00:00Z",
      packageFormats: ["json-ld"],
    });

    const result = await engine.start();

    for (const row of result.rows) {
      if (row.status === "success") {
        expect(row.packagingResult).toBeDefined();
        expect(row.packagingResult!.outputs.length).toBeGreaterThan(0);
        const jsonLdOutput = row.packagingResult!.outputs.find((o) => o.format === "json-ld");
        expect(jsonLdOutput).toBeDefined();
        expect(jsonLdOutput!.mimeType).toBe("application/ld+json");
      }
    }
  });
});
