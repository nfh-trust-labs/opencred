/**
 * Tests for credential packaging (QR, PDF, JSON-LD).
 *
 * Validates QR code generation produces valid PNG, JSON export produces
 * valid JSON-LD, and the packager orchestrator works correctly.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createSoftwareSigner } from "../signing/software-signer";
import { buildAndSign } from "../signing/local-signing-flow";
import { generateQrPng, generateQrSvg, generateQrBuffer, compressCredentialForQr, decodeQrData } from "../packaging/qr-generator";
import { generatePdf } from "../packaging/pdf-generator";
import { exportAsJsonLd, exportAsCompactJson, parseCredentialJson } from "../packaging/json-export";
import { packageCredential } from "../packaging/packager";
import type { VerifiableCredential } from "@opencred/vc-core";

let tmpDir: string;
let testCredential: VerifiableCredential;

// Generate a P-256 key pair for testing
const { privateKey: testPrivateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

beforeAll(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-packaging-test-"));

  const pemKey = testPrivateKey.export({ format: "pem", type: "pkcs8" }) as string;
  const pemKeyPath = path.join(tmpDir, "test-key.pem");
  fs.writeFileSync(pemKeyPath, pemKey);

  const { signer } = createSoftwareSigner(pemKeyPath);

  // Build a small credential for QR code testing
  const result = await buildAndSign(signer, {
    schemaId: "education",
    issuerDid: "did:web:test.example",
    credentialSubject: {
      name: "Test",
      degree: "BS",
      institution: "MIT",
      dateConferred: "2025-01-01",
    },
    validFrom: "2025-01-01T00:00:00Z",
  });

  testCredential = result.credential;
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("QR Generator", () => {
  it("should generate a PNG data URL from a credential", async () => {
    const dataUrl = await generateQrPng(testCredential);

    expect(dataUrl).toMatch(/^data:image\/png;base64,/);
    // Should be a non-trivial length (actual QR code data)
    expect(dataUrl.length).toBeGreaterThan(100);
  });

  it("should generate an SVG string from a credential", async () => {
    const svg = await generateQrSvg(testCredential);

    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
  });

  it("should generate a PNG buffer from a credential", async () => {
    const buffer = await generateQrBuffer(testCredential);

    expect(Buffer.isBuffer(buffer)).toBe(true);
    expect(buffer.length).toBeGreaterThan(0);

    // PNG magic bytes
    expect(buffer[0]).toBe(0x89);
    expect(buffer[1]).toBe(0x50); // 'P'
    expect(buffer[2]).toBe(0x4e); // 'N'
    expect(buffer[3]).toBe(0x47); // 'G'
  });

  it("should handle large credentials via PixelPass compression", async () => {
    // With PixelPass compression, repetitive data compresses well.
    // A credential with 3000 repeated chars will compress and fit.
    const largeCredential: VerifiableCredential = {
      ...testCredential,
      credentialSubject: {
        ...testCredential.credentialSubject,
        largeField: "x".repeat(3000),
      },
    };

    const dataUrl = await generateQrPng(largeCredential);
    expect(dataUrl).toMatch(/^data:image\/png;base64,/);
  });

  it("should roundtrip compress and decode credential data", () => {
    const compressed = compressCredentialForQr(testCredential);

    // Should have OPENCRED1: header
    expect(compressed).toMatch(/^OPENCRED1:/);

    // Roundtrip: compressed data should decode back to the original credential
    const decoded = decodeQrData(compressed);
    const parsed = JSON.parse(decoded);
    expect(parsed["@context"]).toEqual(testCredential["@context"]);
    expect(parsed.id).toBe(testCredential.id);
    expect(parsed.credentialSubject).toEqual(testCredential.credentialSubject);
  });
});

describe("PDF Generator", () => {
  it("should generate a PDF buffer from a credential", async () => {
    const buffer = await generatePdf(testCredential);

    expect(Buffer.isBuffer(buffer)).toBe(true);
    expect(buffer.length).toBeGreaterThan(0);

    // PDF magic bytes
    expect(buffer.toString("ascii", 0, 4)).toBe("%PDF");
  });
});

describe("JSON Export", () => {
  it("should export a credential as formatted JSON-LD", () => {
    const jsonLd = exportAsJsonLd(testCredential);

    expect(jsonLd).toContain("@context");
    expect(jsonLd).toContain("VerifiableCredential");
    expect(jsonLd).toContain("proof");

    // Should be formatted (indented)
    expect(jsonLd).toContain("\n");

    // Should parse back to a valid object
    const parsed = JSON.parse(jsonLd);
    expect(parsed["@context"]).toBeDefined();
    expect(parsed.proof).toBeDefined();
  });

  it("should export a credential as compact JSON", () => {
    const json = exportAsCompactJson(testCredential);

    // Should not have newlines (compact)
    expect(json).not.toContain("\n");

    // Should parse back correctly
    const parsed = JSON.parse(json);
    expect(parsed["@context"]).toBeDefined();
  });

  it("should parse valid credential JSON", () => {
    const json = exportAsJsonLd(testCredential);
    const parsed = parseCredentialJson(json);

    expect(parsed["@context"]).toBeDefined();
    expect(parsed.type).toBeDefined();
    expect(parsed.issuer).toBeDefined();
    expect(parsed.credentialSubject).toBeDefined();
    expect(parsed.proof).toBeDefined();
  });

  it("should reject JSON missing required fields", () => {
    expect(() => parseCredentialJson("{}")).toThrow(/Missing required field/);
    expect(() => parseCredentialJson('{"@context":[]}')).toThrow(/Missing required field/);
  });

  it("should reject invalid JSON", () => {
    expect(() => parseCredentialJson("not json")).toThrow();
  });
});

describe("Packager orchestrator", () => {
  it("should package a credential in all default formats", async () => {
    const result = await packageCredential(testCredential);

    expect(result.outputs.length).toBeGreaterThan(0);

    const formats = result.outputs.map((o) => o.format);
    expect(formats).toContain("json-ld");
  });

  it("should package a credential as JSON-LD", async () => {
    const result = await packageCredential(testCredential, ["json-ld"]);

    expect(result.outputs.length).toBe(1);
    expect(result.outputs[0].format).toBe("json-ld");
    expect(result.outputs[0].mimeType).toBe("application/ld+json");
    expect(result.outputs[0].suggestedFileName).toMatch(/\.jsonld$/);
    expect(typeof result.outputs[0].data).toBe("string");
  });

  it("should package a credential as compact JSON", async () => {
    const result = await packageCredential(testCredential, ["json-compact"]);

    expect(result.outputs.length).toBe(1);
    expect(result.outputs[0].format).toBe("json-compact");
    expect(result.outputs[0].mimeType).toBe("application/json");
    expect(result.outputs[0].suggestedFileName).toMatch(/\.json$/);
  });

  it("should package a credential as QR PNG", async () => {
    const result = await packageCredential(testCredential, ["qr-png"]);

    expect(result.outputs.length).toBe(1);
    expect(result.outputs[0].format).toBe("qr-png");
    expect(result.outputs[0].mimeType).toBe("image/png");
    expect(typeof result.outputs[0].data).toBe("string");
    expect(result.outputs[0].data as string).toMatch(/^data:image\/png/);
  });

  it("should package a credential as QR SVG", async () => {
    const result = await packageCredential(testCredential, ["qr-svg"]);

    expect(result.outputs.length).toBe(1);
    expect(result.outputs[0].format).toBe("qr-svg");
    expect(result.outputs[0].mimeType).toBe("image/svg+xml");
  });

  it("should package a credential as PDF", async () => {
    const result = await packageCredential(testCredential, ["pdf"]);

    expect(result.outputs.length).toBe(1);
    expect(result.outputs[0].format).toBe("pdf");
    expect(result.outputs[0].mimeType).toBe("application/pdf");
    expect(Buffer.isBuffer(result.outputs[0].data)).toBe(true);
  });

  it("should succeed for large credentials with PixelPass compression", async () => {
    const largeCredential: VerifiableCredential = {
      ...testCredential,
      credentialSubject: {
        ...testCredential.credentialSubject,
        largeField: "x".repeat(3000),
      },
    };

    // With PixelPass compression, both QR and JSON should succeed
    const result = await packageCredential(largeCredential, ["qr-png", "json-ld"]);

    expect(result.errors.length).toBe(0);
    expect(result.outputs.length).toBe(2);
    expect(result.outputs[0].format).toBe("qr-png");
    expect(result.outputs[1].format).toBe("json-ld");
  });

  it("should generate appropriate file names", async () => {
    const result = await packageCredential(testCredential, ["json-ld", "pdf"]);

    for (const output of result.outputs) {
      expect(output.suggestedFileName).toBeTruthy();
      expect(output.suggestedFileName.length).toBeGreaterThan(0);
    }
  });
});
