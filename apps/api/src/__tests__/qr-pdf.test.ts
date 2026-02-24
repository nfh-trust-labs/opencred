import { describe, it, expect } from "vitest";
import {
  generateQrDataUrl,
  generateQrBuffer,
  generateCredentialPdf,
  packageFormats,
} from "../output/index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SAMPLE_CREDENTIAL: Record<string, unknown> = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  id: "urn:uuid:7c5c9e9e-0b3a-4f4e-9b3a-4f4e9b3a4f4e",
  type: ["VerifiableCredential", "EducationCredential"],
  issuer: "did:web:university.example",
  validFrom: "2026-01-01T00:00:00Z",
  validUntil: "2027-01-01T00:00:00Z",
  credentialSubject: {
    name: "Jane Doe",
    degree: "Bachelor of Science",
    institution: "Example University",
    dateConferred: "2025-06-15",
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    proofPurpose: "assertionMethod",
    verificationMethod: "did:web:university.example#key-1",
    proofValue: "z3FXQjecWufY46yg7irA89bEjKwoBvE5MjPbhsZkYfYsFM",
  },
};

const CREDENTIAL_WITH_OBJECT_ISSUER: Record<string, unknown> = {
  ...SAMPLE_CREDENTIAL,
  issuer: { id: "did:web:corp.example", name: "Corp Inc." },
};

// ---------------------------------------------------------------------------
// QR Code Tests
// ---------------------------------------------------------------------------

describe("QR code generation", () => {
  it("generateQrDataUrl returns a valid data URL", async () => {
    const dataUrl = await generateQrDataUrl(JSON.stringify(SAMPLE_CREDENTIAL));
    expect(dataUrl).toMatch(/^data:image\/png;base64,/);
    // Should be a non-trivial base64 string
    const base64Part = dataUrl.split(",")[1];
    expect(base64Part.length).toBeGreaterThan(100);
  });

  it("generateQrBuffer returns a valid PNG buffer", async () => {
    const buf = await generateQrBuffer(JSON.stringify(SAMPLE_CREDENTIAL));
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBeGreaterThan(0);
    // PNG magic bytes: 0x89 0x50 0x4e 0x47
    expect(buf[0]).toBe(0x89);
    expect(buf[1]).toBe(0x50); // P
    expect(buf[2]).toBe(0x4e); // N
    expect(buf[3]).toBe(0x47); // G
  });

  it("respects size option (small vs large produce different buffer sizes)", async () => {
    const data = JSON.stringify(SAMPLE_CREDENTIAL);
    const small = await generateQrBuffer(data, { size: "small" });
    const large = await generateQrBuffer(data, { size: "large" });
    // Larger QR image should produce a larger buffer
    expect(large.length).toBeGreaterThan(small.length);
  });

  it("throws ValidationError when data exceeds QR capacity", async () => {
    // Create a string that exceeds 2953 bytes
    const hugeData = "x".repeat(3000);
    await expect(generateQrDataUrl(hugeData)).rejects.toThrow(/exceeds QR code capacity/);
  });

  it("QR round-trip: data URL contains decodable base64 image", async () => {
    const input = JSON.stringify({ hello: "world" });
    const dataUrl = await generateQrDataUrl(input);

    // Verify the data URL structure
    expect(dataUrl).toMatch(/^data:image\/png;base64,[A-Za-z0-9+/]+=*$/);
  });
});

// ---------------------------------------------------------------------------
// PDF Tests
// ---------------------------------------------------------------------------

describe("PDF generation", () => {
  it("generateCredentialPdf returns a valid PDF buffer", async () => {
    const pdfBuf = await generateCredentialPdf({ credential: SAMPLE_CREDENTIAL });
    expect(Buffer.isBuffer(pdfBuf)).toBe(true);
    expect(pdfBuf.length).toBeGreaterThan(0);

    // PDF magic bytes: %PDF
    const header = pdfBuf.subarray(0, 5).toString("ascii");
    expect(header).toMatch(/^%PDF-/);
  });

  it("generates PDF with embedded QR code", async () => {
    const qrBuf = await generateQrBuffer(JSON.stringify(SAMPLE_CREDENTIAL));
    const pdfBuf = await generateCredentialPdf({
      credential: SAMPLE_CREDENTIAL,
      qrBuffer: qrBuf,
    });
    expect(Buffer.isBuffer(pdfBuf)).toBe(true);
    // PDF with QR should be larger than without
    const pdfBufNoQr = await generateCredentialPdf({ credential: SAMPLE_CREDENTIAL });
    expect(pdfBuf.length).toBeGreaterThan(pdfBufNoQr.length);
  });

  it("handles credential with object issuer", async () => {
    const pdfBuf = await generateCredentialPdf({
      credential: CREDENTIAL_WITH_OBJECT_ISSUER,
    });
    expect(Buffer.isBuffer(pdfBuf)).toBe(true);
    const header = pdfBuf.subarray(0, 5).toString("ascii");
    expect(header).toMatch(/^%PDF-/);
  });

  it("handles credential without optional fields", async () => {
    const minimalCredential: Record<string, unknown> = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential"],
      issuer: "did:web:example.com",
      credentialSubject: { name: "Test" },
    };
    const pdfBuf = await generateCredentialPdf({ credential: minimalCredential });
    expect(Buffer.isBuffer(pdfBuf)).toBe(true);
    expect(pdfBuf.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// packageFormats integration
// ---------------------------------------------------------------------------

describe("packageFormats", () => {
  it("returns jsonld, qr, and pdf fields", async () => {
    const result = await packageFormats(SAMPLE_CREDENTIAL);

    // jsonld is the credential itself
    expect(result.jsonld).toEqual(SAMPLE_CREDENTIAL);

    // qr is a data URL
    expect(result.qr).toMatch(/^data:image\/png;base64,/);

    // pdf is base64-encoded
    expect(typeof result.pdf).toBe("string");
    expect(result.pdf.length).toBeGreaterThan(0);

    // Decode PDF and verify magic bytes
    const pdfBuf = Buffer.from(result.pdf, "base64");
    const header = pdfBuf.subarray(0, 5).toString("ascii");
    expect(header).toMatch(/^%PDF-/);
  });

  it("handles credential with object issuer in all formats", async () => {
    const result = await packageFormats(CREDENTIAL_WITH_OBJECT_ISSUER);
    expect(result.jsonld).toEqual(CREDENTIAL_WITH_OBJECT_ISSUER);
    expect(result.qr).toMatch(/^data:image\/png;base64,/);
    expect(result.pdf.length).toBeGreaterThan(0);
  });

  it("gracefully degrades QR for oversized credentials", async () => {
    // Create a credential with a very large subject that exceeds QR capacity
    const largeCredential: Record<string, unknown> = {
      ...SAMPLE_CREDENTIAL,
      credentialSubject: {
        name: "Jane Doe",
        largeField: "x".repeat(3000),
      },
    };

    const result = await packageFormats(largeCredential);

    // QR should contain an error message (graceful degradation)
    expect(result.qr).toMatch(/^error:/);

    // But PDF should still be generated successfully
    const pdfBuf = Buffer.from(result.pdf, "base64");
    const header = pdfBuf.subarray(0, 5).toString("ascii");
    expect(header).toMatch(/^%PDF-/);

    // And jsonld should still be the credential
    expect(result.jsonld).toEqual(largeCredential);
  });
});
