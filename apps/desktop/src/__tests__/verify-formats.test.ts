import { describe, it, expect } from "vitest";
import { decodeQrData, compressCredentialForQr } from "../packaging/qr-generator";
import type { VerifiableCredential } from "@opencred/vc-core";

type FormatResult =
  | { format: "opencred-qr"; decoded: string }
  | { format: "json"; raw: string }
  | { format: "jwt"; raw: string }
  | { format: "sd-jwt"; raw: string }
  | { format: "unknown"; error: string };

function detectFormat(credential: string): FormatResult {
  const trimmed = credential.trim();
  if (trimmed.startsWith("OPENCRED1:")) {
    const decoded = decodeQrData(trimmed);
    return { format: "opencred-qr", decoded };
  } else if (trimmed.startsWith("{")) {
    return { format: "json", raw: trimmed };
  } else if (trimmed.includes("~")) {
    return { format: "sd-jwt", raw: trimmed };
  } else if (trimmed.split(".").length === 3) {
    return { format: "jwt", raw: trimmed };
  } else {
    return {
      format: "unknown",
      error: "Unrecognized credential format. Expected JSON, OPENCRED1: QR data, JWT, or SD-JWT.",
    };
  }
}

describe("verify-formats: format detection", () => {
  it("should detect OPENCRED1: compressed QR data and decode it", () => {
    const sampleCredential = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      issuer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      credentialSubject: { id: "did:example:123", name: "Test" },
    } as unknown as VerifiableCredential;

    const compressed = compressCredentialForQr(sampleCredential);
    expect(compressed).toMatch(/^OPENCRED1:/);

    const result = detectFormat(compressed);
    expect(result.format).toBe("opencred-qr");
    if (result.format === "opencred-qr") {
      const parsed = JSON.parse(result.decoded);
      expect(parsed.issuer).toBe(sampleCredential.issuer);
      expect(parsed.credentialSubject.name).toBe("Test");
    }
  });

  it("should detect raw JSON credentials", () => {
    const json =
      '{"@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiableCredential"]}';
    const result = detectFormat(json);
    expect(result.format).toBe("json");
    if (result.format === "json") {
      expect(result.raw).toBe(json);
    }
  });

  it("should detect JSON with leading whitespace", () => {
    const result = detectFormat('  \n  {"@context": []}');
    expect(result.format).toBe("json");
  });

  it("should detect JWT compact serialization", () => {
    const jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_here";
    const result = detectFormat(jwt);
    expect(result.format).toBe("jwt");
    if (result.format === "jwt") {
      expect(result.raw).toBe(jwt);
    }
  });

  it("should detect SD-JWT format (contains ~ separator)", () => {
    const sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYSJdfQ.sig~eyJhbGciOiJFUzI1NiJ9~";
    const result = detectFormat(sdJwt);
    expect(result.format).toBe("sd-jwt");
    if (result.format === "sd-jwt") {
      expect(result.raw).toBe(sdJwt);
    }
  });

  it("should prefer SD-JWT over JWT when ~ is present", () => {
    const sdJwt = "header.payload.signature~disclosure1~disclosure2~";
    const result = detectFormat(sdJwt);
    expect(result.format).toBe("sd-jwt");
  });

  it("should reject unrecognized formats", () => {
    const result = detectFormat("this is not a credential");
    expect(result.format).toBe("unknown");
    if (result.format === "unknown") {
      expect(result.error).toContain("Unrecognized credential format");
    }
  });

  it("should reject empty strings", () => {
    const result = detectFormat("   ");
    expect(result.format).toBe("unknown");
  });

  it("should handle OPENCRED1: with whitespace padding", () => {
    const sampleCredential = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      issuer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      credentialSubject: { id: "did:example:456" },
    } as unknown as VerifiableCredential;

    const compressed = compressCredentialForQr(sampleCredential);
    const padded = "  " + compressed + "  ";
    const result = detectFormat(padded);
    expect(result.format).toBe("opencred-qr");
  });
});

describe("verify-formats: decodeQrData round-trip", () => {
  it("should round-trip a credential through compress + decode", () => {
    const credential = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      issuer: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      issuanceDate: "2026-01-01T00:00:00Z",
      credentialSubject: {
        id: "did:example:789",
        name: "Alice",
        degree: { type: "BachelorDegree", name: "Computer Science" },
      },
    } as unknown as VerifiableCredential;

    const compressed = compressCredentialForQr(credential);
    const decoded = decodeQrData(compressed);
    const parsed = JSON.parse(decoded);

    expect(parsed.issuer).toBe(credential.issuer);
    expect(parsed.credentialSubject.name).toBe("Alice");
    expect(parsed.credentialSubject.degree.name).toBe("Computer Science");
  });
});
