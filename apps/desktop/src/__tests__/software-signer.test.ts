/**
 * Tests for the software signer module.
 *
 * Validates PEM, JWK, and PKCS#8 DER key loading, invalid key rejection,
 * signing produces valid 64-byte output, and key metadata extraction.
 *
 * All test keys are generated ephemerally — no key material is persisted.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  createSoftwareSigner,
  createSoftwareSignerFromBuffer,
  detectKeyFormat,
} from "../signing/software-signer";

// Temp directory for test key files
let tmpDir: string;

// Generate a P-256 key pair for testing
const { privateKey: testPrivateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

// Export in various formats
const pemKey = testPrivateKey.export({ format: "pem", type: "pkcs8" }) as string;
const derKey = testPrivateKey.export({ format: "der", type: "pkcs8" });
const jwkPrivate = testPrivateKey.export({ format: "jwk" });

// Generate a non-P-256 key for rejection testing
const { privateKey: secp384Key } = generateKeyPairSync("ec", {
  namedCurve: "secp384r1",
});
const secp384Pem = secp384Key.export({ format: "pem", type: "pkcs8" }) as string;

// Generate an RSA key for rejection testing
const { privateKey: rsaKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const rsaPem = rsaKey.export({ format: "pem", type: "pkcs8" }) as string;

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-signer-test-"));

  // Write test keys to files
  fs.writeFileSync(path.join(tmpDir, "test-key.pem"), pemKey);
  fs.writeFileSync(path.join(tmpDir, "test-key.der"), derKey);
  fs.writeFileSync(path.join(tmpDir, "test-key.json"), JSON.stringify(jwkPrivate));
  fs.writeFileSync(path.join(tmpDir, "secp384-key.pem"), secp384Pem);
  fs.writeFileSync(path.join(tmpDir, "rsa-key.pem"), rsaPem);
  fs.writeFileSync(path.join(tmpDir, "invalid.txt"), "this is not a key");
});

afterAll(() => {
  // Clean up temp files
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("detectKeyFormat", () => {
  it("should detect PEM format", () => {
    const content = Buffer.from(pemKey);
    expect(detectKeyFormat(content)).toBe("pem");
  });

  it("should detect JWK format", () => {
    const content = Buffer.from(JSON.stringify(jwkPrivate));
    expect(detectKeyFormat(content)).toBe("jwk");
  });

  it("should detect PKCS#8 DER format (binary fallback)", () => {
    const content = Buffer.from(derKey);
    expect(detectKeyFormat(content)).toBe("pkcs8-der");
  });
});

describe("createSoftwareSigner (from file path)", () => {
  it("should load a PEM key file", () => {
    const { signer, format } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"));

    expect(format).toBe("pem");
    expect(signer.algorithm).toBe("P-256");
    expect(signer.type).toBe("software");
    expect(signer.id).toMatch(/^did:key:z/);
    expect(signer.id).toContain("#");
    expect(signer.metadata.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should load a JWK key file", () => {
    const { signer, format } = createSoftwareSigner(path.join(tmpDir, "test-key.json"));

    expect(format).toBe("jwk");
    expect(signer.algorithm).toBe("P-256");
    expect(signer.type).toBe("software");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("should load a PKCS#8 DER key file", () => {
    const { signer, format } = createSoftwareSigner(path.join(tmpDir, "test-key.der"));

    expect(format).toBe("pkcs8-der");
    expect(signer.algorithm).toBe("P-256");
    expect(signer.type).toBe("software");
  });

  it("should produce consistent did:key IDs across formats", () => {
    const { signer: pemSigner } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"));
    const { signer: jwkSigner } = createSoftwareSigner(path.join(tmpDir, "test-key.json"));
    const { signer: derSigner } = createSoftwareSigner(path.join(tmpDir, "test-key.der"));

    // Same key in different formats should produce the same did:key ID
    expect(pemSigner.id).toBe(jwkSigner.id);
    expect(pemSigner.id).toBe(derSigner.id);
  });

  it("should produce consistent fingerprints across formats", () => {
    const { signer: pemSigner } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"));
    const { signer: jwkSigner } = createSoftwareSigner(path.join(tmpDir, "test-key.json"));
    const { signer: derSigner } = createSoftwareSigner(path.join(tmpDir, "test-key.der"));

    expect(pemSigner.metadata.fingerprint).toBe(jwkSigner.metadata.fingerprint);
    expect(pemSigner.metadata.fingerprint).toBe(derSigner.metadata.fingerprint);
  });

  it("should accept an optional label", () => {
    const { signer } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"), "Test Key");
    expect(signer.metadata.label).toBe("Test Key");
  });

  it("should reject non-P-256 EC keys (secp384r1)", () => {
    expect(() => createSoftwareSigner(path.join(tmpDir, "secp384-key.pem"))).toThrow(/P-256/);
  });

  it("should reject RSA keys", () => {
    expect(() => createSoftwareSigner(path.join(tmpDir, "rsa-key.pem"))).toThrow(
      /P-256|EC|Unsupported/,
    );
  });

  it("should reject invalid key files", () => {
    expect(() => createSoftwareSigner(path.join(tmpDir, "invalid.txt"))).toThrow();
  });

  it("should throw CryptoError for non-existent files", () => {
    expect(() => createSoftwareSigner(path.join(tmpDir, "nonexistent.pem"))).toThrow(
      /Failed to read key file/,
    );
  });
});

describe("createSoftwareSignerFromBuffer", () => {
  it("should create a signer from a PEM buffer", () => {
    const { signer, format } = createSoftwareSignerFromBuffer(Buffer.from(pemKey));

    expect(format).toBe("pem");
    expect(signer.algorithm).toBe("P-256");
  });

  it("should create a signer from a JWK buffer", () => {
    const { signer, format } = createSoftwareSignerFromBuffer(
      Buffer.from(JSON.stringify(jwkPrivate)),
    );

    expect(format).toBe("jwk");
    expect(signer.algorithm).toBe("P-256");
  });

  it("should create a signer from a DER buffer", () => {
    const { signer, format } = createSoftwareSignerFromBuffer(Buffer.from(derKey));

    expect(format).toBe("pkcs8-der");
    expect(signer.algorithm).toBe("P-256");
  });
});

describe("Signer.sign()", () => {
  it("should produce a 64-byte raw r||s signature", async () => {
    const { signer } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"));
    const data = new Uint8Array(64); // 64 bytes of zeros (like a proof hash pair)

    const signature = await signer.sign(data);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });

  it("should produce different signatures for different data", async () => {
    const { signer } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"));

    const data1 = new Uint8Array(64).fill(0);
    const data2 = new Uint8Array(64).fill(1);

    const sig1 = await signer.sign(data1);
    const sig2 = await signer.sign(data2);

    // Signatures should be different (with overwhelming probability)
    expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(false);
  });

  it("should be consistent (same key, same data produces valid signatures)", async () => {
    const { signer } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"));
    const data = new Uint8Array(64).fill(42);

    // Both signatures should be valid 64-byte values (but differ due to ECDSA randomness)
    const sig1 = await signer.sign(data);
    const sig2 = await signer.sign(data);

    expect(sig1.length).toBe(64);
    expect(sig2.length).toBe(64);
  });
});

describe("Signer metadata (security)", () => {
  it("should never expose private key material in metadata", () => {
    const { signer } = createSoftwareSigner(path.join(tmpDir, "test-key.pem"));

    // Metadata should only contain safe information
    const meta = signer.metadata;
    const metaStr = JSON.stringify(meta);

    // Ensure no private key component "d" appears in metadata
    expect(meta).not.toHaveProperty("privateKey");
    expect(meta).not.toHaveProperty("d");
    expect(metaStr).not.toContain('"d"');

    // Should have the expected safe fields
    expect(meta.id).toBeDefined();
    expect(meta.algorithm).toBe("P-256");
    expect(meta.type).toBe("software");
    expect(meta.fingerprint).toBeDefined();
  });
});
