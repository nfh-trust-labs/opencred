/**
 * Tests for PKCS#11 utility functions.
 *
 * Tests publicKeyFromEcPoint (P-256 and P-384), publicKeyFromRsaComponents,
 * normalizeSignature (EC and RSA), derCertToPem, and rsaAlgorithmFromModulusBits.
 * These do not require pkcs11js mocks — they test pure utility functions.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import {
  publicKeyFromEcPoint,
  publicKeyFromRsaComponents,
  rsaAlgorithmFromModulusBits,
  deriveDidKeyIdFromPublicKey,
  deriveDidJwkIdFromPublicKey,
  computeFingerprint,
  normalizeSignature,
  derCertToPem,
} from "../pkcs11-utils.js";

// ---------------------------------------------------------------------------
// Test key generation
// ---------------------------------------------------------------------------

const p256KeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const p256Jwk = p256KeyPair.publicKey.export({ format: "jwk" });
const p256EcPoint = new Uint8Array(65);
p256EcPoint[0] = 0x04;
p256EcPoint.set(Buffer.from(p256Jwk.x!, "base64url"), 1);
p256EcPoint.set(Buffer.from(p256Jwk.y!, "base64url"), 33);

const p384KeyPair = generateKeyPairSync("ec", { namedCurve: "P-384" });
const p384Jwk = p384KeyPair.publicKey.export({ format: "jwk" });
const p384EcPoint = new Uint8Array(97);
p384EcPoint[0] = 0x04;
p384EcPoint.set(Buffer.from(p384Jwk.x!, "base64url"), 1);
p384EcPoint.set(Buffer.from(p384Jwk.y!, "base64url"), 49);

const rsaKeyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsaJwk = rsaKeyPair.publicKey.export({ format: "jwk" });

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("publicKeyFromEcPoint", () => {
  it("should create a P-256 KeyObject from 65-byte point", () => {
    const key = publicKeyFromEcPoint(p256EcPoint);
    const jwk = key.export({ format: "jwk" });
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.x).toBe(p256Jwk.x);
    expect(jwk.y).toBe(p256Jwk.y);
  });

  it("should create a P-384 KeyObject from 97-byte point", () => {
    const key = publicKeyFromEcPoint(p384EcPoint);
    const jwk = key.export({ format: "jwk" });
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-384");
    expect(jwk.x).toBe(p384Jwk.x);
    expect(jwk.y).toBe(p384Jwk.y);
  });

  it("should reject wrong prefix byte", () => {
    const bad = new Uint8Array(65);
    bad[0] = 0x02;
    expect(() => publicKeyFromEcPoint(bad)).toThrow(CryptoError);
    expect(() => publicKeyFromEcPoint(bad)).toThrow(/must start with 0x04/);
  });

  it("should reject invalid length", () => {
    const bad = new Uint8Array(50);
    bad[0] = 0x04;
    expect(() => publicKeyFromEcPoint(bad)).toThrow(CryptoError);
    expect(() => publicKeyFromEcPoint(bad)).toThrow(/expected 65-byte.*or 97-byte/);
  });
});

describe("publicKeyFromRsaComponents", () => {
  it("should create an RSA KeyObject from modulus and exponent", () => {
    const modulus = Buffer.from(rsaJwk.n!, "base64url");
    const exponent = Buffer.from(rsaJwk.e!, "base64url");

    const key = publicKeyFromRsaComponents(new Uint8Array(modulus), new Uint8Array(exponent));

    const jwk = key.export({ format: "jwk" });
    expect(jwk.kty).toBe("RSA");
    expect(jwk.n).toBe(rsaJwk.n);
    expect(jwk.e).toBe(rsaJwk.e);
  });

  it("should handle modulus with leading zero bytes", () => {
    const modulus = Buffer.from(rsaJwk.n!, "base64url");
    const exponent = Buffer.from(rsaJwk.e!, "base64url");

    // Add leading zeros (PKCS#11 sign byte)
    const padded = new Uint8Array(modulus.length + 3);
    padded[0] = 0x00;
    padded[1] = 0x00;
    padded[2] = 0x00;
    padded.set(modulus, 3);

    const key = publicKeyFromRsaComponents(padded, new Uint8Array(exponent));
    const jwk = key.export({ format: "jwk" });
    expect(jwk.kty).toBe("RSA");
    expect(jwk.n).toBe(rsaJwk.n);
  });

  it("should produce a valid key from standard RSA-2048 components", () => {
    const modulus = Buffer.from(rsaJwk.n!, "base64url");
    const exponent = Buffer.from(rsaJwk.e!, "base64url");
    const key = publicKeyFromRsaComponents(new Uint8Array(modulus), new Uint8Array(exponent));
    // Verify round-trip
    const exportedJwk = key.export({ format: "jwk" });
    expect(exportedJwk.kty).toBe("RSA");
    expect(exportedJwk.n).toBe(rsaJwk.n);
  });
});

describe("rsaAlgorithmFromModulusBits", () => {
  it("should map 2048 to RSA-2048", () => {
    expect(rsaAlgorithmFromModulusBits(2048)).toBe("RSA-2048");
  });

  it("should map 3072 to RSA-3072", () => {
    expect(rsaAlgorithmFromModulusBits(3072)).toBe("RSA-3072");
  });

  it("should map 4096 to RSA-4096", () => {
    expect(rsaAlgorithmFromModulusBits(4096)).toBe("RSA-4096");
  });

  it("should map 2560 to RSA-3072 (bucket rounding)", () => {
    expect(rsaAlgorithmFromModulusBits(2560)).toBe("RSA-3072");
  });

  it("should map 3584 to RSA-4096 (bucket rounding)", () => {
    expect(rsaAlgorithmFromModulusBits(3584)).toBe("RSA-4096");
  });
});

describe("normalizeSignature", () => {
  describe("EC signatures", () => {
    it("should pass through 64-byte P-256 raw signatures", () => {
      const raw = new Uint8Array(64);
      raw.fill(0xaa, 0, 32);
      raw.fill(0xbb, 32, 64);
      expect(normalizeSignature(raw, "EC")).toEqual(raw);
    });

    it("should pass through 96-byte P-384 raw signatures", () => {
      const raw = new Uint8Array(96);
      raw.fill(0xcc, 0, 48);
      raw.fill(0xdd, 48, 96);
      expect(normalizeSignature(raw, "EC")).toEqual(raw);
    });

    it("should convert DER to raw for P-256", () => {
      const signer = createSign("SHA256");
      signer.update(Buffer.from("test"));
      const der = signer.sign({ key: p256KeyPair.privateKey, dsaEncoding: "der" });
      const raw = normalizeSignature(new Uint8Array(der), "EC");
      expect(raw.length).toBe(64);
    });

    it("should convert DER to raw for P-384", () => {
      const signer = createSign("SHA384");
      signer.update(Buffer.from("test"));
      const der = signer.sign({ key: p384KeyPair.privateKey, dsaEncoding: "der" });
      const raw = normalizeSignature(new Uint8Array(der), "EC");
      expect(raw.length).toBe(96);
    });

    it("should throw on unexpected EC signature length", () => {
      expect(() => normalizeSignature(new Uint8Array(48), "EC")).toThrow(CryptoError);
    });

    it("should default keyType to EC", () => {
      const raw = new Uint8Array(64);
      raw.fill(0xaa);
      // No keyType parameter — should default to "EC"
      expect(normalizeSignature(raw).length).toBe(64);
    });
  });

  describe("RSA signatures", () => {
    it("should pass through RSA signatures of any length", () => {
      const sig256 = new Uint8Array(256);
      sig256.fill(0xaa);
      expect(normalizeSignature(sig256, "RSA")).toEqual(sig256);

      const sig384 = new Uint8Array(384);
      sig384.fill(0xbb);
      expect(normalizeSignature(sig384, "RSA")).toEqual(sig384);

      const sig512 = new Uint8Array(512);
      sig512.fill(0xcc);
      expect(normalizeSignature(sig512, "RSA")).toEqual(sig512);
    });

    it("should not attempt DER parsing on RSA signatures", () => {
      // An RSA signature that happens to start with 0x30 should NOT be DER-parsed
      const sig = new Uint8Array(256);
      sig[0] = 0x30;
      sig.fill(0xaa, 1);
      expect(normalizeSignature(sig, "RSA")).toEqual(sig);
    });
  });
});

describe("derCertToPem", () => {
  it("should produce valid PEM from DER bytes", () => {
    const der = new Uint8Array([0x30, 0x82, 0x01, 0x00, 0xaa, 0xbb, 0xcc]);
    const pem = derCertToPem(der);

    expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----\n/);
    expect(pem).toMatch(/\n-----END CERTIFICATE-----$/);

    // Round-trip: PEM -> base64 -> DER should match original
    const b64 = pem
      .replace("-----BEGIN CERTIFICATE-----\n", "")
      .replace("\n-----END CERTIFICATE-----", "");
    const decoded = Buffer.from(b64, "base64");
    expect(new Uint8Array(decoded)).toEqual(der);
  });

  it("should wrap long base64 at 64 characters", () => {
    // Create a cert large enough to need line wrapping
    const der = new Uint8Array(100);
    der.fill(0xaa);
    const pem = derCertToPem(der);

    const lines = pem.split("\n");
    // First line is header, last line is footer
    for (let i = 1; i < lines.length - 1; i++) {
      expect(lines[i].length).toBeLessThanOrEqual(64);
    }
  });
});

describe("deriveDidKeyIdFromPublicKey", () => {
  it("should produce a did:key for P-256", () => {
    const key = publicKeyFromEcPoint(p256EcPoint);
    const id = deriveDidKeyIdFromPublicKey(key);
    expect(id).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);
  });

  it("should produce a did:key for P-384", () => {
    const key = publicKeyFromEcPoint(p384EcPoint);
    const id = deriveDidKeyIdFromPublicKey(key);
    expect(id).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);
  });
});

describe("deriveDidJwkIdFromPublicKey", () => {
  it("should produce a did:jwk for RSA", () => {
    const id = deriveDidJwkIdFromPublicKey(rsaKeyPair.publicKey);
    expect(id).toMatch(/^did:jwk:.+#0$/);
  });

  it("should be deterministic", () => {
    const id1 = deriveDidJwkIdFromPublicKey(rsaKeyPair.publicKey);
    const id2 = deriveDidJwkIdFromPublicKey(rsaKeyPair.publicKey);
    expect(id1).toBe(id2);
  });
});

describe("computeFingerprint", () => {
  it("should return a 64-char hex string for EC key", () => {
    const key = publicKeyFromEcPoint(p256EcPoint);
    expect(computeFingerprint(key)).toMatch(/^[a-f0-9]{64}$/);
  });

  it("should return a 64-char hex string for RSA key", () => {
    expect(computeFingerprint(rsaKeyPair.publicKey)).toMatch(/^[a-f0-9]{64}$/);
  });

  it("should be deterministic", () => {
    const key = publicKeyFromEcPoint(p256EcPoint);
    expect(computeFingerprint(key)).toBe(computeFingerprint(key));
  });

  it("should differ for different keys", () => {
    const key256 = publicKeyFromEcPoint(p256EcPoint);
    const key384 = publicKeyFromEcPoint(p384EcPoint);
    expect(computeFingerprint(key256)).not.toBe(computeFingerprint(key384));
  });
});
