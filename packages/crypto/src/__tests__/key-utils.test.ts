/**
 * Tests for key-utils: detectKeyAlgorithm and publicKeyFromEcBytes.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createECDH } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { detectKeyAlgorithm, publicKeyFromEcBytes } from "../key-utils.js";

// ----- detectKeyAlgorithm -----

describe("detectKeyAlgorithm", () => {
  it("should detect P-256", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(detectKeyAlgorithm(publicKey)).toBe("P-256");
  });

  it("should detect P-384", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    expect(detectKeyAlgorithm(publicKey)).toBe("P-384");
  });

  it("should detect Ed25519", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    expect(detectKeyAlgorithm(publicKey)).toBe("Ed25519");
  });

  it("should detect RSA-2048", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(detectKeyAlgorithm(publicKey)).toBe("RSA-2048");
  });

  it("should detect RSA-4096", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 4096 });
    expect(detectKeyAlgorithm(publicKey)).toBe("RSA-4096");
  });

  it("should throw for unsupported EC curve", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
    expect(() => detectKeyAlgorithm(publicKey)).toThrow(CryptoError);
  });
});

// ----- publicKeyFromEcBytes -----

describe("publicKeyFromEcBytes", () => {
  it("should construct a KeyObject from a P-256 uncompressed point", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(x, 1);
    uncompressed.set(y, 33);

    const reconstructed = publicKeyFromEcBytes(uncompressed);
    const reconstructedJwk = reconstructed.export({ format: "jwk" });
    expect(reconstructedJwk.crv).toBe("P-256");
    expect(reconstructedJwk.x).toBe(jwk.x);
    expect(reconstructedJwk.y).toBe(jwk.y);
  });

  it("should construct a KeyObject from a P-384 uncompressed point", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const jwk = publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const uncompressed = new Uint8Array(97);
    uncompressed[0] = 0x04;
    uncompressed.set(x, 1);
    uncompressed.set(y, 49);

    const reconstructed = publicKeyFromEcBytes(uncompressed);
    const reconstructedJwk = reconstructed.export({ format: "jwk" });
    expect(reconstructedJwk.crv).toBe("P-384");
    expect(reconstructedJwk.x).toBe(jwk.x);
    expect(reconstructedJwk.y).toBe(jwk.y);
  });

  it("should construct a KeyObject from a P-256 compressed point", () => {
    const ecdh = createECDH("prime256v1");
    ecdh.generateKeys();
    const compressed = ecdh.getPublicKey(undefined, "compressed");

    const reconstructed = publicKeyFromEcBytes(new Uint8Array(compressed));
    const reconstructedJwk = reconstructed.export({ format: "jwk" });
    expect(reconstructedJwk.crv).toBe("P-256");
  });

  it("should construct a KeyObject from a P-384 compressed point", () => {
    const ecdh = createECDH("secp384r1");
    ecdh.generateKeys();
    const compressed = ecdh.getPublicKey(undefined, "compressed");

    const reconstructed = publicKeyFromEcBytes(new Uint8Array(compressed));
    const reconstructedJwk = reconstructed.export({ format: "jwk" });
    expect(reconstructedJwk.crv).toBe("P-384");
  });

  it("should reject invalid prefix byte", () => {
    const bad = new Uint8Array(65);
    bad[0] = 0x05;
    expect(() => publicKeyFromEcBytes(bad)).toThrow(CryptoError);
    expect(() => publicKeyFromEcBytes(bad)).toThrow(/Invalid EC point/);
  });

  it("should reject invalid uncompressed point length", () => {
    const bad = new Uint8Array(50);
    bad[0] = 0x04;
    expect(() => publicKeyFromEcBytes(bad)).toThrow(CryptoError);
    expect(() => publicKeyFromEcBytes(bad)).toThrow(/Invalid EC.*point/);
  });

  it("should reject invalid compressed point length", () => {
    const bad = new Uint8Array(20);
    bad[0] = 0x02;
    expect(() => publicKeyFromEcBytes(bad)).toThrow(CryptoError);
    expect(() => publicKeyFromEcBytes(bad)).toThrow(/Invalid EC.*point/);
  });
});
