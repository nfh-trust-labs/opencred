import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parsePfx } from "../pfx-parser.js";
import { CryptoError } from "@opencred/shared";

const FIXTURES_DIR = resolve(import.meta.dirname, "../../test/fixtures");

describe("parsePfx", () => {
  it("should parse an RSA-2048 PFX and detect the correct algorithm", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-rsa2048.pfx"));
    const result = parsePfx(buffer, "test123");

    expect(result.keyAlgorithm).toBe("RSA-2048");
    expect(result.privateKey).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(result.certificateChain).toBeInstanceOf(Array);
    expect(result.certificateChain.length).toBeGreaterThanOrEqual(1);
    expect(result.certificateChain[0]).toContain("-----BEGIN CERTIFICATE-----");
  });

  it("should parse an EC P-256 PFX and detect the correct algorithm", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-ec256.pfx"));
    const result = parsePfx(buffer, "test123");

    expect(result.keyAlgorithm).toBe("P-256");
    expect(result.privateKey).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(result.certificateChain.length).toBeGreaterThanOrEqual(1);
  });

  it("should parse an EC P-384 PFX and detect the correct algorithm", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-ec384.pfx"));
    const result = parsePfx(buffer, "test123");

    expect(result.keyAlgorithm).toBe("P-384");
    expect(result.privateKey).toBeDefined();
    expect(result.publicKey).toBeDefined();
    expect(result.certificateChain.length).toBeGreaterThanOrEqual(1);
  });

  it("should parse an RSA PFX with certificate chain and return 2 certs", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-rsa-chain.pfx"));
    const result = parsePfx(buffer, "test123");

    expect(result.keyAlgorithm).toBe("RSA-2048");
    expect(result.certificateChain.length).toBe(2);
    for (const cert of result.certificateChain) {
      expect(cert).toContain("-----BEGIN CERTIFICATE-----");
      expect(cert).toContain("-----END CERTIFICATE-----");
    }
  });

  it("should throw CryptoError for wrong password", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-rsa2048.pfx"));
    expect(() => parsePfx(buffer, "wrongpassword")).toThrow(CryptoError);
  });

  it("should throw CryptoError for invalid PFX data", () => {
    const invalidBuffer = Buffer.from("this is not a valid PFX file");
    expect(() => parsePfx(invalidBuffer, "test123")).toThrow(CryptoError);
  });
});
