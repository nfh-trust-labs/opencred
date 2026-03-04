/**
 * Integration tests for the Windows CNG native addon.
 *
 * These tests are gated to only run on Windows (win32). They verify that
 * the native addon can be loaded and exercised against the real Windows
 * Certificate Store. The test environment may have zero signing certificates,
 * so certificate-dependent tests are skipped when the store is empty.
 *
 * SECURITY: These tests never log or expose private key material.
 */

import { describe, it, expect } from "vitest";
import { createWindowsCertProvider } from "../windows-cert-provider.js";

const IS_WINDOWS = process.platform === "win32";

/**
 * Attempt to load the native addon, returning null if not available.
 */
function tryLoadAddon() {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("../../../native/build/Release/windows-cng.node");
  } catch {
    return null;
  }
}

describe.skipIf(!IS_WINDOWS)("Windows CNG Native Addon — Integration", () => {
  const addon = IS_WINDOWS ? tryLoadAddon() : null;

  it("should load the native addon without errors", () => {
    if (!addon) {
      console.log("Native addon not built — skipping integration tests");
      return;
    }

    expect(typeof addon.listSigningCertificates).toBe("function");
    expect(typeof addon.signWithCertificate).toBe("function");
    expect(typeof addon.getPublicKey).toBe("function");
    expect(typeof addon.getCertificateChain).toBe("function");
  });

  it("should list certificates (may be empty)", () => {
    if (!addon) return;

    const certs = addon.listSigningCertificates();
    expect(Array.isArray(certs)).toBe(true);

    for (const cert of certs) {
      expect(cert).toHaveProperty("id");
      expect(cert).toHaveProperty("subject");
      expect(cert).toHaveProperty("thumbprint");
      expect(cert).toHaveProperty("keyAlgorithm");
      expect(typeof cert.id).toBe("string");
      expect(typeof cert.subject).toBe("string");
      expect(typeof cert.thumbprint).toBe("string");
      expect(typeof cert.keyAlgorithm).toBe("string");
      expect(typeof cert.isExportable).toBe("boolean");
      expect(cert.thumbprint).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("should create a provider that wraps the native addon", async () => {
    if (!addon) return;

    const provider = createWindowsCertProvider(addon);
    const certs = await provider.listCertificates();
    expect(Array.isArray(certs)).toBe(true);
  });

  it("should get public key for first available certificate", async () => {
    if (!addon) return;

    const certs = addon.listSigningCertificates();
    if (certs.length === 0) {
      console.log("No signing certificates in store — skipping public key test");
      return;
    }

    const publicKey = addon.getPublicKey(certs[0].id);
    expect(publicKey).toBeInstanceOf(Buffer);
    expect(publicKey.length).toBeGreaterThan(0);

    const firstByte = publicKey[0];
    expect([0x02, 0x03, 0x30]).toContain(firstByte);
  });

  it("should get certificate chain for first available certificate", async () => {
    if (!addon) return;

    const certs = addon.listSigningCertificates();
    if (certs.length === 0) {
      console.log("No signing certificates — skipping chain test");
      return;
    }

    const chain = addon.getCertificateChain(certs[0].id);
    expect(Array.isArray(chain)).toBe(true);

    for (const pem of chain) {
      expect(typeof pem).toBe("string");
      expect(pem).toContain("-----BEGIN CERTIFICATE-----");
      expect(pem).toContain("-----END CERTIFICATE-----");
    }
  });

  it("should throw for non-existent certificate ID on sign", () => {
    if (!addon) return;

    expect(() => {
      addon.signWithCertificate("nonexistent-thumbprint", Buffer.alloc(32));
    }).toThrow();
  });

  it("should throw for non-existent certificate ID on getPublicKey", () => {
    if (!addon) return;

    expect(() => {
      addon.getPublicKey("nonexistent-thumbprint");
    }).toThrow();
  });

  it("should throw for empty certificate ID on sign", () => {
    if (!addon) return;

    expect(() => {
      addon.signWithCertificate("", Buffer.alloc(32));
    }).toThrow(/must not be empty/);
  });

  it("should throw for empty certificate ID on getPublicKey", () => {
    if (!addon) return;

    expect(() => {
      addon.getPublicKey("");
    }).toThrow(/must not be empty/);
  });
});
