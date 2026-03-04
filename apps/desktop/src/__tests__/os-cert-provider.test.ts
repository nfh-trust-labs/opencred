/**
 * Tests for the OS certificate store providers.
 *
 * Tests the OsCertProvider interface implementations for both macOS and
 * Windows using mock native addons. These tests verify:
 *
 *  - Provider creation with and without native addons
 *  - Certificate enumeration via mock addon
 *  - Signing via mock addon with correct signature format
 *  - Public key extraction via mock addon
 *  - Error handling when native addon is not available
 *  - Error handling for invalid inputs
 */

import { describe, it, expect } from "vitest";
import { CryptoError } from "@opencred/shared";
import { createMacOsCertProvider, type MacOsNativeAddon } from "../signing/macos-cert-provider.js";
import {
  createWindowsCertProvider,
  type WindowsNativeAddon,
} from "../signing/windows-cert-provider.js";
import type { OsCertInfo } from "../signing/os-cert-types.js";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockCertificates: OsCertInfo[] = [
  {
    id: "macos-cert-001",
    subject: "CN=Alice Smith",
    issuer: "CN=Enterprise CA",
    serialNumber: "0a0b0c0d",
    validFrom: "2024-01-01T00:00:00Z",
    validUntil: "2030-12-31T23:59:59Z",
    keyAlgorithm: "ECDSA P-256",
    isExportable: false,
    thumbprint: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  },
  {
    id: "macos-cert-002",
    subject: "CN=Bob Jones",
    issuer: "CN=Enterprise CA",
    serialNumber: "0e0f1011",
    validFrom: "2024-06-01T00:00:00Z",
    validUntil: "2025-06-01T00:00:00Z",
    keyAlgorithm: "ECDSA P-256",
    isExportable: true,
    thumbprint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  },
];

/** A valid 64-byte mock signature (raw r||s). */
const mockSignature = Buffer.alloc(64);
mockSignature.fill(0xaa, 0, 32);
mockSignature.fill(0xbb, 32, 64);

/** A valid 33-byte mock compressed public key. */
const mockCompressedPublicKey = Buffer.alloc(33);
mockCompressedPublicKey[0] = 0x02;
mockCompressedPublicKey.fill(0x11, 1, 33);

/**
 * Create a mock macOS native addon.
 */
function createMockMacOsAddon(options?: {
  throwOnList?: boolean;
  throwOnSign?: boolean;
  throwOnGetPublicKey?: boolean;
}): MacOsNativeAddon {
  return {
    listSigningCertificates(): OsCertInfo[] {
      if (options?.throwOnList) {
        throw new Error("Mock Keychain error");
      }
      return mockCertificates;
    },
    signWithCertificate(_certificateId: string, _data: Buffer): Buffer {
      if (options?.throwOnSign) {
        throw new Error("Mock Keychain signing error");
      }
      return mockSignature;
    },
    getPublicKey(_certificateId: string): Buffer {
      if (options?.throwOnGetPublicKey) {
        throw new Error("Mock Keychain key error");
      }
      return mockCompressedPublicKey;
    },
  };
}

/**
 * Create a mock Windows native addon.
 */
function createMockWindowsAddon(options?: {
  throwOnList?: boolean;
  throwOnSign?: boolean;
  throwOnGetPublicKey?: boolean;
}): WindowsNativeAddon {
  return {
    listSigningCertificates(): OsCertInfo[] {
      if (options?.throwOnList) {
        throw new Error("Mock CNG error");
      }
      return mockCertificates;
    },
    signWithCertificate(_certificateId: string, _data: Buffer): Buffer {
      if (options?.throwOnSign) {
        throw new Error("Mock CNG signing error");
      }
      return mockSignature;
    },
    getPublicKey(_certificateId: string): Buffer {
      if (options?.throwOnGetPublicKey) {
        throw new Error("Mock CNG key error");
      }
      return mockCompressedPublicKey;
    },
  };
}

// ---------------------------------------------------------------------------
// macOS Provider Tests
// ---------------------------------------------------------------------------

describe("macOS Certificate Provider", () => {
  describe("with native addon available", () => {
    it("should list certificates from macOS Keychain", async () => {
      const addon = createMockMacOsAddon();
      const provider = createMacOsCertProvider(addon);

      const certs = await provider.listCertificates();

      expect(certs).toHaveLength(2);
      expect(certs[0].id).toBe("macos-cert-001");
      expect(certs[0].subject).toBe("CN=Alice Smith");
      expect(certs[0].issuer).toBe("CN=Enterprise CA");
      expect(certs[0].keyAlgorithm).toBe("ECDSA P-256");
      expect(certs[0].isExportable).toBe(false);
    });

    it("should sign data via macOS Keychain", async () => {
      const addon = createMockMacOsAddon();
      const provider = createMacOsCertProvider(addon);

      const testData = new Uint8Array(64);
      testData.fill(0xcd);

      const signature = await provider.sign("macos-cert-001", testData);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);

      // Verify the signature matches our mock
      expect(signature.slice(0, 32).every((b) => b === 0xaa)).toBe(true);
      expect(signature.slice(32, 64).every((b) => b === 0xbb)).toBe(true);
    });

    it("should get public key via macOS Keychain", async () => {
      const addon = createMockMacOsAddon();
      const provider = createMacOsCertProvider(addon);

      const publicKey = await provider.getPublicKey("macos-cert-001");
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(33);
      expect(publicKey[0]).toBe(0x02);
    });

    it("should throw CryptoError on listCertificates failure", async () => {
      const addon = createMockMacOsAddon({ throwOnList: true });
      const provider = createMacOsCertProvider(addon);

      await expect(provider.listCertificates()).rejects.toThrow(CryptoError);
      await expect(provider.listCertificates()).rejects.toThrow(
        /Failed to enumerate macOS Keychain certificates/,
      );
    });

    it("should throw CryptoError on sign failure", async () => {
      const addon = createMockMacOsAddon({ throwOnSign: true });
      const provider = createMacOsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(
        /macOS Keychain signing operation failed/,
      );
    });

    it("should throw CryptoError on getPublicKey failure", async () => {
      const addon = createMockMacOsAddon({ throwOnGetPublicKey: true });
      const provider = createMacOsCertProvider(addon);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(
        /Failed to extract public key from macOS Keychain certificate/,
      );
    });

    it("should throw CryptoError for empty certificateId on sign", async () => {
      const addon = createMockMacOsAddon();
      const provider = createMacOsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("", testData)).rejects.toThrow(CryptoError);
      await expect(provider.sign("", testData)).rejects.toThrow(/Certificate ID is required/);
    });

    it("should throw CryptoError for empty certificateId on getPublicKey", async () => {
      const addon = createMockMacOsAddon();
      const provider = createMacOsCertProvider(addon);

      await expect(provider.getPublicKey("")).rejects.toThrow(CryptoError);
      await expect(provider.getPublicKey("")).rejects.toThrow(/Certificate ID is required/);
    });
  });

  describe("without native addon", () => {
    it("should throw CryptoError on listCertificates", async () => {
      const provider = createMacOsCertProvider(null);

      await expect(provider.listCertificates()).rejects.toThrow(CryptoError);
      await expect(provider.listCertificates()).rejects.toThrow(
        /macOS Keychain native addon is not available/,
      );
    });

    it("should throw CryptoError on sign", async () => {
      const provider = createMacOsCertProvider(null);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError on getPublicKey", async () => {
      const provider = createMacOsCertProvider(null);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
    });
  });

  describe("signature validation", () => {
    it("should pass through signatures of any non-zero length", async () => {
      const sig96 = Buffer.alloc(96); // P-384 length
      sig96[0] = 1; // non-zero
      const addon: MacOsNativeAddon = {
        ...createMockMacOsAddon(),
        signWithCertificate: () => sig96,
      };
      const provider = createMacOsCertProvider(addon);

      const testData = new Uint8Array(32);
      const result = await provider.sign("cert-001", testData);
      expect(result.length).toBe(96);
    });

    it("should reject empty signatures", async () => {
      const emptySig = Buffer.alloc(0);
      const addon: MacOsNativeAddon = {
        ...createMockMacOsAddon(),
        signWithCertificate: () => emptySig,
      };
      const provider = createMacOsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
    });

    it("should pass through public keys of any non-zero length", async () => {
      const key65 = Buffer.alloc(65); // uncompressed P-256 point
      key65[0] = 0x04; // uncompressed point prefix
      const addon: MacOsNativeAddon = {
        ...createMockMacOsAddon(),
        getPublicKey: () => key65,
      };
      const provider = createMacOsCertProvider(addon);

      const result = await provider.getPublicKey("cert-001");
      expect(result.length).toBe(65);
    });

    it("should reject empty public keys", async () => {
      const emptyKey = Buffer.alloc(0);
      const addon: MacOsNativeAddon = {
        ...createMockMacOsAddon(),
        getPublicKey: () => emptyKey,
      };
      const provider = createMacOsCertProvider(addon);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
    });
  });
});

// ---------------------------------------------------------------------------
// Windows Provider Tests
// ---------------------------------------------------------------------------

describe("Windows Certificate Provider", () => {
  describe("with native addon available", () => {
    it("should list certificates from Windows Certificate Store", async () => {
      const addon = createMockWindowsAddon();
      const provider = createWindowsCertProvider(addon);

      const certs = await provider.listCertificates();

      expect(certs).toHaveLength(2);
      expect(certs[0].id).toBe("macos-cert-001"); // Uses same mock data
      expect(certs[0].subject).toBe("CN=Alice Smith");
    });

    it("should sign data via Windows CNG", async () => {
      const addon = createMockWindowsAddon();
      const provider = createWindowsCertProvider(addon);

      const testData = new Uint8Array(64);
      testData.fill(0xef);

      const signature = await provider.sign("win-cert-001", testData);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });

    it("should get public key via Windows CNG", async () => {
      const addon = createMockWindowsAddon();
      const provider = createWindowsCertProvider(addon);

      const publicKey = await provider.getPublicKey("win-cert-001");
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(33);
      expect(publicKey[0]).toBe(0x02);
    });

    it("should throw CryptoError on listCertificates failure", async () => {
      const addon = createMockWindowsAddon({ throwOnList: true });
      const provider = createWindowsCertProvider(addon);

      await expect(provider.listCertificates()).rejects.toThrow(CryptoError);
      await expect(provider.listCertificates()).rejects.toThrow(
        /Failed to enumerate Windows Certificate Store certificates/,
      );
    });

    it("should throw CryptoError on sign failure", async () => {
      const addon = createMockWindowsAddon({ throwOnSign: true });
      const provider = createWindowsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(
        /Windows CNG signing operation failed/,
      );
    });

    it("should throw CryptoError on getPublicKey failure", async () => {
      const addon = createMockWindowsAddon({ throwOnGetPublicKey: true });
      const provider = createWindowsCertProvider(addon);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(
        /Failed to extract public key from Windows certificate/,
      );
    });

    it("should throw CryptoError for empty certificateId on sign", async () => {
      const addon = createMockWindowsAddon();
      const provider = createWindowsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("", testData)).rejects.toThrow(CryptoError);
      await expect(provider.sign("", testData)).rejects.toThrow(/Certificate ID is required/);
    });
  });

  describe("without native addon", () => {
    it("should throw CryptoError on listCertificates", async () => {
      const provider = createWindowsCertProvider(null);

      await expect(provider.listCertificates()).rejects.toThrow(CryptoError);
      await expect(provider.listCertificates()).rejects.toThrow(
        /Windows CNG native addon is not available/,
      );
    });

    it("should throw CryptoError on sign", async () => {
      const provider = createWindowsCertProvider(null);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError on getPublicKey", async () => {
      const provider = createWindowsCertProvider(null);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
    });
  });

  describe("signature validation", () => {
    it("should pass through signatures of any non-zero length", async () => {
      const sig96 = Buffer.alloc(96); // P-384 length
      sig96[0] = 1;
      const addon: WindowsNativeAddon = {
        ...createMockWindowsAddon(),
        signWithCertificate: () => sig96,
      };
      const provider = createWindowsCertProvider(addon);

      const testData = new Uint8Array(32);
      const result = await provider.sign("cert-001", testData);
      expect(result.length).toBe(96);
    });

    it("should reject empty signatures", async () => {
      const emptySig = Buffer.alloc(0);
      const addon: WindowsNativeAddon = {
        ...createMockWindowsAddon(),
        signWithCertificate: () => emptySig,
      };
      const provider = createWindowsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
    });

    it("should pass through public keys of any non-zero length", async () => {
      const key65 = Buffer.alloc(65);
      key65[0] = 0x04;
      const addon: WindowsNativeAddon = {
        ...createMockWindowsAddon(),
        getPublicKey: () => key65,
      };
      const provider = createWindowsCertProvider(addon);

      const result = await provider.getPublicKey("cert-001");
      expect(result.length).toBe(65);
    });

    it("should reject empty public keys", async () => {
      const emptyKey = Buffer.alloc(0);
      const addon: WindowsNativeAddon = {
        ...createMockWindowsAddon(),
        getPublicKey: () => emptyKey,
      };
      const provider = createWindowsCertProvider(addon);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
    });
  });
});
