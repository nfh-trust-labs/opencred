/**
 * Tests for the OS certificate store providers.
 *
 * Tests the OsCertProvider interface implementations for both macOS and
 * Windows using mock native addons. These tests verify:
 *
 *  - Provider creation with and without native addons
 *  - Certificate enumeration via mock addon (EC and RSA certs)
 *  - Signing via mock addon with correct signature format
 *  - Public key extraction via mock addon
 *  - Certificate chain retrieval
 *  - Error handling when native addon is not available
 *  - Error handling for invalid inputs
 */

import { describe, it, expect } from "vitest";
import { CryptoError } from "@opencred/shared";
import { createMacOsCertProvider, type MacOsNativeAddon } from "../macos-cert-provider.js";
import {
  createWindowsCertProvider,
  type WindowsNativeAddon,
} from "../windows-cert-provider.js";
import type { OsCertInfo } from "../os-cert-types.js";

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
    keyAlgorithm: "P-256",
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
    keyAlgorithm: "P-256",
    isExportable: true,
    thumbprint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  },
];

const mockCertificatesWithRsa: OsCertInfo[] = [
  ...mockCertificates,
  {
    id: "macos-cert-003",
    subject: "CN=Carol Davis",
    issuer: "CN=Enterprise CA",
    serialNumber: "a0a1a2a3",
    validFrom: "2024-01-01T00:00:00Z",
    validUntil: "2030-12-31T23:59:59Z",
    keyAlgorithm: "RSA-2048",
    isExportable: false,
    thumbprint: "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
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

const mockCertChain = [
  "-----BEGIN CERTIFICATE-----\nMIIB...mock-dsc...\n-----END CERTIFICATE-----",
  "-----BEGIN CERTIFICATE-----\nMIIB...mock-intermediate...\n-----END CERTIFICATE-----",
];

/**
 * Create a mock macOS native addon.
 */
function createMockMacOsAddon(options?: {
  throwOnList?: boolean;
  throwOnSign?: boolean;
  throwOnGetPublicKey?: boolean;
  includeRsaCerts?: boolean;
  certChain?: string[];
  throwOnGetCertChain?: boolean;
}): MacOsNativeAddon {
  const addon: MacOsNativeAddon = {
    listSigningCertificates(): OsCertInfo[] {
      if (options?.throwOnList) {
        throw new Error("Mock Keychain error");
      }
      return options?.includeRsaCerts ? mockCertificatesWithRsa : mockCertificates;
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

  if (options?.certChain !== undefined || options?.throwOnGetCertChain) {
    addon.getCertificateChain = (_certificateId: string): string[] => {
      if (options?.throwOnGetCertChain) {
        throw new Error("Mock Keychain cert chain error");
      }
      return options?.certChain ?? [];
    };
  }

  return addon;
}

/**
 * Create a mock Windows native addon.
 */
function createMockWindowsAddon(options?: {
  throwOnList?: boolean;
  throwOnSign?: boolean;
  throwOnGetPublicKey?: boolean;
  includeRsaCerts?: boolean;
  certChain?: string[];
  throwOnGetCertChain?: boolean;
}): WindowsNativeAddon {
  const addon: WindowsNativeAddon = {
    listSigningCertificates(): OsCertInfo[] {
      if (options?.throwOnList) {
        throw new Error("Mock CNG error");
      }
      return options?.includeRsaCerts ? mockCertificatesWithRsa : mockCertificates;
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

  if (options?.certChain !== undefined || options?.throwOnGetCertChain) {
    addon.getCertificateChain = (_certificateId: string): string[] => {
      if (options?.throwOnGetCertChain) {
        throw new Error("Mock CNG cert chain error");
      }
      return options?.certChain ?? [];
    };
  }

  return addon;
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
      expect(certs[0].keyAlgorithm).toBe("P-256");
      expect(certs[0].isExportable).toBe(false);
    });

    it("should include RSA certificates in listing", async () => {
      const addon = createMockMacOsAddon({ includeRsaCerts: true });
      const provider = createMacOsCertProvider(addon);

      const certs = await provider.listCertificates();

      expect(certs).toHaveLength(3);
      expect(certs[2].id).toBe("macos-cert-003");
      expect(certs[2].keyAlgorithm).toBe("RSA-2048");
      expect(certs[2].subject).toBe("CN=Carol Davis");
    });

    it("should sign data via macOS Keychain", async () => {
      const addon = createMockMacOsAddon();
      const provider = createMacOsCertProvider(addon);

      const testData = new Uint8Array(64);
      testData.fill(0xcd);

      const signature = await provider.sign("macos-cert-001", testData);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);

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

  describe("signature and key validation", () => {
    it("should reject empty signatures", async () => {
      const emptySignature = Buffer.alloc(0);
      const addon: MacOsNativeAddon = {
        ...createMockMacOsAddon(),
        signWithCertificate: () => emptySignature,
      };
      const provider = createMacOsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(/empty signature/);
    });

    it("should reject empty public keys", async () => {
      const emptyKey = Buffer.alloc(0);
      const addon: MacOsNativeAddon = {
        ...createMockMacOsAddon(),
        getPublicKey: () => emptyKey,
      };
      const provider = createMacOsCertProvider(addon);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(/empty public key/);
    });
  });

  describe("getCertificateChain", () => {
    it("should return certificate chain when addon supports it", async () => {
      const addon = createMockMacOsAddon({ certChain: mockCertChain });
      const provider = createMacOsCertProvider(addon);

      const chain = await provider.getCertificateChain!("macos-cert-001");
      expect(chain).toEqual(mockCertChain);
      expect(chain).toHaveLength(2);
    });

    it("should return empty array when addon does not support getCertificateChain", async () => {
      const addon = createMockMacOsAddon(); // No getCertificateChain
      const provider = createMacOsCertProvider(addon);

      const chain = await provider.getCertificateChain!("macos-cert-001");
      expect(chain).toEqual([]);
    });

    it("should return empty array when getCertificateChain throws", async () => {
      const addon = createMockMacOsAddon({ throwOnGetCertChain: true });
      const provider = createMacOsCertProvider(addon);

      const chain = await provider.getCertificateChain!("macos-cert-001");
      expect(chain).toEqual([]);
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

    it("should include RSA certificates in listing", async () => {
      const addon = createMockWindowsAddon({ includeRsaCerts: true });
      const provider = createWindowsCertProvider(addon);

      const certs = await provider.listCertificates();

      expect(certs).toHaveLength(3);
      expect(certs[2].keyAlgorithm).toBe("RSA-2048");
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

  describe("signature and key validation", () => {
    it("should reject empty signatures", async () => {
      const emptySignature = Buffer.alloc(0);
      const addon: WindowsNativeAddon = {
        ...createMockWindowsAddon(),
        signWithCertificate: () => emptySignature,
      };
      const provider = createWindowsCertProvider(addon);

      const testData = new Uint8Array(32);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(CryptoError);
      await expect(provider.sign("cert-001", testData)).rejects.toThrow(/empty signature/);
    });

    it("should reject empty public keys", async () => {
      const emptyKey = Buffer.alloc(0);
      const addon: WindowsNativeAddon = {
        ...createMockWindowsAddon(),
        getPublicKey: () => emptyKey,
      };
      const provider = createWindowsCertProvider(addon);

      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(CryptoError);
      await expect(provider.getPublicKey("cert-001")).rejects.toThrow(/empty public key/);
    });
  });

  describe("getCertificateChain", () => {
    it("should return certificate chain when addon supports it", async () => {
      const addon = createMockWindowsAddon({ certChain: mockCertChain });
      const provider = createWindowsCertProvider(addon);

      const chain = await provider.getCertificateChain!("win-cert-001");
      expect(chain).toEqual(mockCertChain);
      expect(chain).toHaveLength(2);
    });

    it("should return empty array when addon does not support getCertificateChain", async () => {
      const addon = createMockWindowsAddon(); // No getCertificateChain
      const provider = createWindowsCertProvider(addon);

      const chain = await provider.getCertificateChain!("win-cert-001");
      expect(chain).toEqual([]);
    });

    it("should return empty array when getCertificateChain throws", async () => {
      const addon = createMockWindowsAddon({ throwOnGetCertChain: true });
      const provider = createWindowsCertProvider(addon);

      const chain = await provider.getCertificateChain!("win-cert-001");
      expect(chain).toEqual([]);
    });
  });
});
