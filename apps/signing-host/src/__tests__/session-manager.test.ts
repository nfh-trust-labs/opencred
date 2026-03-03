/**
 * Tests for the session manager.
 *
 * Mocks @opencred/signing to test the PKCS#11 and OS cert session lifecycles:
 *  - Connect (create signer + session)
 *  - Sign (delegate to signer)
 *  - Disconnect (cleanup session)
 *  - Error handling
 *
 * SECURITY: Verifies that PINs are not stored and key material
 * never appears in outputs.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks — set up before importing the module under test
// ---------------------------------------------------------------------------

const { mockSigner, mockSession, mockSlots, mockKeys, mockOsCertSigner, mockOsCertList } = vi.hoisted(() => {
  const mockSigner = {
    id: "did:key:zTest123#zTest123",
    algorithm: "P-256" as const,
    type: "pkcs11" as const,
    metadata: {
      id: "did:key:zTest123#zTest123",
      algorithm: "P-256" as const,
      type: "pkcs11" as const,
      fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      label: "Test Key",
    },
    sign: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0xaa)),
  };

  const mockSession = {
    pkcs11: {},
    handle: Buffer.from("session0"),
    slotIndex: 0,
    loggedIn: true,
  };

  const mockSlots = [
    {
      index: 0,
      description: "Mock Slot",
      tokenPresent: true,
      tokenLabel: "Mock Token",
      tokenManufacturer: "Test Mfg",
    },
  ];

  const mockKeys = [
    {
      label: "Test Key",
      id: "01020304",
      keyType: "EC",
      hasPublicKey: true,
    },
  ];

  const mockOsCertSigner = {
    id: "did:key:zOsCert456#zOsCert456",
    algorithm: "P-256" as const,
    type: "os-cert" as const,
    metadata: {
      id: "did:key:zOsCert456#zOsCert456",
      algorithm: "P-256" as const,
      type: "os-cert" as const,
      fingerprint: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      label: "OS Cert Key",
    },
    sign: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0xdd)),
  };

  const mockOsCertList = {
    certificates: [
      {
        id: "cert-id-1",
        subject: "CN=Test User",
        issuer: "CN=Test CA",
        serialNumber: "01",
        validFrom: "2024-01-01T00:00:00Z",
        validUntil: "2025-01-01T00:00:00Z",
        keyAlgorithm: "ECDSA P-256",
        isExportable: false,
        thumbprint: "aabb" + "00".repeat(30),
      },
    ],
    platform: "darwin" as const,
    storeName: "macOS Keychain",
  };

  return { mockSigner, mockSession, mockSlots, mockKeys, mockOsCertSigner, mockOsCertList };
});

vi.mock("@opencred/signing", () => {
  const p11Instance = { C_Finalize: vi.fn() };
  return {
    createPkcs11Signer: vi.fn().mockImplementation(() => ({
      signer: mockSigner,
      availableKeys: mockKeys,
      pkcs11Instance: p11Instance,
      session: mockSession,
    })),
    destroyPkcs11Signer: vi.fn(),
    initializePkcs11: vi.fn().mockReturnValue(p11Instance),
    finalizePkcs11: vi.fn(),
    listSlots: vi.fn().mockReturnValue(mockSlots),
    openSession: vi.fn().mockReturnValue(mockSession),
    closeSession: vi.fn(),
    listKeys: vi.fn().mockReturnValue(mockKeys),
    findPrivateKey: vi.fn(),
    listOsCertificates: vi.fn().mockResolvedValue(mockOsCertList),
    createOsCertSigner: vi.fn().mockResolvedValue({ signer: mockOsCertSigner }),
  };
});

vi.mock("pkcs11js", () => {
  class MockPKCS11 {}
  return { PKCS11: MockPKCS11 };
});

// Import after mocks
import {
  pkcs11Detect,
  pkcs11ListSlots,
  pkcs11ListKeys,
  pkcs11Connect,
  pkcs11Sign,
  pkcs11Disconnect,
  oscertList,
  oscertConnect,
  oscertSign,
  oscertDisconnect,
  getSigner,
  getActiveSessionCount,
  disconnectAll,
} from "../session-manager.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Session Manager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clean up any leftover sessions
    disconnectAll();
  });

  describe("pkcs11Detect", () => {
    it("should return available: true when pkcs11js loads", () => {
      const result = pkcs11Detect();
      expect(result.available).toBe(true);
    });
  });

  describe("pkcs11ListSlots", () => {
    it("should return slot information", () => {
      const slots = pkcs11ListSlots("/mock/pkcs11.so");

      expect(slots).toHaveLength(1);
      expect(slots[0].description).toBe("Mock Slot");
      expect(slots[0].tokenPresent).toBe(true);
      expect(slots[0].tokenLabel).toBe("Mock Token");
    });
  });

  describe("pkcs11ListKeys", () => {
    it("should return key metadata", () => {
      const keys = pkcs11ListKeys("/mock/pkcs11.so", 0, "1234");

      expect(keys).toHaveLength(1);
      expect(keys[0].label).toBe("Test Key");
      expect(keys[0].keyType).toBe("EC");
      expect(keys[0].hasPublicKey).toBe(true);
    });

    it("should not include private key material in results", () => {
      const keys = pkcs11ListKeys("/mock/pkcs11.so", 0, "1234");

      for (const key of keys) {
        const keyObj = key as unknown as Record<string, unknown>;
        expect(keyObj["privateKey"]).toBeUndefined();
        expect(keyObj["secret"]).toBeUndefined();
        expect(keyObj["d"]).toBeUndefined();
      }
    });
  });

  describe("pkcs11Connect", () => {
    it("should return a signerId and metadata", () => {
      const result = pkcs11Connect("/mock/pkcs11.so", 0, "1234");

      expect(result.signerId).toBeDefined();
      expect(typeof result.signerId).toBe("string");
      expect(result.signerId.length).toBeGreaterThan(0);
      expect(result.metadata.id).toBe("did:key:zTest123#zTest123");
      expect(result.metadata.algorithm).toBe("P-256");
      expect(result.metadata.type).toBe("pkcs11");
      expect(result.metadata.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should track the session", () => {
      const before = getActiveSessionCount();
      const result = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      const after = getActiveSessionCount();

      expect(after).toBe(before + 1);
      expect(getSigner(result.signerId)).toBe(mockSigner);
    });

    it("should generate unique signerIds", () => {
      const result1 = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      const result2 = pkcs11Connect("/mock/pkcs11.so", 0, "1234");

      expect(result1.signerId).not.toBe(result2.signerId);
    });
  });

  describe("pkcs11Sign", () => {
    it("should sign data and return 64-byte signature", async () => {
      const { signerId } = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      const testData = new Uint8Array(64).fill(0xcd);

      const signature = await pkcs11Sign(signerId, testData);

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
      expect(mockSigner.sign).toHaveBeenCalledWith(testData);
    });

    it("should throw for unknown signerId", async () => {
      const testData = new Uint8Array(64);

      await expect(pkcs11Sign("nonexistent-id", testData)).rejects.toThrow(
        /not found/,
      );
    });
  });

  describe("pkcs11Disconnect", () => {
    it("should remove the session", () => {
      const { signerId } = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      expect(getSigner(signerId)).toBeDefined();

      pkcs11Disconnect(signerId);
      expect(getSigner(signerId)).toBeUndefined();
    });

    it("should reduce active session count", () => {
      const { signerId } = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      const before = getActiveSessionCount();

      pkcs11Disconnect(signerId);
      expect(getActiveSessionCount()).toBe(before - 1);
    });

    it("should be safe to call for already-disconnected signerId", () => {
      expect(() => pkcs11Disconnect("nonexistent-id")).not.toThrow();
    });

    it("should be safe to call twice for same signerId", () => {
      const { signerId } = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      pkcs11Disconnect(signerId);
      expect(() => pkcs11Disconnect(signerId)).not.toThrow();
    });
  });

  describe("disconnectAll", () => {
    it("should remove all active sessions", () => {
      pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      expect(getActiveSessionCount()).toBe(3);

      disconnectAll();
      expect(getActiveSessionCount()).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // OS cert operations
  // -----------------------------------------------------------------------

  describe("oscertList", () => {
    it("should return certificate list", async () => {
      const result = await oscertList("darwin");

      expect(result.certificates).toHaveLength(1);
      expect(result.certificates[0].subject).toBe("CN=Test User");
      expect(result.platform).toBe("darwin");
      expect(result.storeName).toBe("macOS Keychain");
    });
  });

  describe("oscertConnect", () => {
    it("should return a signerId and metadata", async () => {
      const result = await oscertConnect("cert-id-1", "darwin");

      expect(result.signerId).toBeDefined();
      expect(typeof result.signerId).toBe("string");
      expect(result.signerId.length).toBeGreaterThan(0);
      expect(result.metadata.id).toBe("did:key:zOsCert456#zOsCert456");
      expect(result.metadata.algorithm).toBe("P-256");
      expect(result.metadata.type).toBe("os-cert");
    });

    it("should track the session", async () => {
      const before = getActiveSessionCount();
      const result = await oscertConnect("cert-id-1", "darwin");
      const after = getActiveSessionCount();

      expect(after).toBe(before + 1);
      expect(getSigner(result.signerId)).toBe(mockOsCertSigner);
    });

    it("should generate unique signerIds", async () => {
      const result1 = await oscertConnect("cert-id-1", "darwin");
      const result2 = await oscertConnect("cert-id-1", "darwin");

      expect(result1.signerId).not.toBe(result2.signerId);
    });
  });

  describe("oscertSign", () => {
    it("should sign data and return 64-byte signature", async () => {
      const { signerId } = await oscertConnect("cert-id-1", "darwin");
      const testData = new Uint8Array(64).fill(0xcd);

      const signature = await oscertSign(signerId, testData);

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
      expect(mockOsCertSigner.sign).toHaveBeenCalledWith(testData);
    });

    it("should throw for unknown signerId", async () => {
      const testData = new Uint8Array(64);

      await expect(oscertSign("nonexistent-id", testData)).rejects.toThrow(
        /not found/,
      );
    });
  });

  describe("oscertDisconnect", () => {
    it("should remove the session", async () => {
      const { signerId } = await oscertConnect("cert-id-1", "darwin");
      expect(getSigner(signerId)).toBeDefined();

      oscertDisconnect(signerId);
      expect(getSigner(signerId)).toBeUndefined();
    });

    it("should reduce active session count", async () => {
      const { signerId } = await oscertConnect("cert-id-1", "darwin");
      const before = getActiveSessionCount();

      oscertDisconnect(signerId);
      expect(getActiveSessionCount()).toBe(before - 1);
    });

    it("should be safe to call for already-disconnected signerId", () => {
      expect(() => oscertDisconnect("nonexistent-id")).not.toThrow();
    });
  });

  describe("mixed sessions", () => {
    it("should track PKCS#11 and OS cert sessions independently", async () => {
      const pkcs11Result = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      const oscertResult = await oscertConnect("cert-id-1", "darwin");

      expect(getActiveSessionCount()).toBe(2);

      pkcs11Disconnect(pkcs11Result.signerId);
      expect(getActiveSessionCount()).toBe(1);
      expect(getSigner(oscertResult.signerId)).toBeDefined();

      oscertDisconnect(oscertResult.signerId);
      expect(getActiveSessionCount()).toBe(0);
    });

    it("disconnectAll should clean up both types", async () => {
      pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      await oscertConnect("cert-id-1", "darwin");
      await oscertConnect("cert-id-2", "darwin");
      expect(getActiveSessionCount()).toBe(3);

      disconnectAll();
      expect(getActiveSessionCount()).toBe(0);
    });
  });

  describe("security", () => {
    it("should not include PIN in signer metadata", () => {
      const result = pkcs11Connect("/mock/pkcs11.so", 0, "secretpin");
      const metaStr = JSON.stringify(result.metadata);

      expect(metaStr).not.toContain("secretpin");
      expect(metaStr).not.toContain("pin");
    });

    it("should not include key material in signer metadata", () => {
      const result = pkcs11Connect("/mock/pkcs11.so", 0, "1234");
      const metaStr = JSON.stringify(result.metadata);

      expect(metaStr).not.toContain("privateKey");
      expect(metaStr).not.toContain("secret");
    });
  });
});
