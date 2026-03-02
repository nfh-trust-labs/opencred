/**
 * Tests for the request handler.
 *
 * Validates:
 *  - Ping handler returns version and platform
 *  - PKCS#11 handlers dispatch correctly
 *  - Parameter validation for PKCS#11 operations
 *  - OS cert handlers dispatch correctly
 *  - Parameter validation for OS cert operations
 *  - Unknown operation types return an error
 *  - Response format is correct in all cases
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock session-manager so handler tests are isolated
// ---------------------------------------------------------------------------

const { mockPkcs11Metadata, mockOscertMetadata, mockOscertListResult } = vi.hoisted(() => {
  const mockPkcs11Metadata = {
    id: "did:key:zTest#zTest",
    algorithm: "P-256" as const,
    type: "pkcs11" as const,
    fingerprint: "aabbccdd" + "00".repeat(28),
    label: "Test Key",
  };
  const mockOscertMetadata = {
    id: "did:key:zOsCert#zOsCert",
    algorithm: "P-256" as const,
    type: "os-cert" as const,
    fingerprint: "11223344" + "00".repeat(28),
    label: "OS Cert Key",
  };
  const mockOscertListResult = {
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
  return { mockPkcs11Metadata, mockOscertMetadata, mockOscertListResult };
});

vi.mock("../session-manager.js", () => ({
  pkcs11Detect: vi.fn().mockReturnValue({ available: true }),
  pkcs11ListSlots: vi.fn().mockReturnValue([
    { index: 0, description: "Slot 0", tokenPresent: true, tokenLabel: "Token" },
  ]),
  pkcs11ListKeys: vi.fn().mockReturnValue([
    { label: "Key 1", id: "01020304", keyType: "EC", hasPublicKey: true },
  ]),
  pkcs11Connect: vi.fn().mockReturnValue({
    signerId: "test-signer-uuid",
    metadata: mockPkcs11Metadata,
  }),
  pkcs11Sign: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0xbb)),
  pkcs11Disconnect: vi.fn(),
  oscertList: vi.fn().mockResolvedValue(mockOscertListResult),
  oscertConnect: vi.fn().mockResolvedValue({
    signerId: "test-oscert-signer-uuid",
    metadata: mockOscertMetadata,
  }),
  oscertSign: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0xcc)),
  oscertDisconnect: vi.fn(),
}));

import { handleRequest } from "../handler.js";
import { OperationType, type NativeRequest } from "../protocol.js";
import {
  pkcs11ListSlots, pkcs11ListKeys, pkcs11Connect, pkcs11Sign, pkcs11Disconnect,
  oscertList, oscertConnect, oscertSign, oscertDisconnect,
} from "../session-manager.js";

function makeRequest(type: string, payload: Record<string, unknown> = {}): NativeRequest {
  return {
    id: `test-${type}-${Date.now()}`,
    type: type as NativeRequest["type"],
    origin: "chrome-extension://test",
    payload,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleRequest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -----------------------------------------------------------------------
  // Ping
  // -----------------------------------------------------------------------

  describe("ping", () => {
    it("should return version and platform", async () => {
      const request = makeRequest(OperationType.PING);
      const response = await handleRequest(request);

      expect(response.id).toBe(request.id);
      expect(response.success).toBe(true);
      expect(response.result!["version"]).toBe("0.1.0");
      expect(typeof response.result!["platform"]).toBe("string");
    });
  });

  // -----------------------------------------------------------------------
  // PKCS#11 detect
  // -----------------------------------------------------------------------

  describe("pkcs11_detect", () => {
    it("should return available status", async () => {
      const response = await handleRequest(makeRequest(OperationType.PKCS11_DETECT));

      expect(response.success).toBe(true);
      expect(response.result!["available"]).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // PKCS#11 list_slots
  // -----------------------------------------------------------------------

  describe("pkcs11_list_slots", () => {
    it("should return slots when libraryPath is provided", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_LIST_SLOTS, { libraryPath: "/mock/lib.so" }),
      );

      expect(response.success).toBe(true);
      expect(pkcs11ListSlots).toHaveBeenCalledWith("/mock/lib.so");
      const slots = response.result!["slots"] as unknown[];
      expect(slots).toHaveLength(1);
    });

    it("should return error when libraryPath is missing", async () => {
      const response = await handleRequest(makeRequest(OperationType.PKCS11_LIST_SLOTS));

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
      expect(response.error!.message).toContain("libraryPath");
    });
  });

  // -----------------------------------------------------------------------
  // PKCS#11 list_keys
  // -----------------------------------------------------------------------

  describe("pkcs11_list_keys", () => {
    it("should return keys when all params are provided", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_LIST_KEYS, {
          libraryPath: "/mock/lib.so",
          slotIndex: 0,
          pin: "1234",
        }),
      );

      expect(response.success).toBe(true);
      expect(pkcs11ListKeys).toHaveBeenCalledWith("/mock/lib.so", 0, "1234");
      const keys = response.result!["keys"] as unknown[];
      expect(keys).toHaveLength(1);
    });

    it("should return error when libraryPath is missing", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_LIST_KEYS, { slotIndex: 0, pin: "1234" }),
      );

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });

    it("should return error when slotIndex is missing", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_LIST_KEYS, { libraryPath: "/lib.so", pin: "1234" }),
      );

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });

    it("should return error when pin is missing", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_LIST_KEYS, { libraryPath: "/lib.so", slotIndex: 0 }),
      );

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });
  });

  // -----------------------------------------------------------------------
  // PKCS#11 connect
  // -----------------------------------------------------------------------

  describe("pkcs11_connect", () => {
    it("should return signerId and metadata", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_CONNECT, {
          libraryPath: "/mock/lib.so",
          slotIndex: 0,
          pin: "1234",
        }),
      );

      expect(response.success).toBe(true);
      expect(response.result!["signerId"]).toBe("test-signer-uuid");
      const meta = response.result!["metadata"] as Record<string, unknown>;
      expect(meta["id"]).toBe("did:key:zTest#zTest");
      expect(meta["algorithm"]).toBe("P-256");
      expect(meta["type"]).toBe("pkcs11");
    });

    it("should pass optional keyId and label", async () => {
      await handleRequest(
        makeRequest(OperationType.PKCS11_CONNECT, {
          libraryPath: "/mock/lib.so",
          slotIndex: 0,
          pin: "1234",
          keyId: "aabb",
          label: "My Key",
        }),
      );

      expect(pkcs11Connect).toHaveBeenCalledWith("/mock/lib.so", 0, "1234", "aabb", "My Key");
    });

    it("should return error when required params are missing", async () => {
      const response = await handleRequest(makeRequest(OperationType.PKCS11_CONNECT));

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });
  });

  // -----------------------------------------------------------------------
  // PKCS#11 sign
  // -----------------------------------------------------------------------

  describe("pkcs11_sign", () => {
    it("should return base64 signature", async () => {
      const testData = Buffer.from(new Uint8Array(64).fill(0xcd)).toString("base64");

      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_SIGN, {
          signerId: "test-signer-uuid",
          data: testData,
        }),
      );

      expect(response.success).toBe(true);
      expect(typeof response.result!["signature"]).toBe("string");
      // Decode and verify it's 64 bytes
      const sigBytes = Buffer.from(response.result!["signature"] as string, "base64");
      expect(sigBytes.length).toBe(64);
    });

    it("should call pkcs11Sign with decoded data", async () => {
      const rawData = new Uint8Array(32).fill(0xab);
      const b64Data = Buffer.from(rawData).toString("base64");

      await handleRequest(
        makeRequest(OperationType.PKCS11_SIGN, {
          signerId: "test-signer-uuid",
          data: b64Data,
        }),
      );

      expect(pkcs11Sign).toHaveBeenCalledWith("test-signer-uuid", expect.any(Uint8Array));
    });

    it("should return error when signerId is missing", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_SIGN, { data: "AAAA" }),
      );

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });

    it("should return error when data is missing", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_SIGN, { signerId: "id" }),
      );

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });
  });

  // -----------------------------------------------------------------------
  // PKCS#11 disconnect
  // -----------------------------------------------------------------------

  describe("pkcs11_disconnect", () => {
    it("should disconnect successfully", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.PKCS11_DISCONNECT, { signerId: "test-signer-uuid" }),
      );

      expect(response.success).toBe(true);
      expect(pkcs11Disconnect).toHaveBeenCalledWith("test-signer-uuid");
    });

    it("should return error when signerId is missing", async () => {
      const response = await handleRequest(makeRequest(OperationType.PKCS11_DISCONNECT));

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });
  });

  // -----------------------------------------------------------------------
  // OS cert list
  // -----------------------------------------------------------------------

  describe("oscert_list", () => {
    it("should return certificates", async () => {
      const response = await handleRequest(makeRequest(OperationType.OSCERT_LIST));

      expect(response.success).toBe(true);
      expect(oscertList).toHaveBeenCalled();
      const certs = response.result!["certificates"] as unknown[];
      expect(certs).toHaveLength(1);
      expect(response.result!["platform"]).toBe("darwin");
      expect(response.result!["storeName"]).toBe("macOS Keychain");
    });

    it("should pass platform override", async () => {
      await handleRequest(makeRequest(OperationType.OSCERT_LIST, { platform: "win32" }));

      expect(oscertList).toHaveBeenCalledWith("win32");
    });
  });

  // -----------------------------------------------------------------------
  // OS cert connect
  // -----------------------------------------------------------------------

  describe("oscert_connect", () => {
    it("should return signerId and metadata", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.OSCERT_CONNECT, { certificateId: "cert-id-1" }),
      );

      expect(response.success).toBe(true);
      expect(response.result!["signerId"]).toBe("test-oscert-signer-uuid");
      const meta = response.result!["metadata"] as Record<string, unknown>;
      expect(meta["id"]).toBe("did:key:zOsCert#zOsCert");
      expect(meta["algorithm"]).toBe("P-256");
      expect(meta["type"]).toBe("os-cert");
    });

    it("should pass optional platform and label", async () => {
      await handleRequest(
        makeRequest(OperationType.OSCERT_CONNECT, {
          certificateId: "cert-id-1",
          platform: "win32",
          label: "My Cert",
        }),
      );

      expect(oscertConnect).toHaveBeenCalledWith("cert-id-1", "win32", "My Cert");
    });

    it("should return error when certificateId is missing", async () => {
      const response = await handleRequest(makeRequest(OperationType.OSCERT_CONNECT));

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
      expect(response.error!.message).toContain("certificateId");
    });
  });

  // -----------------------------------------------------------------------
  // OS cert sign
  // -----------------------------------------------------------------------

  describe("oscert_sign", () => {
    it("should return base64 signature", async () => {
      const testData = Buffer.from(new Uint8Array(64).fill(0xcd)).toString("base64");

      const response = await handleRequest(
        makeRequest(OperationType.OSCERT_SIGN, {
          signerId: "test-oscert-signer-uuid",
          data: testData,
        }),
      );

      expect(response.success).toBe(true);
      expect(typeof response.result!["signature"]).toBe("string");
      const sigBytes = Buffer.from(response.result!["signature"] as string, "base64");
      expect(sigBytes.length).toBe(64);
    });

    it("should call oscertSign with decoded data", async () => {
      const rawData = new Uint8Array(32).fill(0xab);
      const b64Data = Buffer.from(rawData).toString("base64");

      await handleRequest(
        makeRequest(OperationType.OSCERT_SIGN, {
          signerId: "test-oscert-signer-uuid",
          data: b64Data,
        }),
      );

      expect(oscertSign).toHaveBeenCalledWith("test-oscert-signer-uuid", expect.any(Uint8Array));
    });

    it("should return error when signerId is missing", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.OSCERT_SIGN, { data: "AAAA" }),
      );

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });

    it("should return error when data is missing", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.OSCERT_SIGN, { signerId: "id" }),
      );

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });
  });

  // -----------------------------------------------------------------------
  // OS cert disconnect
  // -----------------------------------------------------------------------

  describe("oscert_disconnect", () => {
    it("should disconnect successfully", async () => {
      const response = await handleRequest(
        makeRequest(OperationType.OSCERT_DISCONNECT, { signerId: "test-oscert-signer-uuid" }),
      );

      expect(response.success).toBe(true);
      expect(oscertDisconnect).toHaveBeenCalledWith("test-oscert-signer-uuid");
    });

    it("should return error when signerId is missing", async () => {
      const response = await handleRequest(makeRequest(OperationType.OSCERT_DISCONNECT));

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("INVALID_PARAMS");
    });
  });

  // -----------------------------------------------------------------------
  // Unknown operations
  // -----------------------------------------------------------------------

  describe("unknown operation type", () => {
    it("should return UNKNOWN_OPERATION error", async () => {
      const response = await handleRequest(makeRequest("totally_bogus"));

      expect(response.success).toBe(false);
      expect(response.error!.code).toBe("UNKNOWN_OPERATION");
    });
  });

  // -----------------------------------------------------------------------
  // Response format
  // -----------------------------------------------------------------------

  describe("response format", () => {
    it("should always include the request id", async () => {
      const request = makeRequest(OperationType.PING);
      request.id = "specific-id-12345";
      const response = await handleRequest(request);

      expect(response.id).toBe("specific-id-12345");
    });
  });
});
