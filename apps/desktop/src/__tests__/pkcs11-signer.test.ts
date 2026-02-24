/**
 * Tests for the PKCS#11 signer.
 *
 * Since we cannot require a real hardware token in CI, these tests mock
 * the pkcs11js module to simulate the full PKCS#11 session lifecycle:
 *  - Library initialization
 *  - Session open/PIN/close
 *  - Key enumeration
 *  - Signing via C_Sign
 *  - DER -> raw signature conversion
 *  - Error handling (wrong PIN, no token, etc.)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { CryptoError } from "@opencred/shared";

// ---------------------------------------------------------------------------
// vi.hoisted() — variables available inside the mock factory
//
// IMPORTANT: Do NOT call generateKeyPairSync or createSign here.
// vitest hoists this block above all imports, so node:crypto imports
// are not yet available. Instead we use a hardcoded valid P-256 point.
// ---------------------------------------------------------------------------

const {
  testEcPoint,
  testKeyId,
  mockState,
  resetMockState,
  mockSlotHandle,
  mockSessionHandle,
  mockPrivateKeyHandle,
  mockPublicKeyHandle,
  CONSTS,
} = vi.hoisted(() => {
  // Hardcoded valid P-256 uncompressed point (04 || x || y)
  // This is a well-known test vector: x = all 0x01 (32 bytes), y = all 0x02 (32 bytes)
  // is NOT on the P-256 curve, but we only need a valid-looking 65-byte array for
  // the mock PKCS#11 layer. The publicKeyFromEcPoint function constructs the SPKI
  // from these bytes and lets Node validate. For signer tests where we need a
  // real key, we generate one lazily (see getTestKeyPair below).
  //
  // For utility tests that call publicKeyFromEcPoint, we generate a real key
  // pair AFTER imports resolve.

  const _testKeyId = Buffer.from("01020304", "hex");

  /**
   * Find operation state — supports nesting (outer find for private keys,
   * inner find for public keys within findPublicKeyPoint).
   */
  interface FindState {
    findType: "private" | "public" | null;
    findCallCount: number;
  }

  const _mockState = {
    initialized: false,
    sessionOpen: false,
    loggedIn: false,
    shouldReturnDer: false,
    /** Stack of find operations to support nesting. */
    findStack: [] as FindState[],
    /** Lazily populated with a real EC point once tests set it. */
    realEcPoint: null as Uint8Array | null,
    /** Lazily populated with a signing function. */
    signFn: null as ((data: Buffer, der: boolean) => Buffer) | null,
  };

  const _CONSTS = {
    CKA_CLASS: 0x00000000,
    CKA_LABEL: 0x00000003,
    CKA_ID: 0x00000102,
    CKA_KEY_TYPE: 0x00000100,
    CKA_EC_POINT: 0x00000161,
    CKO_PRIVATE_KEY: 0x00000003,
    CKO_PUBLIC_KEY: 0x00000002,
    CKK_EC: 0x00000003,
    CKF_TOKEN_PRESENT: 0x00000001,
    CKF_SERIAL_SESSION: 0x00000004,
    CKF_RW_SESSION: 0x00000002,
    CKU_USER: 1,
    CKM_ECDSA: 0x00001041,
  };

  function _resetMockState() {
    _mockState.initialized = false;
    _mockState.sessionOpen = false;
    _mockState.loggedIn = false;
    _mockState.shouldReturnDer = false;
    _mockState.findStack = [];
    // Do NOT reset realEcPoint or signFn — they persist across tests
  }

  // A placeholder EC point for the mock. This is replaced with a real one
  // in beforeEach after imports resolve and a real key pair is generated.
  const _placeholderEcPoint = new Uint8Array(65);
  _placeholderEcPoint[0] = 0x04;
  _placeholderEcPoint.fill(0x01, 1, 33);
  _placeholderEcPoint.fill(0x02, 33, 65);

  return {
    testEcPoint: _placeholderEcPoint,
    testKeyId: _testKeyId,
    mockState: _mockState,
    resetMockState: _resetMockState,
    mockSlotHandle: Buffer.from("slot0"),
    mockSessionHandle: Buffer.from("session0"),
    mockPrivateKeyHandle: Buffer.from("privkey0"),
    mockPublicKeyHandle: Buffer.from("pubkey0"),
    CONSTS: _CONSTS,
  };
});

vi.mock("pkcs11js", () => {
  class MockPKCS11 {
    load(_path: string) {
      // Accept any path
    }

    C_Initialize() {
      mockState.initialized = true;
    }

    C_Finalize() {
      mockState.initialized = false;
    }

    C_GetSlotList(_tokenPresent: boolean): Buffer[] {
      if (!mockState.initialized) throw new Error("Not initialized");
      return [mockSlotHandle];
    }

    C_GetSlotInfo(_slot: Buffer) {
      return {
        slotDescription: "Mock PKCS#11 Slot     ",
        flags: CONSTS.CKF_TOKEN_PRESENT,
      };
    }

    C_GetTokenInfo(_slot: Buffer) {
      return {
        label: "Mock Token     ",
        manufacturerID: "Test Mfg     ",
      };
    }

    C_OpenSession(_slot: Buffer, _flags: number): Buffer {
      if (!mockState.initialized) throw new Error("Not initialized");
      mockState.sessionOpen = true;
      return mockSessionHandle;
    }

    C_Login(_session: Buffer, _userType: number, pin: string) {
      if (pin !== "1234") throw new Error("CKR_PIN_INCORRECT");
      mockState.loggedIn = true;
    }

    C_Logout(_session: Buffer) {
      mockState.loggedIn = false;
    }

    C_CloseSession(_session: Buffer) {
      mockState.sessionOpen = false;
      mockState.loggedIn = false;
    }

    C_FindObjectsInit(_session: Buffer, template: Array<{ type: number; value: unknown }>) {
      let findType: "private" | "public" | null = null;
      const classAttr = template.find((a) => a.type === CONSTS.CKA_CLASS);
      if (classAttr) {
        if (classAttr.value === CONSTS.CKO_PRIVATE_KEY) {
          findType = "private";
        } else if (classAttr.value === CONSTS.CKO_PUBLIC_KEY) {
          findType = "public";
        }
      }
      mockState.findStack.push({ findType, findCallCount: 0 });
    }

    C_FindObjects(_session: Buffer): Buffer | null {
      const current = mockState.findStack[mockState.findStack.length - 1];
      if (!current) throw new Error("FindObjectsInit not called");

      if (current.findCallCount === 0) {
        current.findCallCount++;
        return current.findType === "private" ? mockPrivateKeyHandle : mockPublicKeyHandle;
      }
      return null;
    }

    C_FindObjectsFinal(_session: Buffer) {
      mockState.findStack.pop();
    }

    C_GetAttributeValue(
      _session: Buffer,
      _obj: Buffer,
      template: Array<{ type: number; value?: unknown }>,
    ) {
      return template.map((attr) => {
        switch (attr.type) {
          case CONSTS.CKA_LABEL:
            return { type: attr.type, value: Buffer.from("Test Key") };
          case CONSTS.CKA_ID:
            return { type: attr.type, value: testKeyId };
          case CONSTS.CKA_KEY_TYPE: {
            const buf = Buffer.alloc(4);
            buf.writeUInt32LE(CONSTS.CKK_EC);
            return { type: attr.type, value: buf };
          }
          case CONSTS.CKA_EC_POINT:
            // Return the real EC point if available, otherwise the placeholder
            return {
              type: attr.type,
              value: mockState.realEcPoint
                ? Buffer.from(mockState.realEcPoint)
                : Buffer.from(testEcPoint),
            };
          default:
            return { type: attr.type, value: null };
        }
      });
    }

    C_SignInit(
      _session: Buffer,
      mechanism: { mechanism: number },
      _key: Buffer,
    ) {
      if (mechanism.mechanism !== CONSTS.CKM_ECDSA) {
        throw new Error("Unsupported mechanism");
      }
    }

    C_Sign(_session: Buffer, data: Buffer, _outputBuf: Buffer): Buffer {
      // Use the lazily-set signing function
      if (!mockState.signFn) {
        throw new Error("Mock signFn not configured — set mockState.signFn in beforeEach");
      }
      return mockState.signFn(data, mockState.shouldReturnDer);
    }
  }

  return {
    PKCS11: MockPKCS11,
    ...CONSTS,
  };
});

// ---------------------------------------------------------------------------
// Import modules under test (AFTER mock is set up)
// ---------------------------------------------------------------------------

import { generateKeyPairSync, createSign } from "node:crypto";
import { createPkcs11Signer } from "../signing/pkcs11-signer.js";
import {
  initializePkcs11,
  finalizePkcs11,
  listSlots,
  openSession,
  closeSession,
  listKeys,
} from "../signing/pkcs11-session.js";
import {
  publicKeyFromEcPoint,
  deriveDidKeyIdFromPublicKey,
  computeFingerprint,
  normalizeSignature,
} from "../signing/pkcs11-utils.js";

// ---------------------------------------------------------------------------
// Generate a real EC key pair once, after imports resolve.
// This is used to populate the mock state and for utility tests.
// ---------------------------------------------------------------------------

const testKeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const testPublicKeyJwk = testKeyPair.publicKey.export({ format: "jwk" });
const xBytes = Buffer.from(testPublicKeyJwk.x!, "base64url");
const yBytes = Buffer.from(testPublicKeyJwk.y!, "base64url");

/** Real P-256 uncompressed point from the test key pair. */
const realEcPoint = new Uint8Array(65);
realEcPoint[0] = 0x04;
realEcPoint.set(xBytes, 1);
realEcPoint.set(yBytes, 33);

/**
 * Signing function that uses the real test key pair.
 * Called by the mock C_Sign method.
 */
function testSignFn(data: Buffer, useDer: boolean): Buffer {
  const signer = createSign("SHA256");
  signer.update(data);
  return signer.sign({
    key: testKeyPair.privateKey,
    dsaEncoding: useDer ? "der" : "ieee-p1363",
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("PKCS#11 Signer", () => {
  beforeEach(() => {
    resetMockState();
    // Wire up the real EC point and signing function for the mock layer
    mockState.realEcPoint = realEcPoint;
    mockState.signFn = testSignFn;
  });

  describe("createPkcs11Signer", () => {
    it("should create a signer with correct metadata", () => {
      const { signer, availableKeys } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      expect(signer).toBeDefined();
      expect(signer.algorithm).toBe("P-256");
      expect(signer.type).toBe("pkcs11");
      expect(signer.id).toMatch(/^did:key:z/);
      expect(signer.id).toContain("#");
      expect(signer.metadata.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(signer.metadata.type).toBe("pkcs11");
      expect(availableKeys.length).toBeGreaterThan(0);
    });

    it("should produce a 64-byte signature from sign()", async () => {
      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      const testData = new Uint8Array(64);
      testData.fill(0xab);

      const signature = await signer.sign(testData);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });

    it("should handle DER-encoded signatures from token", async () => {
      mockState.shouldReturnDer = true;

      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      const testData = new Uint8Array(64);
      testData.fill(0xcd);

      const signature = await signer.sign(testData);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });

    it("should throw CryptoError on wrong PIN", () => {
      expect(() =>
        createPkcs11Signer({
          libraryPath: "/mock/pkcs11.so",
          pin: "wrong",
        }),
      ).toThrow(CryptoError);
    });

    it("should throw CryptoError when key ID not found", () => {
      expect(() =>
        createPkcs11Signer({
          libraryPath: "/mock/pkcs11.so",
          pin: "1234",
          keyId: "deadbeef",
        }),
      ).toThrow(CryptoError);
    });

    it("should include the label from options or token", () => {
      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
        label: "My YubiKey",
      });

      expect(signer.metadata.label).toBe("My YubiKey");
    });
  });

  describe("sign() method", () => {
    it("should not leak key material in errors", async () => {
      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      const testData = new Uint8Array(64);
      const signature = await signer.sign(testData);

      expect(signature.length).toBe(64);

      const r = signature.slice(0, 32);
      const s = signature.slice(32, 64);
      const allZeroR = r.every((b) => b === 0);
      const allZeroS = s.every((b) => b === 0);
      expect(allZeroR && allZeroS).toBe(false);
    });
  });
});

describe("PKCS#11 Session Manager (from signer test)", () => {
  beforeEach(() => {
    resetMockState();
    mockState.realEcPoint = realEcPoint;
    mockState.signFn = testSignFn;
  });

  describe("initializePkcs11", () => {
    it("should initialize the library", () => {
      const p11 = initializePkcs11("/mock/pkcs11.so");
      expect(p11).toBeDefined();
      finalizePkcs11(p11);
    });
  });

  describe("listSlots", () => {
    it("should return slot information", () => {
      const p11 = initializePkcs11("/mock/pkcs11.so");
      const slots = listSlots(p11);

      expect(slots.length).toBeGreaterThan(0);
      expect(slots[0].description).toContain("Mock");
      expect(slots[0].tokenPresent).toBe(true);
      expect(slots[0].tokenLabel).toContain("Mock Token");

      finalizePkcs11(p11);
    });
  });

  describe("openSession / closeSession", () => {
    it("should open and close a session with correct PIN", () => {
      const p11 = initializePkcs11("/mock/pkcs11.so");
      const session = openSession(p11, 0, "1234");

      expect(session.loggedIn).toBe(true);
      expect(session.slotIndex).toBe(0);

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should throw on wrong PIN", () => {
      const p11 = initializePkcs11("/mock/pkcs11.so");
      expect(() => openSession(p11, 0, "wrong")).toThrow(CryptoError);
      finalizePkcs11(p11);
    });

    it("should throw on invalid slot index", () => {
      const p11 = initializePkcs11("/mock/pkcs11.so");
      expect(() => openSession(p11, 99, "1234")).toThrow(CryptoError);
      finalizePkcs11(p11);
    });
  });

  describe("listKeys", () => {
    it("should return key metadata without key material", () => {
      const p11 = initializePkcs11("/mock/pkcs11.so");
      const session = openSession(p11, 0, "1234");
      const keys = listKeys(session);

      expect(keys.length).toBeGreaterThan(0);
      expect(keys[0].label).toBe("Test Key");
      expect(keys[0].keyType).toBe("EC");
      expect(keys[0].hasPublicKey).toBe(true);
      expect(keys[0].ecPoint).toBeDefined();
      expect(keys[0].ecPoint!.length).toBe(65);
      expect(keys[0].ecPoint![0]).toBe(0x04);

      closeSession(session);
      finalizePkcs11(p11);
    });
  });
});

describe("PKCS#11 Utilities", () => {
  describe("publicKeyFromEcPoint", () => {
    it("should create a KeyObject from valid EC point", () => {
      const keyObj = publicKeyFromEcPoint(realEcPoint);
      expect(keyObj).toBeDefined();

      const jwk = keyObj.export({ format: "jwk" });
      expect(jwk.crv).toBe("P-256");
      expect(jwk.kty).toBe("EC");
    });

    it("should throw on invalid EC point length", () => {
      expect(() => publicKeyFromEcPoint(new Uint8Array(32))).toThrow(CryptoError);
    });

    it("should throw on wrong prefix byte", () => {
      const bad = new Uint8Array(65);
      bad[0] = 0x03;
      expect(() => publicKeyFromEcPoint(bad)).toThrow(CryptoError);
    });
  });

  describe("deriveDidKeyIdFromPublicKey", () => {
    it("should produce a valid did:key ID", () => {
      const keyObj = publicKeyFromEcPoint(realEcPoint);
      const didKeyId = deriveDidKeyIdFromPublicKey(keyObj);

      expect(didKeyId).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);

      const [did, fragment] = didKeyId.split("#");
      const suffix = did.replace("did:key:", "");
      expect(fragment).toBe(suffix);
    });
  });

  describe("computeFingerprint", () => {
    it("should return a hex-encoded SHA-256 fingerprint", () => {
      const keyObj = publicKeyFromEcPoint(realEcPoint);
      const fp = computeFingerprint(keyObj);
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should be deterministic", () => {
      const keyObj = publicKeyFromEcPoint(realEcPoint);
      const fp1 = computeFingerprint(keyObj);
      const fp2 = computeFingerprint(keyObj);
      expect(fp1).toBe(fp2);
    });
  });

  describe("normalizeSignature", () => {
    it("should pass through 64-byte raw signatures unchanged", () => {
      const raw = new Uint8Array(64);
      raw.fill(0xaa, 0, 32);
      raw.fill(0xbb, 32, 64);

      const result = normalizeSignature(raw);
      expect(result.length).toBe(64);
      expect(result).toEqual(raw);
    });

    it("should convert DER-encoded signatures to raw", () => {
      const testData = Buffer.from("test data");
      const signer = createSign("SHA256");
      signer.update(testData);
      const derSig = signer.sign({
        key: testKeyPair.privateKey,
        dsaEncoding: "der",
      });

      const raw = normalizeSignature(new Uint8Array(derSig));
      expect(raw.length).toBe(64);
    });

    it("should throw on unexpected signature length", () => {
      expect(() => normalizeSignature(new Uint8Array(48))).toThrow(CryptoError);
    });
  });
});
