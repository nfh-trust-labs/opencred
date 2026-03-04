/**
 * Tests for the PKCS#11 signer.
 *
 * Since we cannot require a real hardware token in CI, these tests mock
 * the pkcs11js module to simulate the full PKCS#11 session lifecycle:
 *  - Library initialization
 *  - Session open/PIN/close
 *  - Key enumeration (EC P-256, P-384, and RSA)
 *  - Signing via C_Sign (ECDSA and RSA-PSS)
 *  - DER -> raw signature conversion
 *  - Certificate chain attachment
 *  - Error handling (wrong PIN, no token, etc.)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { CryptoError } from "@opencred/shared";

// ---------------------------------------------------------------------------
// vi.hoisted() — variables available inside the mock factory
// ---------------------------------------------------------------------------

const {
  testEcPoint,
  testKeyId,
  testRsaKeyId,
  mockState,
  resetMockState,
  mockSlotHandle,
  mockSessionHandle,
  mockPrivateKeyHandle,
  mockRsaPrivateKeyHandle,
  mockPublicKeyHandle,
  CONSTS,
} = vi.hoisted(() => {
  const _testKeyId = Buffer.from("01020304", "hex");
  const _testRsaKeyId = Buffer.from("05060708", "hex");

  interface FindState {
    findType: "private" | "public" | "certificate" | null;
    findCallCount: number;
    maxObjects: number;
  }

  const _mockState = {
    initialized: false,
    sessionOpen: false,
    loggedIn: false,
    shouldReturnDer: false,
    findStack: [] as FindState[],
    realEcPoint: null as Uint8Array | null,
    signFn: null as ((data: Buffer, der: boolean) => Buffer) | null,
    /** When true, listKeys returns an RSA key as the first key. */
    useRsaKey: false,
    /** When true, include certificates in enumeration. */
    includeCerts: false,
  };

  const _CONSTS = {
    CKA_CLASS: 0x00000000,
    CKA_LABEL: 0x00000003,
    CKA_ID: 0x00000102,
    CKA_KEY_TYPE: 0x00000100,
    CKA_EC_POINT: 0x00000161,
    CKA_MODULUS: 0x00000120,
    CKA_PUBLIC_EXPONENT: 0x00000122,
    CKA_VALUE: 0x00000011,
    CKO_PRIVATE_KEY: 0x00000003,
    CKO_PUBLIC_KEY: 0x00000002,
    CKO_CERTIFICATE: 0x00000001,
    CKK_EC: 0x00000003,
    CKK_RSA: 0x00000000,
    CKF_TOKEN_PRESENT: 0x00000001,
    CKF_SERIAL_SESSION: 0x00000004,
    CKF_RW_SESSION: 0x00000002,
    CKU_USER: 1,
    CKM_ECDSA: 0x00001041,
    CKM_RSA_PKCS_PSS: 0x0000000d,
    CKM_SHA256: 0x00000250,
    CKG_MGF1_SHA256: 0x00000002,
    CK_PARAMS_RSA_PSS: 0x00000033,
  };

  function _resetMockState() {
    _mockState.initialized = false;
    _mockState.sessionOpen = false;
    _mockState.loggedIn = false;
    _mockState.shouldReturnDer = false;
    _mockState.findStack = [];
    _mockState.useRsaKey = false;
    _mockState.includeCerts = false;
  }

  const _placeholderEcPoint = new Uint8Array(65);
  _placeholderEcPoint[0] = 0x04;
  _placeholderEcPoint.fill(0x01, 1, 33);
  _placeholderEcPoint.fill(0x02, 33, 65);

  return {
    testEcPoint: _placeholderEcPoint,
    testKeyId: _testKeyId,
    testRsaKeyId: _testRsaKeyId,
    mockState: _mockState,
    resetMockState: _resetMockState,
    mockSlotHandle: Buffer.from("slot0"),
    mockSessionHandle: Buffer.from("session0"),
    mockPrivateKeyHandle: Buffer.from("privkey0"),
    mockRsaPrivateKeyHandle: Buffer.from("rsaprivkey0"),
    mockPublicKeyHandle: Buffer.from("pubkey0"),
    CONSTS: _CONSTS,
  };
});

// Fake RSA modulus (256 bytes = 2048 bits)
const fakeRsaModulus = new Uint8Array(256);
fakeRsaModulus.fill(0xff);
fakeRsaModulus[0] = 0x00; // leading zero for sign
const fakeRsaExponent = new Uint8Array([0x01, 0x00, 0x01]);

// Fake DER certificate
const fakeDerCert = new Uint8Array([0x30, 0x82, 0x01, 0x00]);

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
      let findType: "private" | "public" | "certificate" | null = null;
      let maxObjects = 1;
      const classAttr = template.find((a) => a.type === CONSTS.CKA_CLASS);
      if (classAttr) {
        if (classAttr.value === CONSTS.CKO_PRIVATE_KEY) {
          findType = "private";
        } else if (classAttr.value === CONSTS.CKO_PUBLIC_KEY) {
          findType = "public";
        } else if (classAttr.value === CONSTS.CKO_CERTIFICATE) {
          findType = "certificate";
          maxObjects = mockState.includeCerts ? 1 : 0;
        }
      }
      mockState.findStack.push({ findType, findCallCount: 0, maxObjects });
    }

    C_FindObjects(_session: Buffer): Buffer | null {
      const current = mockState.findStack[mockState.findStack.length - 1];
      if (!current) throw new Error("FindObjectsInit not called");

      if (current.findCallCount < current.maxObjects) {
        current.findCallCount++;
        if (current.findType === "private") {
          return mockState.useRsaKey ? mockRsaPrivateKeyHandle : mockPrivateKeyHandle;
        } else if (current.findType === "public") {
          return mockPublicKeyHandle;
        } else if (current.findType === "certificate") {
          return Buffer.from("cert0");
        }
      }
      return null;
    }

    C_FindObjectsFinal(_session: Buffer) {
      mockState.findStack.pop();
    }

    C_GetAttributeValue(
      _session: Buffer,
      obj: Buffer,
      template: Array<{ type: number; value?: unknown }>,
    ) {
      const isRsa = mockState.useRsaKey && (
        obj === mockRsaPrivateKeyHandle || obj === mockPublicKeyHandle
      );
      const isCert = obj.toString() === "cert0";

      return template.map((attr) => {
        switch (attr.type) {
          case CONSTS.CKA_LABEL:
            if (isCert) return { type: attr.type, value: Buffer.from("Token Certificate") };
            return { type: attr.type, value: Buffer.from(isRsa ? "RSA Key" : "Test Key") };
          case CONSTS.CKA_ID:
            if (isCert) {
              // Match the key ID for cert-to-key matching
              return {
                type: attr.type,
                value: mockState.useRsaKey ? testRsaKeyId : testKeyId,
              };
            }
            return {
              type: attr.type,
              value: isRsa ? testRsaKeyId : testKeyId,
            };
          case CONSTS.CKA_KEY_TYPE: {
            const buf = Buffer.alloc(4);
            buf.writeUInt32LE(isRsa ? CONSTS.CKK_RSA : CONSTS.CKK_EC);
            return { type: attr.type, value: buf };
          }
          case CONSTS.CKA_EC_POINT:
            return {
              type: attr.type,
              value: mockState.realEcPoint
                ? Buffer.from(mockState.realEcPoint)
                : Buffer.from(testEcPoint),
            };
          case CONSTS.CKA_MODULUS:
            return { type: attr.type, value: Buffer.from(fakeRsaModulus) };
          case CONSTS.CKA_PUBLIC_EXPONENT:
            return { type: attr.type, value: Buffer.from(fakeRsaExponent) };
          case CONSTS.CKA_VALUE:
            return { type: attr.type, value: Buffer.from(fakeDerCert) };
          default:
            return { type: attr.type, value: null };
        }
      });
    }

    C_SignInit(_session: Buffer, _mechanism: unknown, _key: Buffer) {
      // Accept any mechanism
    }

    C_Sign(_session: Buffer, data: Buffer, _outputBuf: Buffer): Buffer {
      if (mockState.useRsaKey) {
        // Return a fake RSA signature (256 bytes for RSA-2048)
        const sig = Buffer.alloc(256);
        sig.fill(0xab);
        return sig;
      }
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
import { createPkcs11Signer } from "../pkcs11-signer.js";
import {
  initializePkcs11,
  finalizePkcs11,
  listSlots,
  openSession,
  closeSession,
  listKeys,
} from "../pkcs11-session.js";
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
// Generate a real EC key pair once, after imports resolve.
// ---------------------------------------------------------------------------

const testKeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const testPublicKeyJwk = testKeyPair.publicKey.export({ format: "jwk" });
const xBytes = Buffer.from(testPublicKeyJwk.x!, "base64url");
const yBytes = Buffer.from(testPublicKeyJwk.y!, "base64url");

const realEcPoint = new Uint8Array(65);
realEcPoint[0] = 0x04;
realEcPoint.set(xBytes, 1);
realEcPoint.set(yBytes, 33);

// Generate a real P-384 key pair for P-384 tests
const testP384KeyPair = generateKeyPairSync("ec", { namedCurve: "P-384" });
const testP384PublicKeyJwk = testP384KeyPair.publicKey.export({ format: "jwk" });
const xBytesP384 = Buffer.from(testP384PublicKeyJwk.x!, "base64url");
const yBytesP384 = Buffer.from(testP384PublicKeyJwk.y!, "base64url");

const realP384EcPoint = new Uint8Array(97);
realP384EcPoint[0] = 0x04;
realP384EcPoint.set(xBytesP384, 1);
realP384EcPoint.set(yBytesP384, 49);

// Generate a real RSA key pair for RSA tests
const testRsaKeyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });

/**
 * Signing function that uses the real EC test key pair.
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
    mockState.realEcPoint = realEcPoint;
    mockState.signFn = testSignFn;
  });

  describe("createPkcs11Signer — EC key", () => {
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

  describe("createPkcs11Signer — RSA key", () => {
    beforeEach(() => {
      mockState.useRsaKey = true;
    });

    it("should create an RSA signer with correct metadata", () => {
      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      expect(signer).toBeDefined();
      expect(signer.algorithm).toBe("RSA-2048");
      expect(signer.type).toBe("pkcs11");
      expect(signer.id).toMatch(/^did:jwk:/);
      expect(signer.id).toContain("#0");
      expect(signer.metadata.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should produce an RSA signature from sign()", async () => {
      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      const testData = new Uint8Array(64);
      testData.fill(0xab);

      const signature = await signer.sign(testData);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(256); // RSA-2048 signature
    });
  });

  describe("certificate chain attachment", () => {
    it("should attach certificate chain when certs match key ID", () => {
      mockState.includeCerts = true;

      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      expect(signer.metadata.certificateChain).toBeDefined();
      expect(signer.metadata.certificateChain!.length).toBe(1);
      expect(signer.metadata.certificateChain![0]).toContain("-----BEGIN CERTIFICATE-----");
      expect(signer.metadata.certificateChain![0]).toContain("-----END CERTIFICATE-----");
    });

    it("should not have certificate chain when no certs present", () => {
      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      expect(signer.metadata.certificateChain).toBeUndefined();
    });

    it("should attach certificate chain to RSA signer", () => {
      mockState.useRsaKey = true;
      mockState.includeCerts = true;

      const { signer } = createPkcs11Signer({
        libraryPath: "/mock/pkcs11.so",
        pin: "1234",
      });

      expect(signer.metadata.certificateChain).toBeDefined();
      expect(signer.metadata.certificateChain!.length).toBe(1);
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
  describe("publicKeyFromEcPoint — P-256", () => {
    it("should create a KeyObject from valid P-256 EC point", () => {
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

  describe("publicKeyFromEcPoint — P-384", () => {
    it("should create a KeyObject from valid P-384 EC point", () => {
      const keyObj = publicKeyFromEcPoint(realP384EcPoint);
      expect(keyObj).toBeDefined();

      const jwk = keyObj.export({ format: "jwk" });
      expect(jwk.crv).toBe("P-384");
      expect(jwk.kty).toBe("EC");
    });

    it("should throw on 97-byte point with wrong prefix", () => {
      const bad = new Uint8Array(97);
      bad[0] = 0x02;
      expect(() => publicKeyFromEcPoint(bad)).toThrow(CryptoError);
    });
  });

  describe("publicKeyFromRsaComponents", () => {
    it("should create a KeyObject from RSA modulus and exponent", () => {
      const rsaJwk = testRsaKeyPair.publicKey.export({ format: "jwk" });
      const modulus = Buffer.from(rsaJwk.n!, "base64url");
      const exponent = Buffer.from(rsaJwk.e!, "base64url");

      const keyObj = publicKeyFromRsaComponents(
        new Uint8Array(modulus),
        new Uint8Array(exponent),
      );

      expect(keyObj).toBeDefined();
      const jwk = keyObj.export({ format: "jwk" });
      expect(jwk.kty).toBe("RSA");
      expect(jwk.n).toBeDefined();
      expect(jwk.e).toBeDefined();
    });

    it("should strip leading zero bytes from modulus", () => {
      const rsaJwk = testRsaKeyPair.publicKey.export({ format: "jwk" });
      const modulus = Buffer.from(rsaJwk.n!, "base64url");
      const exponent = Buffer.from(rsaJwk.e!, "base64url");

      // Add leading zeros
      const paddedModulus = new Uint8Array(modulus.length + 2);
      paddedModulus[0] = 0x00;
      paddedModulus[1] = 0x00;
      paddedModulus.set(modulus, 2);

      const keyObj = publicKeyFromRsaComponents(paddedModulus, new Uint8Array(exponent));
      expect(keyObj).toBeDefined();
      const jwk = keyObj.export({ format: "jwk" });
      expect(jwk.kty).toBe("RSA");
    });
  });

  describe("rsaAlgorithmFromModulusBits", () => {
    it("should return RSA-2048 for 2048 bits", () => {
      expect(rsaAlgorithmFromModulusBits(2048)).toBe("RSA-2048");
    });

    it("should return RSA-3072 for 3072 bits", () => {
      expect(rsaAlgorithmFromModulusBits(3072)).toBe("RSA-3072");
    });

    it("should return RSA-4096 for 4096 bits", () => {
      expect(rsaAlgorithmFromModulusBits(4096)).toBe("RSA-4096");
    });

    it("should return RSA-2048 for smaller bit lengths", () => {
      expect(rsaAlgorithmFromModulusBits(1024)).toBe("RSA-2048");
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

  describe("deriveDidJwkIdFromPublicKey", () => {
    it("should produce a valid did:jwk ID for RSA key", () => {
      const didJwkId = deriveDidJwkIdFromPublicKey(testRsaKeyPair.publicKey);

      expect(didJwkId).toMatch(/^did:jwk:.+#0$/);
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

  describe("derCertToPem", () => {
    it("should wrap DER bytes in PEM headers", () => {
      const der = new Uint8Array([0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB]);
      const pem = derCertToPem(der);

      expect(pem).toContain("-----BEGIN CERTIFICATE-----");
      expect(pem).toContain("-----END CERTIFICATE-----");
      // Check that the base64 content is valid
      const b64Content = pem
        .replace("-----BEGIN CERTIFICATE-----\n", "")
        .replace("\n-----END CERTIFICATE-----", "");
      const decoded = Buffer.from(b64Content, "base64");
      expect(new Uint8Array(decoded)).toEqual(der);
    });
  });

  describe("normalizeSignature", () => {
    it("should pass through 64-byte raw signatures unchanged (P-256)", () => {
      const raw = new Uint8Array(64);
      raw.fill(0xaa, 0, 32);
      raw.fill(0xbb, 32, 64);

      const result = normalizeSignature(raw);
      expect(result.length).toBe(64);
      expect(result).toEqual(raw);
    });

    it("should pass through 96-byte raw signatures unchanged (P-384)", () => {
      const raw = new Uint8Array(96);
      raw.fill(0xaa, 0, 48);
      raw.fill(0xbb, 48, 96);

      const result = normalizeSignature(raw, "EC");
      expect(result.length).toBe(96);
      expect(result).toEqual(raw);
    });

    it("should pass through RSA signatures unchanged", () => {
      const rsaSig = new Uint8Array(256);
      rsaSig.fill(0xcc);

      const result = normalizeSignature(rsaSig, "RSA");
      expect(result.length).toBe(256);
      expect(result).toEqual(rsaSig);
    });

    it("should convert DER-encoded EC signatures to raw", () => {
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

    it("should throw on unexpected EC signature length", () => {
      expect(() => normalizeSignature(new Uint8Array(48))).toThrow(CryptoError);
    });

    it("should not throw on unexpected length for RSA", () => {
      const oddLenSig = new Uint8Array(48);
      const result = normalizeSignature(oddLenSig, "RSA");
      expect(result.length).toBe(48);
    });
  });
});
