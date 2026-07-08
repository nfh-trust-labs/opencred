/**
 * Tests for the PKCS#11 session manager.
 *
 * Uses a mock of pkcs11js to test session lifecycle, slot enumeration,
 * key discovery (EC and RSA), certificate discovery, and error handling
 * without requiring real hardware.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { CryptoError } from "@opencred/shared";

// ---------------------------------------------------------------------------
// vi.hoisted() — variables available inside the mock factory
// ---------------------------------------------------------------------------

const { mockState, resetMocks, testKeyId, testEcPoint, testRsaKeyId, CONSTS } = vi.hoisted(() => {
  /**
   * Find operation state — supports nesting (outer find for private keys,
   * inner find for public keys within findPublicKeyPoint).
   */
  interface FindState {
    findType: "private" | "public" | "certificate" | null;
    findCallCount: number;
    /** For private key finds, cycle through both EC and RSA keys. */
    maxObjects: number;
  }

  const _mockState = {
    initialized: false,
    sessionCount: 0,
    loadShouldFail: false,
    /** Stack of find operations to support nesting. */
    findStack: [] as FindState[],
    /** Whether to include RSA keys in enumeration. */
    includeRsaKeys: false,
    /** Whether to include certificates in enumeration. */
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
  };

  const _testKeyId = Buffer.from("aabb", "hex");
  const _testRsaKeyId = Buffer.from("ccdd", "hex");

  // Minimal valid uncompressed P-256 point (65 bytes, prefix 0x04)
  const _testEcPoint = new Uint8Array(65);
  _testEcPoint[0] = 0x04;
  _testEcPoint.fill(0x01, 1, 33);
  _testEcPoint.fill(0x02, 33, 65);

  function _resetMocks() {
    _mockState.initialized = false;
    _mockState.sessionCount = 0;
    _mockState.loadShouldFail = false;
    _mockState.findStack = [];
    _mockState.includeRsaKeys = false;
    _mockState.includeCerts = false;
  }

  return {
    mockState: _mockState,
    resetMocks: _resetMocks,
    testKeyId: _testKeyId,
    testRsaKeyId: _testRsaKeyId,
    testEcPoint: _testEcPoint,
    CONSTS: _CONSTS,
  };
});

// A fake RSA modulus (256 bytes = 2048 bits)
const fakeRsaModulus = new Uint8Array(256);
fakeRsaModulus.fill(0x01);
// A fake RSA public exponent (3 bytes = 65537)
const fakeRsaExponent = new Uint8Array([0x01, 0x00, 0x01]);

// A fake DER certificate
const fakeDerCert = new Uint8Array([0x30, 0x82, 0x01, 0x00, 0xaa, 0xbb, 0xcc]);

vi.mock("../pkcs11-loader.js", () => {
  // Build the mock pkcs11js module inline, then export it via loadPkcs11js()
  return {
    loadPkcs11js: () => mockPkcs11Module,
  };
});

const mockPkcs11Module = (() => {
  class MockPKCS11 {
    load(_path: string) {
      if (mockState.loadShouldFail) throw new Error("Cannot load library");
    }

    C_Initialize() {
      mockState.initialized = true;
    }

    C_Finalize() {
      mockState.initialized = false;
    }

    C_GetSlotList(tokenPresent: boolean): Buffer[] {
      if (!mockState.initialized) throw new Error("Not initialized");
      if (tokenPresent) {
        return [Buffer.from("slot0")];
      }
      return [Buffer.from("slot0"), Buffer.from("slot1-empty")];
    }

    C_GetSlotInfo(slot: Buffer) {
      const isFirstSlot = slot.toString() === "slot0";
      return {
        slotDescription: isFirstSlot ? "Virtual Token Slot    " : "Empty Slot            ",
        flags: isFirstSlot ? CONSTS.CKF_TOKEN_PRESENT : 0,
      };
    }

    C_GetTokenInfo(_slot: Buffer) {
      return {
        label: "Test SmartCard     ",
        manufacturerID: "OpenSC Project    ",
      };
    }

    C_OpenSession(_slot: Buffer, _flags: number): Buffer {
      mockState.sessionCount++;
      return Buffer.from(`sess${mockState.sessionCount}`);
    }

    C_Login(_session: Buffer, _userType: number, pin: string) {
      if (pin === "wrong") throw new Error("CKR_PIN_INCORRECT");
      if (pin === "locked") throw new Error("CKR_PIN_LOCKED");
    }

    C_Logout(_session: Buffer) {
      // no-op
    }

    C_CloseSession(_session: Buffer) {
      mockState.sessionCount--;
    }

    C_FindObjectsInit(_session: Buffer, template: Array<{ type: number; value: unknown }>) {
      let findType: "private" | "public" | "certificate" | null = null;
      let maxObjects = 1;
      const classAttr = template.find((a) => a.type === CONSTS.CKA_CLASS);
      if (classAttr) {
        if (classAttr.value === CONSTS.CKO_PRIVATE_KEY) {
          findType = "private";
          // Return 2 keys when RSA is included
          if (mockState.includeRsaKeys) maxObjects = 2;
        } else if (classAttr.value === CONSTS.CKO_PUBLIC_KEY) {
          findType = "public";
        } else if (classAttr.value === CONSTS.CKO_CERTIFICATE) {
          findType = "certificate";
          if (mockState.includeCerts) maxObjects = 1;
          else maxObjects = 0;
        }
      }
      mockState.findStack.push({ findType, findCallCount: 0, maxObjects });
    }

    C_FindObjects(_session: Buffer): Buffer | null {
      const current = mockState.findStack[mockState.findStack.length - 1];
      if (!current) return null;

      if (current.findCallCount < current.maxObjects) {
        const idx = current.findCallCount;
        current.findCallCount++;

        if (current.findType === "private") {
          return idx === 0 ? Buffer.from("privkey0") : Buffer.from("privkey1");
        } else if (current.findType === "public") {
          return Buffer.from("pubkey0");
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
      const objName = obj.toString();
      const isRsaKey = objName === "privkey1" || (objName === "pubkey0" && this._lastFindForRsa);
      const isCert = objName === "cert0";

      return template.map((attr) => {
        switch (attr.type) {
          case CONSTS.CKA_LABEL:
            if (isCert) return { type: attr.type, value: Buffer.from("Token Certificate") };
            return {
              type: attr.type,
              value: Buffer.from(isRsaKey ? "RSA Key 1" : "Signing Key 1"),
            };
          case CONSTS.CKA_ID:
            if (isCert) return { type: attr.type, value: testKeyId };
            return {
              type: attr.type,
              value: isRsaKey ? testRsaKeyId : testKeyId,
            };
          case CONSTS.CKA_KEY_TYPE: {
            const buf = Buffer.alloc(4);
            buf.writeUInt32LE(isRsaKey ? CONSTS.CKK_RSA : CONSTS.CKK_EC);
            return { type: attr.type, value: buf };
          }
          case CONSTS.CKA_EC_POINT:
            return { type: attr.type, value: Buffer.from(testEcPoint) };
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

    /** Track whether last find was for RSA public key lookup. */
    _lastFindForRsa = false;
  }

  return {
    PKCS11: MockPKCS11,
    ...CONSTS,
  };
})();

// Import after mocks
import {
  initializePkcs11,
  finalizePkcs11,
  listSlots,
  openSession,
  closeSession,
  listKeys,
  listCertificates,
  findPrivateKey,
} from "../pkcs11-session.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("PKCS#11 Session Manager", () => {
  beforeEach(() => {
    resetMocks();
  });

  describe("initializePkcs11 / finalizePkcs11", () => {
    it("should initialize and finalize cleanly", () => {
      const p11 = initializePkcs11("/usr/lib/opensc-pkcs11.so");
      expect(p11).toBeDefined();
      finalizePkcs11(p11);
    });

    it("should throw CryptoError on invalid library path", () => {
      mockState.loadShouldFail = true;
      expect(() => initializePkcs11("/nonexistent/lib.so")).toThrow(CryptoError);
    });

    it("finalize should not throw even on repeated calls", () => {
      const p11 = initializePkcs11("/usr/lib/opensc-pkcs11.so");
      finalizePkcs11(p11);
      expect(() => finalizePkcs11(p11)).not.toThrow();
    });
  });

  describe("listSlots", () => {
    it("should list all slots including empty ones", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const slots = listSlots(p11);

      expect(slots.length).toBe(2);

      expect(slots[0].index).toBe(0);
      expect(slots[0].tokenPresent).toBe(true);
      expect(slots[0].tokenLabel).toBe("Test SmartCard");
      expect(slots[0].tokenManufacturer).toBe("OpenSC Project");
      expect(slots[0].description).toContain("Virtual Token");

      expect(slots[1].index).toBe(1);
      expect(slots[1].tokenPresent).toBe(false);
      expect(slots[1].tokenLabel).toBeUndefined();

      finalizePkcs11(p11);
    });
  });

  describe("openSession", () => {
    it("should open a session with valid PIN", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");

      expect(session.handle).toBeDefined();
      expect(session.loggedIn).toBe(true);
      expect(session.slotIndex).toBe(0);

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should throw on wrong PIN", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      expect(() => openSession(p11, 0, "wrong")).toThrow(CryptoError);
      expect(() => openSession(p11, 0, "wrong")).toThrow(/login failed/i);
      finalizePkcs11(p11);
    });

    it("should throw on locked PIN", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      expect(() => openSession(p11, 0, "locked")).toThrow(CryptoError);
      finalizePkcs11(p11);
    });

    it("should throw on invalid slot index", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      expect(() => openSession(p11, 5, "1234")).toThrow(CryptoError);
      expect(() => openSession(p11, 5, "1234")).toThrow(/out of range/);
      finalizePkcs11(p11);
    });
  });

  describe("closeSession", () => {
    it("should close cleanly after login", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");

      closeSession(session);
      expect(session.loggedIn).toBe(false);

      finalizePkcs11(p11);
    });

    it("should be safe to call multiple times", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");

      closeSession(session);
      expect(() => closeSession(session)).not.toThrow();

      finalizePkcs11(p11);
    });
  });

  describe("listKeys", () => {
    it("should return EC key metadata", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");
      const keys = listKeys(session);

      expect(keys.length).toBeGreaterThan(0);
      const key = keys[0];
      expect(key.label).toBe("Signing Key 1");
      expect(key.id).toBe(testKeyId.toString("hex"));
      expect(key.keyType).toBe("EC");
      expect(key.hasPublicKey).toBe(true);

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should return EC point for keys with public key", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");
      const keys = listKeys(session);

      expect(keys[0].ecPoint).toBeDefined();
      expect(keys[0].ecPoint!.length).toBe(65);
      expect(keys[0].ecPoint![0]).toBe(0x04);

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should return both EC and RSA keys when RSA keys are present", () => {
      mockState.includeRsaKeys = true;

      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");
      const keys = listKeys(session);

      expect(keys.length).toBe(2);

      // First key: EC
      const ecKey = keys.find((k) => k.keyType === "EC");
      expect(ecKey).toBeDefined();
      expect(ecKey!.ecPoint).toBeDefined();
      expect(ecKey!.rsaModulus).toBeUndefined();

      // Second key: RSA
      const rsaKey = keys.find((k) => k.keyType === "RSA");
      expect(rsaKey).toBeDefined();
      expect(rsaKey!.rsaModulus).toBeDefined();
      expect(rsaKey!.rsaPublicExponent).toBeDefined();
      expect(rsaKey!.ecPoint).toBeUndefined();

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should return RSA modulus and exponent", () => {
      mockState.includeRsaKeys = true;

      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");
      const keys = listKeys(session);

      const rsaKey = keys.find((k) => k.keyType === "RSA")!;
      expect(rsaKey.rsaModulus!.length).toBe(256); // 2048-bit modulus
      expect(rsaKey.rsaPublicExponent).toEqual(new Uint8Array([0x01, 0x00, 0x01]));

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should never return private key material", () => {
      mockState.includeRsaKeys = true;

      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");
      const keys = listKeys(session);

      for (const key of keys) {
        expect(typeof key.label).toBe("string");
        expect(typeof key.id).toBe("string");
        expect(typeof key.keyType).toBe("string");
        expect(typeof key.hasPublicKey).toBe("boolean");

        const keyObj = key as unknown as Record<string, unknown>;
        expect(keyObj["privateKey"]).toBeUndefined();
        expect(keyObj["key"]).toBeUndefined();
        expect(keyObj["secret"]).toBeUndefined();
        expect(keyObj["d"]).toBeUndefined();
      }

      closeSession(session);
      finalizePkcs11(p11);
    });
  });

  describe("listCertificates", () => {
    it("should return empty array when no certificates", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");
      const certs = listCertificates(session);

      expect(certs).toEqual([]);

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should return certificate info when certificates are present", () => {
      mockState.includeCerts = true;

      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");
      const certs = listCertificates(session);

      expect(certs.length).toBe(1);
      expect(certs[0].label).toBe("Token Certificate");
      expect(certs[0].id).toBe(testKeyId.toString("hex"));
      expect(certs[0].derValue).toBeInstanceOf(Uint8Array);
      expect(certs[0].derValue.length).toBeGreaterThan(0);

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should match certificates to keys by CKA_ID", () => {
      mockState.includeCerts = true;

      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");

      const keys = listKeys(session);
      const certs = listCertificates(session);

      // The certificate's ID should match the EC key's ID
      const ecKey = keys[0];
      const matchingCerts = certs.filter((c) => c.id === ecKey.id);
      expect(matchingCerts.length).toBe(1);

      closeSession(session);
      finalizePkcs11(p11);
    });
  });

  describe("findPrivateKey", () => {
    it("should find a private key by hex ID", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");

      const handle = findPrivateKey(session, testKeyId.toString("hex"));
      expect(handle).toBeDefined();
      expect(Buffer.isBuffer(handle)).toBe(true);

      closeSession(session);
      finalizePkcs11(p11);
    });
  });

  describe("Session lifecycle integration", () => {
    it("should handle full flow: init -> open -> list -> close -> finalize", () => {
      const p11 = initializePkcs11("/mock/lib.so");
      const slots = listSlots(p11);
      expect(slots.length).toBeGreaterThan(0);

      const session = openSession(p11, 0, "1234");
      expect(session.loggedIn).toBe(true);

      const keys = listKeys(session);
      expect(keys.length).toBeGreaterThan(0);

      closeSession(session);
      finalizePkcs11(p11);
    });

    it("should clean up on PIN failure", () => {
      const p11 = initializePkcs11("/mock/lib.so");

      try {
        openSession(p11, 0, "wrong");
      } catch {
        // Expected
      }

      finalizePkcs11(p11);
    });

    it("should handle full flow with RSA keys and certificates", () => {
      mockState.includeRsaKeys = true;
      mockState.includeCerts = true;

      const p11 = initializePkcs11("/mock/lib.so");
      const session = openSession(p11, 0, "1234");

      const keys = listKeys(session);
      expect(keys.length).toBe(2);
      expect(keys.some((k) => k.keyType === "EC")).toBe(true);
      expect(keys.some((k) => k.keyType === "RSA")).toBe(true);

      const certs = listCertificates(session);
      expect(certs.length).toBe(1);

      closeSession(session);
      finalizePkcs11(p11);
    });
  });
});
