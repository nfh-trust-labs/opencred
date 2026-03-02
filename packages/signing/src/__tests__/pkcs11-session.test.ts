/**
 * Tests for the PKCS#11 session manager.
 *
 * Uses a mock of pkcs11js to test session lifecycle, slot enumeration,
 * key discovery, and error handling without requiring real hardware.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { CryptoError } from "@opencred/shared";

// ---------------------------------------------------------------------------
// vi.hoisted() — variables available inside the mock factory
// ---------------------------------------------------------------------------

const { mockState, resetMocks, testKeyId, testEcPoint, CONSTS } = vi.hoisted(() => {
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
    sessionCount: 0,
    loadShouldFail: false,
    /** Stack of find operations to support nesting. */
    findStack: [] as FindState[],
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

  const _testKeyId = Buffer.from("aabb", "hex");

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
  }

  return {
    mockState: _mockState,
    resetMocks: _resetMocks,
    testKeyId: _testKeyId,
    testEcPoint: _testEcPoint,
    CONSTS: _CONSTS,
  };
});

vi.mock("pkcs11js", () => {
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
      if (!current) return null;

      if (current.findCallCount === 0) {
        current.findCallCount++;
        return current.findType === "private" ? Buffer.from("privkey0") : Buffer.from("pubkey0");
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
            return { type: attr.type, value: Buffer.from("Signing Key 1") };
          case CONSTS.CKA_ID:
            return { type: attr.type, value: testKeyId };
          case CONSTS.CKA_KEY_TYPE: {
            const buf = Buffer.alloc(4);
            buf.writeUInt32LE(CONSTS.CKK_EC);
            return { type: attr.type, value: buf };
          }
          case CONSTS.CKA_EC_POINT:
            return { type: attr.type, value: Buffer.from(testEcPoint) };
          default:
            return { type: attr.type, value: null };
        }
      });
    }
  }

  return {
    PKCS11: MockPKCS11,
    ...CONSTS,
  };
});

// Import after mocks
import {
  initializePkcs11,
  finalizePkcs11,
  listSlots,
  openSession,
  closeSession,
  listKeys,
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
    it("should return key metadata", () => {
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

    it("should never return private key material", () => {
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
  });
});
