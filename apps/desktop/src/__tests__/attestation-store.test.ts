import { describe, it, expect, beforeEach, vi } from "vitest";

// Mock electron-store used by ./store.js — provides a fake get/set interface.
const mockStoreData: Record<string, unknown> = {};
const mockElectronStore = {
  get: vi.fn((key: string) => mockStoreData[key]),
  set: vi.fn((key: string, value: unknown) => {
    mockStoreData[key] = value;
  }),
};

vi.mock("../main/store.js", () => ({
  getStore: vi.fn(() => mockElectronStore),
}));

// Mock @opencred/key-attestation — the real implementation checks for
// type: [..., "KeyAttestationCredential"] which we replicate here.
vi.mock("@opencred/key-attestation", () => ({
  isKeyAttestationCredential: vi.fn((cred: unknown) => {
    if (!cred || typeof cred !== "object") return false;
    const vc = cred as Record<string, unknown>;
    const types = vc["type"];
    return Array.isArray(types) && types.includes("KeyAttestationCredential");
  }),
}));

const {
  storeAttestation,
  getAttestation,
  listAttestations,
  removeAttestation,
  clearAttestationStore,
  hasAttestation,
  loadPersistedAttestations,
} = await import("../main/attestation-store.js");

function validAttestationCredential(): Record<string, unknown> {
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/data-integrity/v1",
      "https://opencred.dev/ns/key-attestation/v1",
    ],
    id: "urn:uuid:test-attestation",
    type: ["VerifiableCredential", "KeyAttestationCredential"],
    issuer: "did:key:z6MkOpenCred",
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:key:z6MkIssuer",
      keyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      keyFingerprint: "sha256:a1b2c3d4",
      keyAlgorithm: "P-256",
      verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
      identityVerification: {
        method: "dns-txt",
        verifiedDomain: "university.example",
        verifiedAt: "2026-03-10T12:00:00Z",
        challengeId: "urn:uuid:test-challenge",
      },
      organizationName: "Example University",
    },
  };
}

describe("attestation-store", () => {
  beforeEach(() => {
    clearAttestationStore();
    // Reset mock store data
    for (const key of Object.keys(mockStoreData)) {
      delete mockStoreData[key];
    }
    vi.clearAllMocks();
  });

  describe("storeAttestation", () => {
    it("stores and retrieves an attestation", () => {
      const credential = validAttestationCredential();
      const stored = storeAttestation("key-1", credential);

      expect(stored.keyId).toBe("key-1");
      expect(stored.organizationName).toBe("Example University");
      expect(stored.verifiedDomain).toBe("university.example");
      expect(stored.validFrom).toBe("2026-01-01T00:00:00Z");
      expect(stored.validUntil).toBe("2027-01-01T00:00:00Z");
      expect(stored.storedAt).toBeDefined();

      const retrieved = getAttestation("key-1");
      expect(retrieved).toBeDefined();
      expect(retrieved!.credential).toEqual(credential);
    });

    it("persists to electron-store on store", () => {
      storeAttestation("key-1", validAttestationCredential());
      expect(mockElectronStore.set).toHaveBeenCalledWith(
        "attestations",
        expect.arrayContaining([
          expect.objectContaining({ keyId: "key-1" }),
        ]),
      );
    });

    it("rejects non-KeyAttestationCredential", () => {
      const invalidCred = { type: ["VerifiableCredential"], issuer: "did:example:123" };
      expect(() => storeAttestation("key-bad", invalidCred)).toThrow(
        "not a KeyAttestationCredential",
      );
    });

    it("extracts nested metadata correctly", () => {
      const credential = validAttestationCredential();
      const stored = storeAttestation("key-2", credential);

      expect(stored.organizationName).toBe("Example University");
      expect(stored.verifiedDomain).toBe("university.example");
    });
  });

  describe("getAttestation", () => {
    it("returns undefined for non-existent key", () => {
      expect(getAttestation("nonexistent")).toBeUndefined();
    });
  });

  describe("listAttestations", () => {
    it("lists all stored attestations", () => {
      storeAttestation("key-a", validAttestationCredential());

      const cred2 = validAttestationCredential();
      (cred2.credentialSubject as Record<string, unknown>).organizationName = "Another Org";
      storeAttestation("key-b", cred2);

      const all = listAttestations();
      expect(all).toHaveLength(2);
      expect(all.map((a) => a.keyId).sort()).toEqual(["key-a", "key-b"]);
    });
  });

  describe("removeAttestation", () => {
    it("removes an existing attestation and persists", () => {
      storeAttestation("key-rm", validAttestationCredential());
      expect(hasAttestation("key-rm")).toBe(true);

      vi.clearAllMocks();
      const removed = removeAttestation("key-rm");
      expect(removed).toBe(true);
      expect(hasAttestation("key-rm")).toBe(false);
      // Should persist the removal
      expect(mockElectronStore.set).toHaveBeenCalledWith("attestations", []);
    });

    it("returns false for non-existent key and does not persist", () => {
      vi.clearAllMocks();
      expect(removeAttestation("no-such-key")).toBe(false);
      expect(mockElectronStore.set).not.toHaveBeenCalled();
    });
  });

  describe("hasAttestation", () => {
    it("returns true for existing attestation", () => {
      storeAttestation("key-has", validAttestationCredential());
      expect(hasAttestation("key-has")).toBe(true);
    });

    it("returns false for missing attestation", () => {
      expect(hasAttestation("key-missing")).toBe(false);
    });
  });

  describe("clearAttestationStore", () => {
    it("removes all attestations and persists empty list", () => {
      storeAttestation("key-x", validAttestationCredential());
      storeAttestation("key-y", validAttestationCredential());
      expect(listAttestations()).toHaveLength(2);

      vi.clearAllMocks();
      clearAttestationStore();
      expect(listAttestations()).toHaveLength(0);
      expect(mockElectronStore.set).toHaveBeenCalledWith("attestations", []);
    });
  });

  describe("loadPersistedAttestations", () => {
    it("loads valid attestations from electron-store into memory", () => {
      const cred = validAttestationCredential();
      const entry = {
        keyId: "key-persisted",
        credential: cred,
        storedAt: "2026-03-01T00:00:00Z",
        organizationName: "Example University",
        verifiedDomain: "university.example",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2027-01-01T00:00:00Z",
      };
      mockStoreData["attestations"] = [entry];

      loadPersistedAttestations();

      expect(hasAttestation("key-persisted")).toBe(true);
      const loaded = getAttestation("key-persisted");
      expect(loaded?.organizationName).toBe("Example University");
    });

    it("prunes expired attestations", () => {
      const cred = validAttestationCredential();
      // Set validUntil in the past
      cred["validUntil"] = "2020-01-01T00:00:00Z";
      const entry = {
        keyId: "key-expired",
        credential: cred,
        storedAt: "2019-01-01T00:00:00Z",
        organizationName: "Expired Org",
        verifiedDomain: "expired.example",
        validFrom: "2019-01-01T00:00:00Z",
        validUntil: "2020-01-01T00:00:00Z",
      };
      mockStoreData["attestations"] = [entry];

      loadPersistedAttestations();

      expect(hasAttestation("key-expired")).toBe(false);
      // Should persist the pruned (empty) list
      expect(mockElectronStore.set).toHaveBeenCalledWith("attestations", []);
    });

    it("prunes structurally invalid attestations", () => {
      const entry = {
        keyId: "key-invalid",
        credential: { type: ["VerifiableCredential"] }, // missing KeyAttestationCredential type
        storedAt: "2026-03-01T00:00:00Z",
        organizationName: "Invalid",
        verifiedDomain: "invalid.example",
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2027-01-01T00:00:00Z",
      };
      mockStoreData["attestations"] = [entry];

      loadPersistedAttestations();

      expect(hasAttestation("key-invalid")).toBe(false);
      expect(mockElectronStore.set).toHaveBeenCalledWith("attestations", []);
    });

    it("keeps valid and prunes expired in the same batch", () => {
      const validCred = validAttestationCredential();
      const expiredCred = validAttestationCredential();
      expiredCred["validUntil"] = "2020-01-01T00:00:00Z";

      mockStoreData["attestations"] = [
        {
          keyId: "key-valid",
          credential: validCred,
          storedAt: "2026-03-01T00:00:00Z",
          organizationName: "Valid Org",
          verifiedDomain: "valid.example",
          validFrom: "2026-01-01T00:00:00Z",
          validUntil: "2027-01-01T00:00:00Z",
        },
        {
          keyId: "key-expired",
          credential: expiredCred,
          storedAt: "2019-01-01T00:00:00Z",
          organizationName: "Expired Org",
          verifiedDomain: "expired.example",
          validFrom: "2019-01-01T00:00:00Z",
          validUntil: "2020-01-01T00:00:00Z",
        },
      ];

      loadPersistedAttestations();

      expect(hasAttestation("key-valid")).toBe(true);
      expect(hasAttestation("key-expired")).toBe(false);
      expect(listAttestations()).toHaveLength(1);
    });

    it("handles empty persisted list gracefully", () => {
      mockStoreData["attestations"] = [];
      loadPersistedAttestations();
      expect(listAttestations()).toHaveLength(0);
    });

    it("handles missing attestations key gracefully", () => {
      // attestations key not set at all
      loadPersistedAttestations();
      expect(listAttestations()).toHaveLength(0);
    });
  });
});
