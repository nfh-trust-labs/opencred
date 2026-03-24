import { describe, it, expect, beforeEach } from "vitest";
import {
  storeAttestation,
  getAttestation,
  listAttestations,
  removeAttestation,
  clearAttestationStore,
  hasAttestation,
} from "../main/attestation-store.js";

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
      },
      organizationName: "Example University",
    },
  };
}

describe("attestation-store", () => {
  beforeEach(() => {
    clearAttestationStore();
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
    it("removes an existing attestation", () => {
      storeAttestation("key-rm", validAttestationCredential());
      expect(hasAttestation("key-rm")).toBe(true);

      const removed = removeAttestation("key-rm");
      expect(removed).toBe(true);
      expect(hasAttestation("key-rm")).toBe(false);
    });

    it("returns false for non-existent key", () => {
      expect(removeAttestation("no-such-key")).toBe(false);
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
    it("removes all attestations", () => {
      storeAttestation("key-x", validAttestationCredential());
      storeAttestation("key-y", validAttestationCredential());
      expect(listAttestations()).toHaveLength(2);

      clearAttestationStore();
      expect(listAttestations()).toHaveLength(0);
    });
  });
});
