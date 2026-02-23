import { describe, it, expect, vi } from "vitest";
import type { DeDiClient } from "@opencred/dedi-client";
import type { DelegationCertificate } from "@opencred/delegation";
import { checkDelegationChain } from "../delegation-check.js";

function createValidDelegationCertificate(
  overrides: Partial<DelegationCertificate> = {},
): DelegationCertificate {
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://opencred.id/ns/delegation/v1",
    ],
    id: "urn:uuid:delegation-001",
    type: ["DelegationCertificate"],
    delegator: { id: "did:web:issuer.example" },
    delegatee: { id: "did:key:z6MkOpenCredKey1" },
    scope: {
      credentialTypes: ["UniversityDegreeCredential"],
      namespaces: ["education"],
    },
    validFrom: "2025-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    authorisationPath: "ephemeral-keypair",
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      verificationMethod: "did:web:issuer.example#key-1",
      proofPurpose: "assertionMethod",
      created: "2025-01-01T00:00:00Z",
      proofValue: "mock-delegation-proof-value",
    },
    ...overrides,
  };
}

function createDelegatedCredential(
  delegation: DelegationCertificate,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:credential-001",
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    issuer: "did:web:issuer.example",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder123",
      degree: { type: "BachelorDegree", name: "Computer Science" },
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      verificationMethod: "did:key:z6MkOpenCredKey1#z6MkOpenCredKey1",
      proofPurpose: "assertionMethod",
      created: "2026-06-15T12:00:00Z",
      proofValue: "mock-credential-proof-value",
      delegationCertificate: delegation,
    },
    ...overrides,
  };
}

function createReferencedDelegationCredential(
  delegationUrl: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:credential-002",
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    issuer: "did:web:issuer.example",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder456",
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      verificationMethod: "did:key:z6MkOpenCredKey1#z6MkOpenCredKey1",
      proofPurpose: "assertionMethod",
      created: "2026-06-15T12:00:00Z",
      proofValue: "mock-credential-proof-value",
      delegationCertificateUrl: delegationUrl,
    },
    ...overrides,
  };
}

describe("checkDelegationChain", () => {
  describe("no delegation reference", () => {
    it("should skip when credential has no delegation reference", async () => {
      const credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
        proof: {
          type: "DataIntegrityProof",
          created: "2026-01-01T00:00:00Z",
          proofValue: "some-proof",
        },
      };

      const result = await checkDelegationChain(credential);

      expect(result.name).toBe("delegation");
      expect(result.passed).toBe(true);
      expect(result.detail).toContain("not a delegated credential");
    });

    it("should skip when credential has no proof at all", async () => {
      const credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
      };

      const result = await checkDelegationChain(credential);

      expect(result.name).toBe("delegation");
      expect(result.passed).toBe(true);
    });
  });

  describe("valid delegation chain", () => {
    it("should pass for a valid inline delegation", async () => {
      const delegation = createValidDelegationCertificate();
      const credential = createDelegatedCredential(delegation);

      const result = await checkDelegationChain(credential);

      expect(result.name).toBe("delegation");
      expect(result.passed).toBe(true);
    });

    it("should pass when delegation was valid at proof.created (point-in-time check)", async () => {
      // Delegation valid from 2025 to 2027
      // Credential signed at 2026-06-15 (within delegation validity)
      // Verification happens "now" (after 2027) — should still PASS
      const delegation = createValidDelegationCertificate({
        validFrom: "2025-01-01T00:00:00Z",
        validUntil: "2027-01-01T00:00:00Z",
      });
      const credential = createDelegatedCredential(delegation);

      // proof.created is 2026-06-15 which is within [2025, 2027]
      const result = await checkDelegationChain(credential);

      expect(result.passed).toBe(true);
    });
  });

  describe("expired delegation", () => {
    it("should fail when delegation was already expired at proof.created", async () => {
      // Delegation expired 2024-12-31
      // Credential signed at 2026-06-15 — delegation was already expired
      const delegation = createValidDelegationCertificate({
        validFrom: "2023-01-01T00:00:00Z",
        validUntil: "2024-12-31T00:00:00Z",
      });
      const credential = createDelegatedCredential(delegation);

      const result = await checkDelegationChain(credential);

      expect(result.name).toBe("delegation");
      expect(result.passed).toBe(false);
      expect(result.detail).toContain("expired");
    });

    it("should fail when delegation was not yet valid at proof.created", async () => {
      // Delegation valid from 2028-01-01
      // Credential signed at 2026-06-15 — delegation not yet valid
      const delegation = createValidDelegationCertificate({
        validFrom: "2028-01-01T00:00:00Z",
        validUntil: "2030-01-01T00:00:00Z",
      });
      const credential = createDelegatedCredential(delegation);

      const result = await checkDelegationChain(credential);

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("not yet valid");
    });
  });

  describe("scope mismatch", () => {
    it("should fail when delegation does not cover the credential type", async () => {
      const delegation = createValidDelegationCertificate({
        scope: {
          credentialTypes: ["DriverLicenseCredential"],
          namespaces: ["transportation"],
        },
      });

      // Credential type is UniversityDegreeCredential but delegation only covers DriverLicense
      const credential = createDelegatedCredential(delegation);

      const result = await checkDelegationChain(credential);

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("not within delegation scope");
    });
  });

  describe("missing delegation (reference but can't resolve)", () => {
    it("should fail when delegation is by reference but no DeDi client", async () => {
      const credential = createReferencedDelegationCredential(
        "https://dedi.example/delegations/del-001",
      );

      const result = await checkDelegationChain(credential);

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("no DeDi client configured");
    });

    it("should fail when DeDi resolution fails", async () => {
      const credential = createReferencedDelegationCredential(
        "https://dedi.example/delegations/del-001",
      );

      const mockDediClient = {
        resolveDelegation: vi.fn().mockRejectedValue(new Error("not found")),
      } as unknown as DeDiClient;

      const result = await checkDelegationChain(credential, {
        dediClient: mockDediClient,
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Failed to resolve delegation");
    });
  });

  describe("resolved delegation via DeDi", () => {
    it("should pass when delegation resolved from DeDi is valid", async () => {
      const delegation = createValidDelegationCertificate();
      const credential = createReferencedDelegationCredential(
        "https://dedi.example/delegations/del-001",
      );

      const mockDediClient = {
        resolveDelegation: vi.fn().mockResolvedValue({
          id: "del-001",
          issuerDid: "did:web:issuer.example",
          delegateDid: "did:key:z6MkOpenCredKey1",
          scope: ["UniversityDegreeCredential"],
          validFrom: "2025-01-01T00:00:00Z",
          validUntil: "2027-01-01T00:00:00Z",
          certificate: delegation,
        }),
      } as unknown as DeDiClient;

      const result = await checkDelegationChain(credential, {
        dediClient: mockDediClient,
      });

      expect(result.passed).toBe(true);
    });
  });

  describe("missing proof.created", () => {
    it("should fail when proof has no created timestamp", async () => {
      const delegation = createValidDelegationCertificate();
      const credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "UniversityDegreeCredential"],
        proof: {
          type: "DataIntegrityProof",
          proofValue: "mock-proof",
          delegationCertificate: delegation,
          // No "created" field
        },
      };

      const result = await checkDelegationChain(credential);

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("no 'created' timestamp");
    });
  });

  describe("structural validation", () => {
    it("should fail when delegation certificate is missing required fields", async () => {
      // Missing delegator.id
      const brokenDelegation = createValidDelegationCertificate();
      (brokenDelegation as Record<string, unknown>)["delegator"] = {};

      const credential = createDelegatedCredential(brokenDelegation);

      const result = await checkDelegationChain(credential);

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Delegation chain invalid");
    });
  });

  describe("credential with only VerifiableCredential type", () => {
    it("should pass when delegation has empty credentialTypes (no restriction)", async () => {
      const delegation = createValidDelegationCertificate({
        scope: {
          credentialTypes: [],
          namespaces: [],
        },
      });

      const credential = createDelegatedCredential(delegation, {
        type: ["VerifiableCredential"],
      });

      const result = await checkDelegationChain(credential);

      expect(result.passed).toBe(true);
    });
  });
});
