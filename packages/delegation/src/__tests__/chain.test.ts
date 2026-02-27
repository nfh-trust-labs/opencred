import { describe, it, expect, vi } from "vitest";
import { DelegationError } from "@opencred/shared";
import type { DeDiClient } from "@opencred/dedi-client";
import type { VerifiableCredential, Proof } from "@opencred/vc-core";
import { validateDelegationChain, validateDelegateeMatchesSigningKey } from "../chain.js";
import { createDelegationCertificate } from "../certificate.js";
import type {
  CreateDelegationParams,
  DelegationCertificate,
  DelegatedCredentialProof,
} from "../types.js";
import type { DelegationResolver } from "../chain.js";

function createValidParams(overrides?: Partial<CreateDelegationParams>): CreateDelegationParams {
  return {
    delegator: {
      id: "https://example.com",
      name: "Example Corp Ltd",
    },
    delegatee: {
      id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    },
    scope: {
      credentialTypes: ["UniversityDegreeCredential"],
      namespaces: ["education"],
    },
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    authorisationPath: "ephemeral-keypair",
    ...overrides,
  };
}

function createSignedDelegation(
  overrides?: Partial<CreateDelegationParams>,
): DelegationCertificate {
  const unsigned = createDelegationCertificate(createValidParams(overrides));
  return {
    ...unsigned,
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2026-01-01T00:00:00Z",
      verificationMethod: "did:key:z6Mk-delegator#key-1",
      proofPurpose: "assertionMethod",
      proofValue: "zFakeProofValue",
    },
  };
}

function createTestVC(proofOverrides?: Partial<DelegatedCredentialProof>): VerifiableCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:test-vc",
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    issuer: { id: "https://example.com", name: "Example Corp" },
    validFrom: "2026-06-01T00:00:00Z",
    credentialSubject: { id: "did:example:holder", name: "Jane" },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2026-06-15T00:00:00Z",
      verificationMethod:
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      proofPurpose: "assertionMethod",
      proofValue: "z123abc",
      ...proofOverrides,
    },
  };
}

function noopResolver(): DelegationResolver {
  return vi.fn().mockRejectedValue(new DelegationError("Should not be called"));
}

function createMockDeDiClient(overrides?: Record<string, unknown>): DeDiClient {
  return {
    publishRevocationHash: vi.fn(),
    queryRevocationHash: vi.fn().mockResolvedValue({ hash: "abc", revoked: false }),
    resolveDID: vi.fn(),
    registerDelegation: vi.fn(),
    resolveDelegation: vi.fn(),
    ...overrides,
  } as unknown as DeDiClient;
}

describe("validateDelegationChain -- inline delegation", () => {
  it("should validate a credential with an inline delegation certificate", async () => {
    const delegation = createSignedDelegation();
    const vc = createTestVC({ delegationCertificate: delegation });
    const result = await validateDelegationChain(vc, noopResolver(), {
      now: new Date("2026-06-15T00:00:00Z"),
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.delegation).toBeDefined();
  });

  it("should fail when delegation is expired", async () => {
    const delegation = createSignedDelegation({
      validFrom: "2025-01-01T00:00:00Z",
      validUntil: "2025-12-31T00:00:00Z",
    });
    const vc = createTestVC({ delegationCertificate: delegation, created: "2026-06-15T00:00:00Z" });
    const result = await validateDelegationChain(vc, noopResolver());
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("expired"))).toBe(true);
  });

  it("should fail when delegation is not yet valid", async () => {
    const delegation = createSignedDelegation({
      validFrom: "2027-01-01T00:00:00Z",
      validUntil: "2028-01-01T00:00:00Z",
    });
    const vc = createTestVC({ delegationCertificate: delegation, created: "2026-06-15T00:00:00Z" });
    const result = await validateDelegationChain(vc, noopResolver());
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("not yet valid"))).toBe(true);
  });

  it("should fail when delegatee does not match signing key", async () => {
    const delegation = createSignedDelegation({
      delegatee: { id: "did:key:z6MkDIFFERENT#z6MkDIFFERENT" },
    });
    const vc = createTestVC({ delegationCertificate: delegation });
    const result = await validateDelegationChain(vc, noopResolver(), {
      now: new Date("2026-06-15T00:00:00Z"),
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("does not match"))).toBe(true);
  });
});

describe("validateDelegationChain -- referenced delegation", () => {
  it("should resolve and validate a delegation referenced by URL", async () => {
    const delegation = createSignedDelegation();
    const vc = createTestVC({
      delegationCertificateUrl:
        "https://dedi.example/delegations/" + encodeURIComponent(delegation.id),
    });
    const resolver = vi.fn().mockResolvedValue(delegation);
    const result = await validateDelegationChain(vc, resolver, {
      now: new Date("2026-06-15T00:00:00Z"),
    });
    expect(result.valid).toBe(true);
    expect(resolver).toHaveBeenCalledOnce();
  });

  it("should fail when delegation cannot be resolved", async () => {
    const vc = createTestVC({
      delegationCertificateUrl: "https://dedi.example/delegations/nonexistent",
    });
    const resolver = vi.fn().mockRejectedValue(new DelegationError("Delegation not found"));
    const result = await validateDelegationChain(vc, resolver);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("Failed to resolve delegation"))).toBe(
      true,
    );
  });
});

describe("validateDelegationChain -- edge cases", () => {
  it("should fail when credential has no proof", async () => {
    const vc = createTestVC();
    // @ts-expect-error -- deliberately testing missing proof
    delete vc.proof;
    const result = await validateDelegationChain(vc, noopResolver());
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Credential has no proof");
  });

  it("should fail when proof has no delegation reference", async () => {
    const vc = createTestVC();
    const result = await validateDelegationChain(vc, noopResolver());
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("no delegation certificate"))).toBe(true);
  });

  it("should accept delegation when scope is unrestricted", async () => {
    const delegation = createSignedDelegation({ scope: { credentialTypes: [], namespaces: [] } });
    const vc = createTestVC({ delegationCertificate: delegation });
    const result = await validateDelegationChain(vc, noopResolver(), {
      now: new Date("2026-06-15T00:00:00Z"),
      credentialType: "AnyCredentialType",
      namespace: "any-namespace",
    });
    expect(result.valid).toBe(true);
  });

  it("should use proof.created as validation time when no time option provided", async () => {
    const delegation = createSignedDelegation({
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2026-12-31T00:00:00Z",
    });
    const vc = createTestVC({ delegationCertificate: delegation, created: "2026-06-15T00:00:00Z" });
    const result = await validateDelegationChain(vc, noopResolver());
    expect(result.valid).toBe(true);
  });
});

describe("validateDelegationChain -- revocation checking", () => {
  it("should reject a revoked delegation when dediClient is provided", async () => {
    const delegation = createSignedDelegation();
    const vc = createTestVC({ delegationCertificate: delegation });
    const client = createMockDeDiClient({
      queryRevocationHash: vi
        .fn()
        .mockResolvedValue({ hash: "abc123", revoked: true, revokedAt: "2026-06-15T00:00:00Z" }),
    });
    const result = await validateDelegationChain(vc, noopResolver(), {
      now: new Date("2026-06-15T00:00:00Z"),
      dediClient: client,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e: string) => e.includes("has been revoked"))).toBe(true);
  });

  it("should accept a non-revoked delegation when dediClient is provided", async () => {
    const delegation = createSignedDelegation();
    const vc = createTestVC({ delegationCertificate: delegation });
    const client = createMockDeDiClient({
      queryRevocationHash: vi.fn().mockResolvedValue({ hash: "abc123", revoked: false }),
    });
    const result = await validateDelegationChain(vc, noopResolver(), {
      now: new Date("2026-06-15T00:00:00Z"),
      dediClient: client,
    });
    expect(result.valid).toBe(true);
  });

  it("should skip revocation check when dediClient is not provided", async () => {
    const delegation = createSignedDelegation();
    const vc = createTestVC({ delegationCertificate: delegation });
    const result = await validateDelegationChain(vc, noopResolver(), {
      now: new Date("2026-06-15T00:00:00Z"),
    });
    expect(result.valid).toBe(true);
  });

  it("should report error when revocation check fails", async () => {
    const delegation = createSignedDelegation();
    const vc = createTestVC({ delegationCertificate: delegation });
    const client = createMockDeDiClient({
      queryRevocationHash: vi.fn().mockRejectedValue(new Error("network failure")),
    });
    const result = await validateDelegationChain(vc, noopResolver(), {
      now: new Date("2026-06-15T00:00:00Z"),
      dediClient: client,
    });
    expect(result.valid).toBe(false);
    expect(
      result.errors.some((e: string) => e.includes("Failed to check delegation revocation status")),
    ).toBe(true);
  });
});

describe("validateDelegateeMatchesSigningKey -- strict matching", () => {
  function makeDelegation(delegateeId: string): DelegationCertificate {
    return createSignedDelegation({ delegatee: { id: delegateeId } });
  }

  it("should pass when delegatee ID exactly matches verification method", () => {
    const errors: string[] = [];
    const delegation = makeDelegation("did:key:zABC#zABC");
    const proof = {
      type: "DataIntegrityProof",
      verificationMethod: "did:key:zABC#zABC",
      created: "2024-01-01T00:00:00Z",
      proofPurpose: "assertionMethod",
      proofValue: "zStubSignature",
    };
    validateDelegateeMatchesSigningKey(delegation, proof, errors);
    expect(errors).toHaveLength(0);
  });

  it("should fail when fragment differs even if base DID matches", () => {
    const errors: string[] = [];
    const delegation = makeDelegation("did:key:zABC#zABC");
    const proof = {
      type: "DataIntegrityProof",
      verificationMethod: "did:key:zABC#zDEF",
      created: "2024-01-01T00:00:00Z",
      proofPurpose: "assertionMethod",
      proofValue: "zStubSignature",
    };
    validateDelegateeMatchesSigningKey(delegation, proof, errors);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("does not match");
  });

  it("should fail when base DID differs", () => {
    const errors: string[] = [];
    const delegation = makeDelegation("did:key:zABC#zABC");
    const proof = {
      type: "DataIntegrityProof",
      verificationMethod: "did:key:zXYZ#zXYZ",
      created: "2024-01-01T00:00:00Z",
      proofPurpose: "assertionMethod",
      proofValue: "zStubSignature",
    };
    validateDelegateeMatchesSigningKey(delegation, proof, errors);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("does not match");
  });

  it("should fail when proof has no verificationMethod", () => {
    const errors: string[] = [];
    const delegation = makeDelegation("did:key:zABC#zABC");
    const proof = {
      type: "DataIntegrityProof",
      created: "2024-01-01T00:00:00Z",
      proofPurpose: "assertionMethod",
      proofValue: "zStubSignature",
    } as Proof;
    validateDelegateeMatchesSigningKey(delegation, proof, errors);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("no verificationMethod");
  });
});
