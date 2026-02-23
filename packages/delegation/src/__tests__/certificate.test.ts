import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { ValidationError, DelegationError } from "@opencred/shared";
import { signCredential } from "@opencred/crypto";
import type { SigningKey, ProofOptions } from "@opencred/crypto";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import {
  createDelegationCertificate,
  validateDelegationCertificate,
  embedDelegation,
  isDelegationAuthorised,
  computeDelegationStatus,
} from "../certificate.js";
import type {
  CreateDelegationParams,
  DelegationCertificate,
} from "../types.js";
import { OPENCRED_DELEGATION_CONTEXT } from "../types.js";

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

function createTestSigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateTestKeyPair();
  return { id, privateKey, publicKey, algorithm: "P-256" };
}

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

async function signDelegationCertificate(
  cert: ReturnType<typeof createDelegationCertificate>,
  signingKey: SigningKey,
): Promise<DelegationCertificate> {
  const proofOptions: ProofOptions = {
    verificationMethod: signingKey.id,
    proofPurpose: "assertionMethod",
    created: "2026-01-01T00:00:00Z",
  };
  const signed = await signCredential(
    cert as unknown as UnsignedCredential,
    signingKey,
    proofOptions,
  );
  return signed as unknown as DelegationCertificate;
}

describe("createDelegationCertificate", () => {
  it("should create a valid unsigned delegation certificate", () => {
    const params = createValidParams();
    const cert = createDelegationCertificate(params);

    expect(cert.type).toEqual(["DelegationCertificate"]);
    expect(cert.delegator.id).toBe("https://example.com");
    expect(cert.delegator.name).toBe("Example Corp Ltd");
    expect(cert.delegatee.id).toContain("did:key:");
    expect(cert.scope.credentialTypes).toEqual(["UniversityDegreeCredential"]);
    expect(cert.scope.namespaces).toEqual(["education"]);
    expect(cert.validFrom).toBe("2026-01-01T00:00:00Z");
    expect(cert.validUntil).toBe("2027-01-01T00:00:00Z");
    expect(cert.authorisationPath).toBe("ephemeral-keypair");
    expect(cert.id).toMatch(/^urn:uuid:/);
    expect(cert["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
    expect(cert["@context"]).toContain(OPENCRED_DELEGATION_CONTEXT);
  });

  it("should use custom id when provided", () => {
    const params = createValidParams({ id: "urn:uuid:custom-id" });
    const cert = createDelegationCertificate(params);
    expect(cert.id).toBe("urn:uuid:custom-id");
  });

  it("should include credentialStatus when provided", () => {
    const params = createValidParams({
      credentialStatus: {
        id: "https://dedi.example/delegations/123",
        type: "DeDiDelegationStatus",
        statusPurpose: "revocation",
      },
    });
    const cert = createDelegationCertificate(params);
    expect(cert.credentialStatus).toBeDefined();
    expect(cert.credentialStatus!.type).toBe("DeDiDelegationStatus");
  });

  it("should include maxIssuanceCount when provided", () => {
    const params = createValidParams({
      scope: {
        credentialTypes: [],
        namespaces: [],
        maxIssuanceCount: 100,
      },
    });
    const cert = createDelegationCertificate(params);
    expect(cert.scope.maxIssuanceCount).toBe(100);
  });

  it("should support all authorisation paths", () => {
    for (const path of ["ephemeral-keypair", "passkey", "dedi-registry"] as const) {
      const cert = createDelegationCertificate(createValidParams({ authorisationPath: path }));
      expect(cert.authorisationPath).toBe(path);
    }
  });

  it("should defensively copy arrays and objects", () => {
    const params = createValidParams();
    const cert = createDelegationCertificate(params);

    params.scope.credentialTypes.push("SneakyType");
    params.delegator.name = "Modified Name";

    expect(cert.scope.credentialTypes).toEqual(["UniversityDegreeCredential"]);
    expect(cert.delegator.name).toBe("Example Corp Ltd");
  });
});

describe("createDelegationCertificate — validation errors", () => {
  it("should throw for missing delegator.id", () => {
    const params = createValidParams({ delegator: { id: "" } });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("delegator.id is required");
  });

  it("should throw for missing delegatee.id", () => {
    const params = createValidParams({ delegatee: { id: "" } });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("delegatee.id is required");
  });

  it("should throw for missing validFrom", () => {
    const params = createValidParams({ validFrom: "" });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("validFrom is required");
  });

  it("should throw for missing validUntil", () => {
    const params = createValidParams({ validUntil: "" });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("validUntil is required");
  });

  it("should throw for invalid validFrom date", () => {
    const params = createValidParams({ validFrom: "not-a-date" });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("Invalid validFrom date");
  });

  it("should throw for invalid validUntil date", () => {
    const params = createValidParams({ validUntil: "not-a-date" });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("Invalid validUntil date");
  });

  it("should throw when validUntil is before validFrom", () => {
    const params = createValidParams({
      validFrom: "2027-01-01T00:00:00Z",
      validUntil: "2026-01-01T00:00:00Z",
    });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("validUntil must be after validFrom");
  });

  it("should throw when validUntil equals validFrom", () => {
    const params = createValidParams({
      validFrom: "2026-06-01T00:00:00Z",
      validUntil: "2026-06-01T00:00:00Z",
    });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
  });

  it("should throw for non-positive maxIssuanceCount", () => {
    const params = createValidParams({
      scope: { credentialTypes: [], namespaces: [], maxIssuanceCount: 0 },
    });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
    expect(() => createDelegationCertificate(params)).toThrow("maxIssuanceCount must be a positive integer");
  });

  it("should throw for non-integer maxIssuanceCount", () => {
    const params = createValidParams({
      scope: { credentialTypes: [], namespaces: [], maxIssuanceCount: 1.5 },
    });
    expect(() => createDelegationCertificate(params)).toThrow(ValidationError);
  });
});

describe("validateDelegationCertificate — structural validation", () => {
  it("should pass for a valid signed certificate", async () => {
    const params = createValidParams();
    const unsigned = createDelegationCertificate(params);
    const signingKey = createTestSigningKey("did:key:z6Mk-delegator#key-1");
    const signed = await signDelegationCertificate(unsigned, signingKey);

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
    });

    expect(result.valid).toBe(true);
    expect(result.status).toBe("active");
    expect(result.errors).toHaveLength(0);
  });

  it("should fail for missing delegator.id", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));
    // Deliberately corrupt the certificate
    (signed.delegator as { id: string }).id = "";

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Missing delegator.id");
  });

  it("should fail for missing delegatee.id", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));
    (signed.delegatee as { id: string }).id = "";

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Missing delegatee.id");
  });
});

describe("validateDelegationCertificate — temporal validation", () => {
  it("should reject an expired delegation", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2028-01-01T00:00:00Z"),
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe("expired");
    expect(result.errors.some((e) => e.includes("expired"))).toBe(true);
  });

  it("should reject a not-yet-valid delegation", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2025-01-01T00:00:00Z"),
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("not yet valid"))).toBe(true);
  });

  it("should accept delegation at exact validFrom boundary", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-01-01T00:00:00Z"),
    });

    expect(result.valid).toBe(true);
  });

  it("should skip temporal validation when skipTemporalValidation is true", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2030-01-01T00:00:00Z"),
      skipTemporalValidation: true,
    });

    expect(result.valid).toBe(true);
  });
});

describe("validateDelegationCertificate — scope validation", () => {
  it("should accept a credential type within scope", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
      credentialType: "UniversityDegreeCredential",
    });

    expect(result.valid).toBe(true);
  });

  it("should reject a credential type outside scope", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
      credentialType: "DriverLicenseCredential",
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("not within delegation scope"))).toBe(true);
  });

  it("should accept any credential type when scope is empty (unrestricted)", async () => {
    const cert = createDelegationCertificate(
      createValidParams({
        scope: { credentialTypes: [], namespaces: [], },
      }),
    );
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
      credentialType: "AnythingGoes",
    });

    expect(result.valid).toBe(true);
  });

  it("should reject a namespace outside scope", async () => {
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, createTestSigningKey("key-1"));

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
      namespace: "healthcare",
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Namespace 'healthcare'"))).toBe(true);
  });
});

describe("validateDelegationCertificate — proof verification", () => {
  it("should verify a valid proof with the delegator's public key", async () => {
    const signingKey = createTestSigningKey("did:key:z6Mk-delegator#key-1");
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, signingKey);

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
      delegatorPublicKey: signingKey.publicKey,
    });

    expect(result.valid).toBe(true);
  });

  it("should fail proof verification with wrong public key", async () => {
    const signingKey = createTestSigningKey("did:key:z6Mk-delegator#key-1");
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, signingKey);

    const wrongKey = generateTestKeyPair();

    const result = await validateDelegationCertificate(signed, {
      now: new Date("2026-06-15T00:00:00Z"),
      delegatorPublicKey: wrongKey.publicKey,
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Proof verification failed"))).toBe(true);
  });

  it("should report error when public key is provided but certificate has no proof", async () => {
    const cert = createDelegationCertificate(createValidParams()) as unknown as DelegationCertificate;
    const { publicKey } = generateTestKeyPair();

    const result = await validateDelegationCertificate(cert, {
      now: new Date("2026-06-15T00:00:00Z"),
      delegatorPublicKey: publicKey,
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("no proof"))).toBe(true);
  });
});

describe("embedDelegation", () => {
  function createTestVC(): VerifiableCredential {
    return {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:test-vc",
      type: ["VerifiableCredential"],
      issuer: { id: "https://example.com", name: "Example Corp" },
      validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { id: "did:example:holder", name: "Jane" },
      proof: {
        type: "DataIntegrityProof",
        cryptosuite: "ecdsa-rdfc-2019",
        created: "2026-01-01T00:00:00Z",
        verificationMethod: "did:key:z6Mk-opencred#key-1",
        proofPurpose: "assertionMethod",
        proofValue: "z123abc",
      },
    };
  }

  it("should embed delegation certificate inline by default", async () => {
    const vc = createTestVC();
    const signingKey = createTestSigningKey("key-1");
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, signingKey);

    const embedded = embedDelegation(vc, signed);

    expect(embedded.proof).toBeDefined();
    const proof = embedded.proof as { delegationCertificate?: DelegationCertificate };
    expect(proof.delegationCertificate).toBeDefined();
    expect(proof.delegationCertificate!.type).toEqual(["DelegationCertificate"]);
  });

  it("should embed delegation certificate by reference", async () => {
    const vc = createTestVC();
    const signingKey = createTestSigningKey("key-1");
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, signingKey);

    const embedded = embedDelegation(vc, signed, {
      inline: false,
      delegationUrl: "https://dedi.example/delegations/123",
    });

    const proof = embedded.proof as { delegationCertificateUrl?: string };
    expect(proof.delegationCertificateUrl).toBe("https://dedi.example/delegations/123");
  });

  it("should throw when embedding by reference without URL", async () => {
    const vc = createTestVC();
    const signingKey = createTestSigningKey("key-1");
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, signingKey);

    expect(() => embedDelegation(vc, signed, { inline: false })).toThrow(DelegationError);
    expect(() => embedDelegation(vc, signed, { inline: false })).toThrow("delegationUrl is required");
  });

  it("should throw for credential without proof", async () => {
    const vc = createTestVC();
    // @ts-expect-error — deliberately testing missing proof
    delete vc.proof;
    const signingKey = createTestSigningKey("key-1");
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, signingKey);

    expect(() => embedDelegation(vc, signed)).toThrow(DelegationError);
    expect(() => embedDelegation(vc, signed)).toThrow("credential has no proof");
  });

  it("should throw for unsigned delegation certificate", () => {
    const vc = createTestVC();
    const unsigned = createDelegationCertificate(createValidParams());

    expect(() => embedDelegation(vc, unsigned as unknown as DelegationCertificate)).toThrow(
      DelegationError,
    );
    expect(() => embedDelegation(vc, unsigned as unknown as DelegationCertificate)).toThrow(
      "unsigned delegation certificate",
    );
  });

  it("should not mutate the original credential", async () => {
    const vc = createTestVC();
    const originalProofValue = vc.proof.proofValue;
    const signingKey = createTestSigningKey("key-1");
    const cert = createDelegationCertificate(createValidParams());
    const signed = await signDelegationCertificate(cert, signingKey);

    const embedded = embedDelegation(vc, signed);

    expect(vc.proof.proofValue).toBe(originalProofValue);
    expect((vc.proof as Record<string, unknown>).delegationCertificate).toBeUndefined();
    expect(embedded).not.toBe(vc);
  });
});

describe("isDelegationAuthorised", () => {
  function createActiveCert(): DelegationCertificate {
    const cert = createDelegationCertificate(createValidParams());
    // Add a fake proof to make it a "signed" cert
    return {
      ...cert,
      proof: {
        type: "DataIntegrityProof",
        cryptosuite: "ecdsa-rdfc-2019",
        created: "2026-01-01T00:00:00Z",
        verificationMethod: "did:key:test#key-1",
        proofPurpose: "assertionMethod",
        proofValue: "zFake",
      },
    };
  }

  it("should return true for valid type and namespace within period", () => {
    const cert = createActiveCert();
    expect(isDelegationAuthorised(cert, "UniversityDegreeCredential", "education",
      new Date("2026-06-15T00:00:00Z"))).toBe(true);
  });

  it("should return false for expired delegation", () => {
    const cert = createActiveCert();
    expect(isDelegationAuthorised(cert, "UniversityDegreeCredential", "education",
      new Date("2028-01-01T00:00:00Z"))).toBe(false);
  });

  it("should return false for not-yet-valid delegation", () => {
    const cert = createActiveCert();
    expect(isDelegationAuthorised(cert, "UniversityDegreeCredential", "education",
      new Date("2025-01-01T00:00:00Z"))).toBe(false);
  });

  it("should return false for out-of-scope credential type", () => {
    const cert = createActiveCert();
    expect(isDelegationAuthorised(cert, "DriverLicenseCredential", undefined,
      new Date("2026-06-15T00:00:00Z"))).toBe(false);
  });

  it("should return false for out-of-scope namespace", () => {
    const cert = createActiveCert();
    expect(isDelegationAuthorised(cert, undefined, "healthcare",
      new Date("2026-06-15T00:00:00Z"))).toBe(false);
  });

  it("should return true for unrestricted scope", () => {
    const cert = createDelegationCertificate(
      createValidParams({
        scope: { credentialTypes: [], namespaces: [] },
      }),
    ) as unknown as DelegationCertificate;
    cert.proof = {
      type: "DataIntegrityProof", cryptosuite: "ecdsa-rdfc-2019",
      created: "2026-01-01T00:00:00Z", verificationMethod: "test",
      proofPurpose: "assertionMethod", proofValue: "zFake",
    };

    expect(isDelegationAuthorised(cert, "AnythingGoes", "anything",
      new Date("2026-06-15T00:00:00Z"))).toBe(true);
  });
});

describe("computeDelegationStatus", () => {
  it("should return 'active' within validity period", () => {
    const cert = createDelegationCertificate(createValidParams());
    expect(computeDelegationStatus(cert, new Date("2026-06-15T00:00:00Z"))).toBe("active");
  });

  it("should return 'expired' after validUntil", () => {
    const cert = createDelegationCertificate(createValidParams());
    expect(computeDelegationStatus(cert, new Date("2028-01-01T00:00:00Z"))).toBe("expired");
  });

  it("should return 'not-yet-valid' before validFrom", () => {
    const cert = createDelegationCertificate(createValidParams());
    expect(computeDelegationStatus(cert, new Date("2025-01-01T00:00:00Z"))).toBe("not-yet-valid");
  });
});
