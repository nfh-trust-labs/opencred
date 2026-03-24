import { describe, it, expect } from "vitest";
import { validateKeyAttestation, isKeyAttestationCredential } from "../validator.js";
import { OPENCRED_KEY_ATTESTATION_V1_CONTEXT } from "../types.js";
import { W3C_CREDENTIALS_V2_CONTEXT, DATA_INTEGRITY_V1_CONTEXT } from "@opencred/vc-core";

function validAttestation(): Record<string, unknown> {
  return {
    "@context": [
      W3C_CREDENTIALS_V2_CONTEXT,
      DATA_INTEGRITY_V1_CONTEXT,
      OPENCRED_KEY_ATTESTATION_V1_CONTEXT,
    ],
    id: "urn:uuid:test-id",
    type: ["VerifiableCredential", "KeyAttestationCredential"],
    issuer: "did:key:z6MkOpenCred",
    validFrom: "2025-01-01T00:00:00Z",
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
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2026-03-10T00:00:00Z",
      verificationMethod: "did:key:z6MkOpenCred#z6MkOpenCred",
      proofPurpose: "assertionMethod",
      proofValue: "z...",
    },
  };
}

describe("validateKeyAttestation", () => {
  it("accepts a valid attestation", () => {
    const result = validateKeyAttestation(validAttestation());

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects null input", () => {
    const result = validateKeyAttestation(null);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Attestation must be a non-null object");
  });

  it("rejects non-object input", () => {
    const result = validateKeyAttestation("not-an-object");

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Attestation must be a non-null object");
  });

  it("rejects missing @context", () => {
    const attestation = validAttestation();
    delete attestation["@context"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("@context must be an array");
  });

  it("rejects @context without key-attestation context", () => {
    const attestation = validAttestation();
    attestation["@context"] = [W3C_CREDENTIALS_V2_CONTEXT];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain(OPENCRED_KEY_ATTESTATION_V1_CONTEXT);
  });

  it("rejects missing KeyAttestationCredential type", () => {
    const attestation = validAttestation();
    attestation["type"] = ["VerifiableCredential"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("type must include 'KeyAttestationCredential'");
  });

  it("rejects missing VerifiableCredential type", () => {
    const attestation = validAttestation();
    attestation["type"] = ["KeyAttestationCredential"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("type must include 'VerifiableCredential'");
  });

  it("rejects missing issuer", () => {
    const attestation = validAttestation();
    delete attestation["issuer"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("issuer must be a DID string");
  });

  it("rejects missing credentialSubject", () => {
    const attestation = validAttestation();
    delete attestation["credentialSubject"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("credentialSubject is required");
  });

  it("rejects missing credentialSubject.id", () => {
    const attestation = validAttestation();
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    delete subject["id"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("credentialSubject.id is required");
  });

  it("rejects missing keyJwk", () => {
    const attestation = validAttestation();
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    delete subject["keyJwk"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("credentialSubject.keyJwk is required");
  });

  it("rejects missing identityVerification", () => {
    const attestation = validAttestation();
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    delete subject["identityVerification"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("credentialSubject.identityVerification is required");
  });

  it("rejects missing identityVerification.method", () => {
    const attestation = validAttestation();
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    const iv = subject["identityVerification"] as Record<string, unknown>;
    delete iv["method"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("identityVerification.method is required");
  });

  // Temporal validation
  it("rejects attestation not yet valid (validFrom in future)", () => {
    const attestation = validAttestation();
    attestation["validFrom"] = "2099-01-01T00:00:00Z";
    attestation["validUntil"] = "2100-01-01T00:00:00Z";

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Attestation is not yet valid (validFrom is in the future)");
  });

  it("rejects expired attestation", () => {
    const attestation = validAttestation();
    attestation["validFrom"] = "2020-01-01T00:00:00Z";
    attestation["validUntil"] = "2021-01-01T00:00:00Z";

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Attestation has expired (validUntil is in the past)");
  });

  it("validates at a specific point in time", () => {
    const attestation = validAttestation();
    attestation["validFrom"] = "2026-01-01T00:00:00Z";
    attestation["validUntil"] = "2026-06-01T00:00:00Z";

    // Valid at this time
    const validResult = validateKeyAttestation(attestation, {
      now: new Date("2026-03-01T00:00:00Z"),
    });
    expect(validResult.valid).toBe(true);

    // Expired at this time
    const expiredResult = validateKeyAttestation(attestation, {
      now: new Date("2026-07-01T00:00:00Z"),
    });
    expect(expiredResult.valid).toBe(false);
    expect(expiredResult.errors).toContain("Attestation has expired (validUntil is in the past)");
  });

  it("rejects missing validFrom", () => {
    const attestation = validAttestation();
    delete attestation["validFrom"];

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("validFrom is required");
  });

  // Key binding checks
  it("accepts matching key fingerprint", () => {
    const result = validateKeyAttestation(validAttestation(), {
      signingKeyFingerprint: "sha256:a1b2c3d4",
    });

    expect(result.valid).toBe(true);
  });

  it("rejects mismatched key fingerprint", () => {
    const result = validateKeyAttestation(validAttestation(), {
      signingKeyFingerprint: "sha256:different",
    });

    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("Key binding mismatch");
  });

  it("accepts matching verification method ID", () => {
    const result = validateKeyAttestation(validAttestation(), {
      signingVerificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
    });

    expect(result.valid).toBe(true);
  });

  it("accepts base DID match for verification method", () => {
    const result = validateKeyAttestation(validAttestation(), {
      signingVerificationMethodId: "did:key:z6MkIssuer#differentFragment",
    });

    expect(result.valid).toBe(true);
  });

  it("rejects mismatched verification method", () => {
    const result = validateKeyAttestation(validAttestation(), {
      signingVerificationMethodId: "did:key:z6MkSomeoneElse#z6MkSomeoneElse",
    });

    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("Verification method mismatch");
  });

  // sourceCredentialId validation for business-vc
  it("requires sourceCredentialId for business-vc method", () => {
    const attestation = validAttestation();
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    subject["identityVerification"] = {
      method: "business-vc",
      verifiedDomain: "example.com",
      verifiedAt: "2026-03-10T12:00:00Z",
    };

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      "identityVerification.sourceCredentialId is required for business-vc method",
    );
  });

  it("accepts business-vc method with sourceCredentialId", () => {
    const attestation = validAttestation();
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    subject["identityVerification"] = {
      method: "business-vc",
      verifiedDomain: "example.com",
      verifiedAt: "2026-03-10T12:00:00Z",
      sourceCredentialId: "urn:uuid:biz-vc-123",
    };

    const result = validateKeyAttestation(attestation);
    expect(result.valid).toBe(true);
  });

  // Multiple errors
  it("collects multiple errors", () => {
    const attestation = {
      "@context": ["wrong"],
      type: ["wrong"],
      credentialSubject: {},
    };

    const result = validateKeyAttestation(attestation);

    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(3);
  });
});

describe("isKeyAttestationCredential", () => {
  it("returns true for valid attestation credential", () => {
    expect(isKeyAttestationCredential(validAttestation())).toBe(true);
  });

  it("returns false for null", () => {
    expect(isKeyAttestationCredential(null)).toBe(false);
  });

  it("returns false for non-object", () => {
    expect(isKeyAttestationCredential("string")).toBe(false);
  });

  it("returns false for VC without KeyAttestationCredential type", () => {
    expect(
      isKeyAttestationCredential({
        type: ["VerifiableCredential"],
      }),
    ).toBe(false);
  });
});
