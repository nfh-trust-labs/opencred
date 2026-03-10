import { describe, it, expect } from "vitest";
import { checkAttestationChain } from "../attestation-check.js";

function validAttestationVC(): Record<string, unknown> {
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/data-integrity/v1",
      "https://opencred.dev/ns/key-attestation/v1",
    ],
    id: "urn:uuid:attestation-id",
    type: ["VerifiableCredential", "KeyAttestationCredential"],
    issuer: "did:key:z6MkOpenCred",
    validFrom: "2025-01-01T00:00:00Z",
    validUntil: "2027-12-31T00:00:00Z",
    credentialSubject: {
      id: "did:key:z6MkIssuer",
      keyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      keyFingerprint: "sha256:a1b2c3d4",
      keyAlgorithm: "P-256",
      verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
      identityVerification: {
        method: "dns-txt",
        verifiedDomain: "university.example",
        verifiedAt: "2025-06-01T00:00:00Z",
        challengeId: "urn:uuid:challenge-id",
      },
      organizationName: "Example University",
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2025-01-01T00:00:00Z",
      verificationMethod: "did:key:z6MkOpenCred#z6MkOpenCred",
      proofPurpose: "assertionMethod",
      proofValue: "z...",
    },
  };
}

function credentialWithAttestation(): Record<string, unknown> {
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/data-integrity/v1",
    ],
    id: "urn:uuid:credential-id",
    type: ["VerifiableCredential", "EducationCredential"],
    issuer: "did:key:z6MkIssuer",
    validFrom: "2026-06-01T00:00:00Z",
    credentialSubject: {
      id: "did:key:z6MkStudent",
      degree: "Bachelor of Science",
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2026-06-01T00:00:00Z",
      verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
      proofPurpose: "assertionMethod",
      proofValue: "z...",
      keyAttestationCredential: validAttestationVC(),
    },
  };
}

describe("checkAttestationChain", () => {
  // Happy path
  it("passes for valid inline attestation with matching key", async () => {
    const result = await checkAttestationChain(credentialWithAttestation());

    expect(result.name).toBe("attestation");
    expect(result.passed).toBe(true);
  });

  // Skip cases
  it("skips when credential has no proof", async () => {
    const result = await checkAttestationChain({ type: ["VerifiableCredential"] });

    expect(result.passed).toBe(true);
    expect(result.detail).toContain("No proof");
  });

  it("skips when proof has no attestation reference", async () => {
    const credential = {
      proof: {
        type: "DataIntegrityProof",
        verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
        created: "2026-06-01T00:00:00Z",
        proofValue: "z...",
      },
    };

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(true);
    expect(result.detail).toContain("No attestation reference");
  });

  // Attestation type validation
  it("returns ATTESTATION_INVALID when attestation missing KeyAttestationCredential type", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    attestation["type"] = ["VerifiableCredential"]; // Missing KeyAttestationCredential

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("KeyAttestationCredential");
  });

  // Key binding
  it("fails when attested key does not match signing key", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    subject["verificationMethodId"] = "did:key:z6MkDifferent#z6MkDifferent";

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("key binding mismatch");
  });

  it("passes when attested key matches via base DID", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    // Different fragment but same base DID
    subject["verificationMethodId"] = "did:key:z6MkIssuer#differentFragment";

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(true);
  });

  it("fails when proof has no verificationMethod", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    delete proof["verificationMethod"];

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("no verificationMethod");
  });

  // Temporal validation
  it("fails when attestation not yet valid at proof time", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    // Attestation valid from 2027, but proof was created in 2026
    attestation["validFrom"] = "2027-01-01T00:00:00Z";

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("not yet valid");
  });

  it("fails when attestation expired before proof time", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    // Attestation expired before credential was signed
    attestation["validUntil"] = "2026-01-01T00:00:00Z";

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("expired");
  });

  it("fails when proof has no created timestamp", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    delete proof["created"];

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("no 'created' timestamp");
  });

  it("fails when proof.created is invalid", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    proof["created"] = "not-a-date";

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Invalid proof.created");
  });

  // URL-based attestation
  it("fails when attestation is URL-based but no DeDi client", async () => {
    const credential = {
      proof: {
        type: "DataIntegrityProof",
        verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
        created: "2026-06-01T00:00:00Z",
        proofValue: "z...",
        keyAttestationUrl: "https://dedi.example/attestation/123",
      },
    };

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("no DeDi client");
  });

  // Edge cases
  it("fails when attestation has no credentialSubject", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    delete attestation["credentialSubject"];

    const result = await checkAttestationChain(credential);

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("no credentialSubject");
  });
});
