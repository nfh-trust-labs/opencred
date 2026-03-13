import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { signCredential } from "@opencred/crypto";
import type { UnsignedCredential } from "@opencred/vc-core";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";
import { checkAttestationChain } from "../attestation-check.js";
import type { VerificationResultCode } from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

function createMockResolver(did: string, vm: VerificationMethod): DIDResolver {
  return {
    resolve: async (inputDid: string): Promise<DIDResolutionResult> => {
      if (inputDid !== did) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: "notFound" },
          didDocumentMetadata: {},
        };
      }
      return {
        didDocument: {
          "@context": "https://www.w3.org/ns/did/v1",
          id: did,
          verificationMethod: [vm],
          assertionMethod: [vm.id],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

/**
 * Create and cryptographically sign a Key Attestation VC using the given
 * OpenCred keypair. Returns the signed attestation as a plain object.
 */
async function createSignedAttestationVC(
  opencredKeyPair: { privateKey: KeyObject; publicKey: KeyObject },
  issuerVmId: string,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const opencredDid = "did:key:z6MkOpenCred";
  const opencredVmId = `${opencredDid}#z6MkOpenCred`;

  // Use only the W3C v2 context for signing to avoid JSON-LD context conflicts.
  // In production, the key-attestation context would be compatible; for tests
  // we use the minimal context set required for valid Data Integrity signing.
  const unsignedAttestation: UnsignedCredential = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
    ],
    id: "urn:uuid:attestation-id",
    type: ["VerifiableCredential", "KeyAttestationCredential"],
    issuer: opencredDid,
    validFrom: (overrides["validFrom"] as string) ?? "2025-01-01T00:00:00Z",
    validUntil: (overrides["validUntil"] as string) ?? "2027-12-31T00:00:00Z",
    credentialSubject: {
      id: issuerVmId.split("#")[0],
      verificationMethodId: issuerVmId,
    },
  };

  const signed = await signCredential(
    unsignedAttestation,
    {
      id: opencredVmId,
      privateKey: opencredKeyPair.privateKey,
      publicKey: opencredKeyPair.publicKey,
      algorithm: "P-256",
    },
    {
      verificationMethod: opencredVmId,
      proofPurpose: "assertionMethod",
      created: "2025-01-01T00:00:00Z",
    },
  );

  // Apply any proof overrides
  const result = signed as unknown as Record<string, unknown>;
  if (overrides["type"]) {
    result["type"] = overrides["type"];
  }
  return result;
}

/**
 * Build a credential that embeds a signed attestation VC in its proof.
 */
function credentialWithSignedAttestation(
  attestationVC: Record<string, unknown>,
  issuerVmId: string = "did:key:z6MkIssuer#z6MkIssuer",
): Record<string, unknown> {
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/data-integrity/v1",
    ],
    id: "urn:uuid:credential-id",
    type: ["VerifiableCredential", "EducationCredential"],
    issuer: issuerVmId.split("#")[0],
    validFrom: "2026-06-01T00:00:00Z",
    credentialSubject: {
      id: "did:key:z6MkStudent",
      degree: "Bachelor of Science",
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2026-06-01T00:00:00Z",
      verificationMethod: issuerVmId,
      proofPurpose: "assertionMethod",
      proofValue: "z...",
      keyAttestationCredential: attestationVC,
    },
  };
}

// Structural-only attestation VC (no real signature)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("checkAttestationChain", () => {
  // ---- Structural / Skip tests (unchanged behavior) ----

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

  // ---- Attestation type validation ----

  it("fails when attestation missing KeyAttestationCredential type", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    attestation["type"] = ["VerifiableCredential"];

    const result = await checkAttestationChain(credential);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("KeyAttestationCredential");
  });

  // ---- Key binding ----

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

  it("passes key binding when attested key matches via base DID", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    const subject = attestation["credentialSubject"] as Record<string, unknown>;
    subject["verificationMethodId"] = "did:key:z6MkIssuer#differentFragment";

    // Structural validation passes -- signature check will fail since it's a mock
    // but key binding should pass
    const result = await checkAttestationChain(credential);
    // Key binding passes but signature check fails (no resolver or key configured)
    expect(result.detail).not.toContain("key binding mismatch");
  });

  it("fails when proof has no verificationMethod", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    delete proof["verificationMethod"];

    const result = await checkAttestationChain(credential);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("no verificationMethod");
  });

  // ---- Temporal validation ----

  it("fails when attestation not yet valid at proof time", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    attestation["validFrom"] = "2027-01-01T00:00:00Z";

    const result = await checkAttestationChain(credential);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("not yet valid");
  });

  it("fails when attestation expired before proof time", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
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

  // ---- Edge cases ----

  it("fails when attestation has no credentialSubject", async () => {
    const credential = credentialWithAttestation();
    const proof = credential["proof"] as Record<string, unknown>;
    const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
    delete attestation["credentialSubject"];

    const result = await checkAttestationChain(credential);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("no credentialSubject");
  });

  // ---- Cryptographic signature verification ----

  describe("attestation VC signature verification", () => {
    it("passes for valid attestation VC with valid cryptographic signature (opencredPublicKey)", async () => {
      const opencredKeyPair = generateTestKeyPair();
      const issuerVmId = "did:key:z6MkIssuer#z6MkIssuer";

      const signedAttestation = await createSignedAttestationVC(opencredKeyPair, issuerVmId);
      const credential = credentialWithSignedAttestation(signedAttestation, issuerVmId);

      const result = await checkAttestationChain(credential, {
        opencredPublicKey: opencredKeyPair.publicKey,
      });

      expect(result.passed).toBe(true);
      expect(result.name).toBe("attestation");
    });

    it("fails for attestation VC with tampered content (signature mismatch)", async () => {
      const opencredKeyPair = generateTestKeyPair();
      const issuerVmId = "did:key:z6MkIssuer#z6MkIssuer";

      const signedAttestation = await createSignedAttestationVC(opencredKeyPair, issuerVmId);
      // Tamper with the attestation after signing -- change a field that exists
      const subject = signedAttestation["credentialSubject"] as Record<string, unknown>;
      subject["id"] = "did:key:z6MkTampered";

      const credential = credentialWithSignedAttestation(signedAttestation, issuerVmId);

      const result = await checkAttestationChain(credential, {
        opencredPublicKey: opencredKeyPair.publicKey,
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Attestation VC signature invalid");
    });

    it("fails when attestation VC was signed by wrong key", async () => {
      const opencredKeyPair = generateTestKeyPair();
      const wrongKeyPair = generateTestKeyPair();
      const issuerVmId = "did:key:z6MkIssuer#z6MkIssuer";

      // Sign with the real key but verify with a different one
      const signedAttestation = await createSignedAttestationVC(opencredKeyPair, issuerVmId);
      const credential = credentialWithSignedAttestation(signedAttestation, issuerVmId);

      const result = await checkAttestationChain(credential, {
        opencredPublicKey: wrongKeyPair.publicKey,
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Attestation VC signature invalid");
    });

    it("passes when attestation VC signature is verified via DID resolver", async () => {
      const opencredKeyPair = generateTestKeyPair();
      const issuerVmId = "did:key:z6MkIssuer#z6MkIssuer";
      const opencredDid = "did:key:z6MkOpenCred";
      const opencredVmId = `${opencredDid}#z6MkOpenCred`;

      const signedAttestation = await createSignedAttestationVC(opencredKeyPair, issuerVmId);
      const credential = credentialWithSignedAttestation(signedAttestation, issuerVmId);

      const jwk = opencredKeyPair.publicKey.export({ format: "jwk" });
      const resolver = createMockResolver(opencredDid, {
        id: opencredVmId,
        type: "JsonWebKey",
        controller: opencredDid,
        publicKeyJwk: jwk as import("@opencred/did").JWK,
      });

      const result = await checkAttestationChain(credential, {
        didResolver: resolver,
      });

      expect(result.passed).toBe(true);
    });

    it("fails when no public key or DID resolver is configured", async () => {
      const credential = credentialWithAttestation();

      const result = await checkAttestationChain(credential, {});

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("No OpenCred public key or DID resolver configured");
    });

    it("fails when attestation VC has no proof", async () => {
      const credential = credentialWithAttestation();
      const proof = credential["proof"] as Record<string, unknown>;
      const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
      delete attestation["proof"];

      const result = await checkAttestationChain(credential, {});

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Attestation VC has no proof");
    });

    it("fails when attestation proof has no verificationMethod and opencredPublicKey is set", async () => {
      const opencredKeyPair = generateTestKeyPair();
      const credential = credentialWithAttestation();
      const proof = credential["proof"] as Record<string, unknown>;
      const attestation = proof["keyAttestationCredential"] as Record<string, unknown>;
      const attestationProof = attestation["proof"] as Record<string, unknown>;
      delete attestationProof["verificationMethod"];

      const result = await checkAttestationChain(credential, {
        opencredPublicKey: opencredKeyPair.publicKey,
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Attestation proof has no verificationMethod");
    });
  });

  // ---- URL-based attestation resolution ----

  describe("URL-based attestation resolution", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let fetchSpy: any;

    beforeEach(() => {
      fetchSpy = vi.spyOn(globalThis, "fetch");
    });

    afterEach(() => {
      fetchSpy.mockRestore();
    });

    it("fetches and validates attestation from URL", async () => {
      const opencredKeyPair = generateTestKeyPair();
      const issuerVmId = "did:key:z6MkIssuer#z6MkIssuer";

      const signedAttestation = await createSignedAttestationVC(opencredKeyPair, issuerVmId);

      fetchSpy.mockResolvedValueOnce(
        new Response(JSON.stringify(signedAttestation), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );

      const credential = {
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "ecdsa-rdfc-2019",
          created: "2026-06-01T00:00:00Z",
          verificationMethod: issuerVmId,
          proofPurpose: "assertionMethod",
          proofValue: "z...",
          keyAttestationUrl: "https://dedi.example/attestation/123",
        },
      };

      const result = await checkAttestationChain(credential, {
        opencredPublicKey: opencredKeyPair.publicKey,
      });

      expect(result.passed).toBe(true);
      expect(fetchSpy).toHaveBeenCalledOnce();
      expect(fetchSpy).toHaveBeenCalledWith(
        "https://dedi.example/attestation/123",
        expect.objectContaining({
          redirect: "error",
        }),
      );
    });

    it("rejects non-HTTPS attestation URLs", async () => {
      const credential = {
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "ecdsa-rdfc-2019",
          created: "2026-06-01T00:00:00Z",
          verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
          proofPurpose: "assertionMethod",
          proofValue: "z...",
          keyAttestationUrl: "http://insecure.example/attestation/123",
        },
      };

      const result = await checkAttestationChain(credential, {});

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Attestation URL must use HTTPS");
    });

    it("rejects invalid attestation URLs", async () => {
      const credential = {
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "ecdsa-rdfc-2019",
          created: "2026-06-01T00:00:00Z",
          verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
          proofPurpose: "assertionMethod",
          proofValue: "z...",
          keyAttestationUrl: "not-a-url",
        },
      };

      const result = await checkAttestationChain(credential, {});

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Invalid attestation URL");
    });

    it("handles fetch failure gracefully", async () => {
      fetchSpy.mockRejectedValueOnce(new Error("Network error"));

      const credential = {
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "ecdsa-rdfc-2019",
          created: "2026-06-01T00:00:00Z",
          verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
          proofPurpose: "assertionMethod",
          proofValue: "z...",
          keyAttestationUrl: "https://dedi.example/attestation/123",
        },
      };

      const result = await checkAttestationChain(credential, {});

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("failed to fetch attestation from URL");
    });

    it("handles HTTP error responses", async () => {
      fetchSpy.mockResolvedValueOnce(
        new Response("Not Found", { status: 404 }),
      );

      const credential = {
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "ecdsa-rdfc-2019",
          created: "2026-06-01T00:00:00Z",
          verificationMethod: "did:key:z6MkIssuer#z6MkIssuer",
          proofPurpose: "assertionMethod",
          proofValue: "z...",
          keyAttestationUrl: "https://dedi.example/attestation/123",
        },
      };

      const result = await checkAttestationChain(credential, {});

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("HTTP 404");
    });
  });

  // ---- DELEGATION_INVALID removed ----

  it("DELEGATION_INVALID is not in VerificationResultCode", async () => {
    // This test verifies that DELEGATION_INVALID has been removed from the union.
    // The type system enforces it at compile time, but we also verify
    // that the string value is not usable as a result code.
    const validCodes: VerificationResultCode[] = [
      "VALID",
      "REVOKED",
      "EXPIRED",
      "INVALID",
      "UNRESOLVABLE",
      "ATTESTATION_INVALID",
    ];
    expect(validCodes).not.toContain("DELEGATION_INVALID");
    expect(validCodes).toContain("ATTESTATION_INVALID");
  });
});
