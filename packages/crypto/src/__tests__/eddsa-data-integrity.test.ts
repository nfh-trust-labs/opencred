import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import {
  prepareEdDsaProof,
  completeEdDsaProof,
  signCredentialEdDsa,
  verifyEdDsaProof,
} from "../eddsa-data-integrity.js";
import type { SigningKey, ProofOptions } from "../types.js";

function generateEd25519KeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

function createTestSigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateEd25519KeyPair();
  return { id, privateKey, publicKey, algorithm: "Ed25519" };
}

function createTestCredential(): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:test-eddsa-credential-001",
    type: ["VerifiableCredential"],
    issuer: "did:web:university.example",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder123",
      name: "Jane Doe",
    },
  };
}

const defaultProofOptions: ProofOptions = {
  verificationMethod: "did:web:university.example#key-ed25519",
  proofPurpose: "assertionMethod",
  created: "2026-01-01T00:00:00Z",
};

describe("signCredentialEdDsa / verifyEdDsaProof — full round-trip", () => {
  it("should sign and verify a credential successfully", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-ed25519");

    const signedVC = await signCredentialEdDsa(unsignedVC, signingKey, defaultProofOptions);

    expect(signedVC.proof).toBeDefined();
    expect(signedVC.proof.type).toBe("DataIntegrityProof");
    expect(signedVC.proof.cryptosuite).toBe("eddsa-rdfc-2022");
    expect(signedVC.proof.proofPurpose).toBe("assertionMethod");
    expect(signedVC.proof.verificationMethod).toBe("did:web:university.example#key-ed25519");
    expect(signedVC.proof.proofValue).toMatch(/^z/);
    expect(signedVC.proof.created).toBe("2026-01-01T00:00:00Z");

    const result = await verifyEdDsaProof(signedVC, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("should preserve all credential fields after signing", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-ed25519");

    const signedVC = await signCredentialEdDsa(unsignedVC, signingKey, defaultProofOptions);

    expect(signedVC["@context"]).toEqual(unsignedVC["@context"]);
    expect(signedVC.id).toBe(unsignedVC.id);
    expect(signedVC.type).toEqual(unsignedVC.type);
    expect(signedVC.issuer).toBe(unsignedVC.issuer);
    expect(signedVC.validFrom).toBe(unsignedVC.validFrom);
    expect(signedVC.credentialSubject).toEqual(unsignedVC.credentialSubject);
  });

  it("should reject non-Ed25519 keys", async () => {
    const unsignedVC = createTestCredential();
    const ecKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signingKey: SigningKey = {
      id: "did:web:example#key-1",
      privateKey: ecKey.privateKey,
      publicKey: ecKey.publicKey,
      algorithm: "P-256",
    };

    await expect(
      signCredentialEdDsa(unsignedVC, signingKey, defaultProofOptions),
    ).rejects.toThrow(CryptoError);
  });
});

describe("prepareEdDsaProof / completeEdDsaProof — two-phase round-trip", () => {
  it("should prepare, externally sign, complete, and verify", async () => {
    const unsignedVC = createTestCredential();
    const { privateKey, publicKey } = generateEd25519KeyPair();

    // Phase 1: Prepare
    const prepared = await prepareEdDsaProof(unsignedVC, defaultProofOptions);
    expect(prepared.dataToSign).toBeInstanceOf(Uint8Array);
    expect(prepared.dataToSign.length).toBe(64); // SHA-256(proofConfig) || SHA-256(document)
    expect(prepared.proofConfig.type).toBe("DataIntegrityProof");
    expect(prepared.proofConfig.cryptosuite).toBe("eddsa-rdfc-2022");

    // External signing (simulating browser or HSM)
    const signature = sign(null, prepared.dataToSign, privateKey);
    expect(signature.length).toBe(64);

    // Phase 2: Complete
    const signedVC = completeEdDsaProof(unsignedVC, prepared.proofConfig, new Uint8Array(signature));
    expect(signedVC.proof).toBeDefined();
    expect(signedVC.proof.proofValue).toMatch(/^z/);

    // Verify
    const result = await verifyEdDsaProof(signedVC, { publicKey });
    expect(result.verified).toBe(true);
  });

  it("should reject signature of wrong length in completeEdDsaProof", () => {
    const unsignedVC = createTestCredential();
    const proofConfig = {
      "@context": unsignedVC["@context"] as (string | Record<string, unknown>)[],
      type: "DataIntegrityProof" as const,
      cryptosuite: "eddsa-rdfc-2022" as const,
      created: "2026-01-01T00:00:00Z",
      verificationMethod: "did:web:university.example#key-ed25519",
      proofPurpose: "assertionMethod",
    };

    expect(() => completeEdDsaProof(unsignedVC, proofConfig, new Uint8Array(32))).toThrow(
      CryptoError,
    );
  });
});

describe("verifyEdDsaProof — failure cases", () => {
  it("should fail for a tampered credential", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-ed25519");

    const signedVC = await signCredentialEdDsa(unsignedVC, signingKey, defaultProofOptions);

    const tampered: VerifiableCredential = {
      ...signedVC,
      credentialSubject: {
        ...signedVC.credentialSubject,
        name: "Evil Eve",
      },
    };

    const result = await verifyEdDsaProof(tampered, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(false);
  });

  it("should fail when proof is missing", async () => {
    const vc = createTestCredential() as unknown as VerifiableCredential;
    // @ts-expect-error — deliberately testing missing proof
    delete vc.proof;

    const result = await verifyEdDsaProof(vc);
    expect(result.verified).toBe(false);
    expect(result.error).toContain("no proof");
  });

  it("should fail for unsupported cryptosuite", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-ed25519");
    const signedVC = await signCredentialEdDsa(unsignedVC, signingKey, defaultProofOptions);

    const modified: VerifiableCredential = {
      ...signedVC,
      proof: { ...signedVC.proof, cryptosuite: "ecdsa-rdfc-2019" },
    };

    const result = await verifyEdDsaProof(modified, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(false);
    expect(result.error).toContain("Unsupported cryptosuite");
  });

  it("should fail when no public key is available", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-ed25519");
    const signedVC = await signCredentialEdDsa(unsignedVC, signingKey, defaultProofOptions);

    const result = await verifyEdDsaProof(signedVC);
    expect(result.verified).toBe(false);
    expect(result.error).toContain("Unable to resolve public key");
  });

  it("should fail with wrong public key", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-ed25519");
    const signedVC = await signCredentialEdDsa(unsignedVC, signingKey, defaultProofOptions);

    const { publicKey: wrongKey } = generateEd25519KeyPair();
    const result = await verifyEdDsaProof(signedVC, { publicKey: wrongKey });
    expect(result.verified).toBe(false);
  });
});

describe("prepareEdDsaProof — validation", () => {
  it("should throw for missing verificationMethod", async () => {
    const unsignedVC = createTestCredential();
    await expect(
      prepareEdDsaProof(unsignedVC, {
        verificationMethod: "",
        proofPurpose: "assertionMethod",
      }),
    ).rejects.toThrow(CryptoError);
  });

  it("should throw for missing proofPurpose", async () => {
    const unsignedVC = createTestCredential();
    await expect(
      prepareEdDsaProof(unsignedVC, {
        verificationMethod: "did:web:example#key-1",
        proofPurpose: "",
      }),
    ).rejects.toThrow(CryptoError);
  });
});

describe("proof with domain and challenge", () => {
  it("should include domain and challenge in the proof", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-ed25519");

    const signedVC = await signCredentialEdDsa(unsignedVC, signingKey, {
      ...defaultProofOptions,
      domain: "https://example.com",
      challenge: "abc123",
    });

    expect(signedVC.proof.domain).toBe("https://example.com");
    expect(signedVC.proof.challenge).toBe("abc123");

    const result = await verifyEdDsaProof(signedVC, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(true);
  });
});
