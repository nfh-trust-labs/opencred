import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign, type KeyObject } from "node:crypto";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import {
  signCredential,
  verifyProof,
  prepareProof,
  completeProof,
  multibaseDecode,
} from "../data-integrity.js";
import type { SigningKey, ProofOptions } from "../types.js";

function generateP384KeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-384" });
}

function createP384SigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateP384KeyPair();
  return { id, privateKey, publicKey, algorithm: "P-384" };
}

function createTestCredential(): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:p384-test-credential",
    type: ["VerifiableCredential"],
    issuer: "did:web:university.example",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder-p384",
      name: "P-384 Test Subject",
    },
  };
}

const defaultProofOptions: ProofOptions = {
  verificationMethod: "did:web:university.example#key-p384",
  proofPurpose: "assertionMethod",
  created: "2026-01-01T00:00:00Z",
};

describe("P-384 Data Integrity — signCredential", () => {
  it("should produce a VC with a 96-byte proof signature", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createP384SigningKey("did:web:university.example#key-p384");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    expect(signedVC.proof).toBeDefined();
    expect(signedVC.proof.type).toBe("DataIntegrityProof");
    expect(signedVC.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(signedVC.proof.proofValue).toMatch(/^z/); // multibase base58btc prefix

    // Decode the signature and check it is 96 bytes (P-384 raw r||s)
    const sigBytes = multibaseDecode(signedVC.proof.proofValue);
    expect(sigBytes.length).toBe(96);
  });

  it("should preserve all credential fields after signing", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createP384SigningKey("did:web:university.example#key-p384");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    expect(signedVC["@context"]).toEqual(unsignedVC["@context"]);
    expect(signedVC.id).toBe(unsignedVC.id);
    expect(signedVC.type).toEqual(unsignedVC.type);
    expect(signedVC.issuer).toBe(unsignedVC.issuer);
    expect(signedVC.validFrom).toBe(unsignedVC.validFrom);
    expect(signedVC.credentialSubject).toEqual(unsignedVC.credentialSubject);
  });
});

describe("P-384 Data Integrity — verifyProof", () => {
  it("should verify a P-384-signed credential", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createP384SigningKey("did:web:university.example#key-p384");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const result = await verifyProof(signedVC, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("should fail verification with a tampered credential", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createP384SigningKey("did:web:university.example#key-p384");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const tampered: VerifiableCredential = {
      ...signedVC,
      credentialSubject: {
        ...signedVC.credentialSubject,
        name: "Tampered Name",
      },
    };

    const result = await verifyProof(tampered, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("should fail verification with wrong public key", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createP384SigningKey("did:web:university.example#key-p384");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const { publicKey: wrongKey } = generateP384KeyPair();
    const result = await verifyProof(signedVC, { publicKey: wrongKey });
    expect(result.verified).toBe(false);
  });
});

describe("P-384 Data Integrity — sign/verify round-trip", () => {
  it("should complete a full sign-then-verify round-trip with P-384", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createP384SigningKey("did:web:university.example#key-p384");

    // Sign
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    // Verify
    const result = await verifyProof(signedVC, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(true);

    // The proof metadata should be correct
    expect(signedVC.proof.verificationMethod).toBe("did:web:university.example#key-p384");
    expect(signedVC.proof.proofPurpose).toBe("assertionMethod");
    expect(signedVC.proof.created).toBe("2026-01-01T00:00:00Z");
  });
});

describe("P-384 Data Integrity — prepareProof", () => {
  it("should produce a 96-byte dataToSign when algorithm is P-384", async () => {
    const unsignedVC = createTestCredential();

    // prepareProof with P-384 should use SHA-384 hashes (48+48=96 bytes)
    const prepared = await prepareProof(unsignedVC, defaultProofOptions, "P-384");

    expect(prepared.dataToSign).toBeInstanceOf(Uint8Array);
    // SHA-384 hash = 48 bytes; two hashes concatenated = 96 bytes
    expect(prepared.dataToSign.length).toBe(96);
    expect(prepared.proofConfig.type).toBe("DataIntegrityProof");
    expect(prepared.proofConfig.cryptosuite).toBe("ecdsa-rdfc-2019");
  });

  it("should produce a 64-byte dataToSign when algorithm is P-256 (default)", async () => {
    const unsignedVC = createTestCredential();

    const prepared = await prepareProof(unsignedVC, defaultProofOptions);

    expect(prepared.dataToSign).toBeInstanceOf(Uint8Array);
    // SHA-256 hash = 32 bytes; two hashes concatenated = 64 bytes
    expect(prepared.dataToSign.length).toBe(64);
  });
});

describe("P-384 Data Integrity — two-phase prepareProof/completeProof", () => {
  it("should prepare, externally sign with P-384, complete, and verify", async () => {
    const unsignedVC = createTestCredential();
    const { privateKey, publicKey } = generateP384KeyPair();

    // Phase 1: Prepare with P-384
    const prepared = await prepareProof(unsignedVC, defaultProofOptions, "P-384");
    expect(prepared.dataToSign.length).toBe(96);

    // External signing (simulating P-384 ECDSA)
    const signer = createSign("SHA384");
    signer.update(prepared.dataToSign);
    const signatureBuffer = signer.sign({
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    const signatureBytes = new Uint8Array(signatureBuffer);
    expect(signatureBytes.length).toBe(96); // P-384 raw signature = 96 bytes

    // Phase 2: Complete
    const signedVC = completeProof(unsignedVC, prepared.proofConfig, signatureBytes);
    expect(signedVC.proof).toBeDefined();
    expect(signedVC.proof.proofValue).toMatch(/^z/);

    // Verify
    const result = await verifyProof(signedVC, { publicKey });
    expect(result.verified).toBe(true);
  });

  it("should accept 96-byte signature in completeProof", () => {
    const unsignedVC = createTestCredential();
    const proofConfig = {
      "@context": unsignedVC["@context"] as (string | Record<string, unknown>)[],
      type: "DataIntegrityProof" as const,
      cryptosuite: "ecdsa-rdfc-2019" as const,
      created: "2026-01-01T00:00:00Z",
      verificationMethod: "did:web:university.example#key-p384",
      proofPurpose: "assertionMethod",
    };

    // 96-byte signature should be accepted (P-384)
    const sig96 = new Uint8Array(96);
    for (let i = 0; i < 96; i++) sig96[i] = i;
    const vc = completeProof(unsignedVC, proofConfig, sig96);
    expect(vc.proof.proofValue).toMatch(/^z/);
  });
});
