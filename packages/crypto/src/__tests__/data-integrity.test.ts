import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign, KeyObject } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import {
  prepareProof,
  completeProof,
  signCredential,
  verifyProof,
  multibaseEncode,
  multibaseDecode,
} from "../data-integrity.js";
import type { SigningKey, ProofOptions } from "../types.js";

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

function createTestSigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateTestKeyPair();
  return { id, privateKey, publicKey, algorithm: "P-256" };
}

function createTestCredential(): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:test-credential-001",
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
  verificationMethod: "did:web:university.example#key-1",
  proofPurpose: "assertionMethod",
  created: "2026-01-01T00:00:00Z",
};

describe("signCredential / verifyProof — full round-trip", () => {
  it("should sign and verify a credential successfully", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    expect(signedVC.proof).toBeDefined();
    expect(signedVC.proof.type).toBe("DataIntegrityProof");
    expect(signedVC.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(signedVC.proof.proofPurpose).toBe("assertionMethod");
    expect(signedVC.proof.verificationMethod).toBe("did:web:university.example#key-1");
    expect(signedVC.proof.proofValue).toMatch(/^z/); // multibase base58btc prefix
    expect(signedVC.proof.created).toBe("2026-01-01T00:00:00Z");

    // Verify with the public key
    const result = await verifyProof(signedVC, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("should preserve all credential fields after signing", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    expect(signedVC["@context"]).toEqual(unsignedVC["@context"]);
    expect(signedVC.id).toBe(unsignedVC.id);
    expect(signedVC.type).toEqual(unsignedVC.type);
    expect(signedVC.issuer).toBe(unsignedVC.issuer);
    expect(signedVC.validFrom).toBe(unsignedVC.validFrom);
    expect(signedVC.credentialSubject).toEqual(unsignedVC.credentialSubject);
  });

  it("should auto-generate created timestamp if not provided", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");

    const signedVC = await signCredential(unsignedVC, signingKey, {
      verificationMethod: "did:web:university.example#key-1",
      proofPurpose: "assertionMethod",
    });

    expect(signedVC.proof.created).toBeDefined();
    // Should be a valid ISO 8601 date
    expect(new Date(signedVC.proof.created).toISOString()).toBe(signedVC.proof.created);
  });
});

describe("prepareProof / completeProof — two-phase round-trip", () => {
  it("should prepare, externally sign, complete, and verify", async () => {
    const unsignedVC = createTestCredential();
    const { privateKey, publicKey } = generateTestKeyPair();

    // Phase 1: Prepare
    const prepared = await prepareProof(unsignedVC, defaultProofOptions);
    expect(prepared.dataToSign).toBeInstanceOf(Uint8Array);
    expect(prepared.dataToSign.length).toBe(64); // SHA-256(proofConfig) || SHA-256(document)
    expect(prepared.proofConfig.type).toBe("DataIntegrityProof");
    expect(prepared.proofConfig.cryptosuite).toBe("ecdsa-rdfc-2019");

    // External signing (simulating browser SubtleCrypto or HSM)
    const signer = createSign("SHA256");
    signer.update(prepared.dataToSign);
    const signatureBuffer = signer.sign({
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    const signatureBytes = new Uint8Array(signatureBuffer);
    expect(signatureBytes.length).toBe(64); // P-256 raw signature = 64 bytes

    // Phase 2: Complete
    const signedVC = completeProof(unsignedVC, prepared.proofConfig, signatureBytes);
    expect(signedVC.proof).toBeDefined();
    expect(signedVC.proof.proofValue).toMatch(/^z/);

    // Verify
    const result = await verifyProof(signedVC, { publicKey });
    expect(result.verified).toBe(true);
  });

  it("should reject signature of wrong length in completeProof", () => {
    const unsignedVC = createTestCredential();
    const proofConfig = {
      "@context": unsignedVC["@context"] as (string | Record<string, unknown>)[],
      type: "DataIntegrityProof" as const,
      cryptosuite: "ecdsa-rdfc-2019" as const,
      created: "2026-01-01T00:00:00Z",
      verificationMethod: "did:web:university.example#key-1",
      proofPurpose: "assertionMethod",
    };

    expect(() => completeProof(unsignedVC, proofConfig, new Uint8Array(32))).toThrow(CryptoError);
  });
});

describe("verifyProof — failure cases", () => {
  it("should fail for a tampered credential", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");

    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    // Tamper with the credential
    const tampered: VerifiableCredential = {
      ...signedVC,
      credentialSubject: {
        ...signedVC.credentialSubject,
        name: "Evil Eve",
      },
    };

    const result = await verifyProof(tampered, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("should fail when proof is missing", async () => {
    const vc = createTestCredential() as unknown as VerifiableCredential;
    // @ts-expect-error — deliberately testing missing proof
    delete vc.proof;

    const result = await verifyProof(vc);
    expect(result.verified).toBe(false);
    expect(result.error).toContain("no proof");
  });

  it("should fail for unsupported proof type", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const modified: VerifiableCredential = {
      ...signedVC,
      proof: { ...signedVC.proof, type: "Ed25519Signature2020" },
    };

    const result = await verifyProof(modified, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(false);
    expect(result.error).toContain("Unsupported proof type");
  });

  it("should fail for unsupported cryptosuite", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const modified: VerifiableCredential = {
      ...signedVC,
      proof: { ...signedVC.proof, cryptosuite: "eddsa-rdfc-2022" },
    };

    const result = await verifyProof(modified, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(false);
    expect(result.error).toContain("Unsupported cryptosuite");
  });

  it("should fail when no public key is available for verification", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    // No public key provided and no resolver
    const result = await verifyProof(signedVC);
    expect(result.verified).toBe(false);
    expect(result.error).toContain("Unable to resolve public key");
  });

  it("should fail with wrong public key", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    // Use a different key pair for verification
    const { publicKey: wrongKey } = generateTestKeyPair();
    const result = await verifyProof(signedVC, { publicKey: wrongKey });
    expect(result.verified).toBe(false);
  });
});

describe("prepareProof — validation", () => {
  it("should throw for missing verificationMethod", async () => {
    const unsignedVC = createTestCredential();
    await expect(
      prepareProof(unsignedVC, {
        verificationMethod: "",
        proofPurpose: "assertionMethod",
      }),
    ).rejects.toThrow(CryptoError);
  });

  it("should throw for missing proofPurpose", async () => {
    const unsignedVC = createTestCredential();
    await expect(
      prepareProof(unsignedVC, {
        verificationMethod: "did:web:example#key-1",
        proofPurpose: "",
      }),
    ).rejects.toThrow(CryptoError);
  });
});

describe("signCredential — validation", () => {
  it("should throw for RSA keys (Data Integrity only supports EC)", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:example#key-1");
    // Tamper the algorithm to RSA, which is not supported by Data Integrity
    const badKey = { ...signingKey, algorithm: "RSA-2048" as const } as unknown as SigningKey;

    await expect(signCredential(unsignedVC, badKey, defaultProofOptions)).rejects.toThrow(
      CryptoError,
    );
  });
});

describe("multibaseEncode / multibaseDecode", () => {
  it("should round-trip encode/decode", () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const encoded = multibaseEncode(bytes);
    expect(encoded.startsWith("z")).toBe(true);

    const decoded = multibaseDecode(encoded);
    expect(decoded).toEqual(bytes);
  });

  it("should handle all-zero bytes", () => {
    const bytes = new Uint8Array([0, 0, 0, 1]);
    const encoded = multibaseEncode(bytes);
    const decoded = multibaseDecode(encoded);
    expect(decoded).toEqual(bytes);
  });

  it("should handle 64-byte signatures (P-256)", () => {
    // Simulate a P-256 signature (64 bytes)
    const sig = new Uint8Array(64);
    for (let i = 0; i < 64; i++) sig[i] = i;
    const encoded = multibaseEncode(sig);
    const decoded = multibaseDecode(encoded);
    expect(decoded).toEqual(sig);
  });

  it("should reject non-base58btc prefix", () => {
    expect(() => multibaseDecode("M" + "abc")).toThrow(CryptoError);
  });
});

describe("verifyProof — error propagation", () => {
  it("re-throws TypeError instead of swallowing it", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    // Use a Proxy to throw TypeError after the early proofValue check passes
    const corrupted = {
      ...signedVC,
      proof: new Proxy(signedVC.proof, {
        get(target, prop) {
          if (prop === "verificationMethod") {
            throw new TypeError("simulated TypeError");
          }
          return Reflect.get(target, prop);
        },
      }),
    } as VerifiableCredential;

    await expect(verifyProof(corrupted, { publicKey: signingKey.publicKey })).rejects.toThrow(
      TypeError,
    );
  });

  it("re-throws ReferenceError instead of swallowing it", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const corrupted = {
      ...signedVC,
      proof: new Proxy(signedVC.proof, {
        get(target, prop) {
          if (prop === "verificationMethod") {
            throw new ReferenceError("simulated ReferenceError");
          }
          return Reflect.get(target, prop);
        },
      }),
    } as VerifiableCredential;

    await expect(verifyProof(corrupted, { publicKey: signingKey.publicKey })).rejects.toThrow(
      ReferenceError,
    );
  });

  it("re-throws SyntaxError instead of swallowing it", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const corrupted = {
      ...signedVC,
      proof: new Proxy(signedVC.proof, {
        get(target, prop) {
          if (prop === "verificationMethod") {
            throw new SyntaxError("simulated SyntaxError");
          }
          return Reflect.get(target, prop);
        },
      }),
    } as VerifiableCredential;

    await expect(verifyProof(corrupted, { publicKey: signingKey.publicKey })).rejects.toThrow(
      SyntaxError,
    );
  });

  it("re-throws RangeError instead of swallowing it", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const corrupted = {
      ...signedVC,
      proof: new Proxy(signedVC.proof, {
        get(target, prop) {
          if (prop === "verificationMethod") {
            throw new RangeError("simulated RangeError");
          }
          return Reflect.get(target, prop);
        },
      }),
    } as VerifiableCredential;

    await expect(verifyProof(corrupted, { publicKey: signingKey.publicKey })).rejects.toThrow(
      RangeError,
    );
  });

  it("catches generic Error and returns { verified: false }", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");
    const signedVC = await signCredential(unsignedVC, signingKey, defaultProofOptions);

    const corrupted = {
      ...signedVC,
      proof: new Proxy(signedVC.proof, {
        get(target, prop) {
          if (prop === "verificationMethod") {
            throw new Error("simulated generic error");
          }
          return Reflect.get(target, prop);
        },
      }),
    } as VerifiableCredential;

    const result = await verifyProof(corrupted, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(false);
    expect(result.error).toContain("simulated generic error");
  });
});

describe("proof with domain and challenge", () => {
  it("should include domain and challenge in the proof", async () => {
    const unsignedVC = createTestCredential();
    const signingKey = createTestSigningKey("did:web:university.example#key-1");

    const signedVC = await signCredential(unsignedVC, signingKey, {
      ...defaultProofOptions,
      domain: "https://example.com",
      challenge: "abc123",
    });

    expect(signedVC.proof.domain).toBe("https://example.com");
    expect(signedVC.proof.challenge).toBe("abc123");

    const result = await verifyProof(signedVC, { publicKey: signingKey.publicKey });
    expect(result.verified).toBe(true);
  });
});
