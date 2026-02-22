import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { signCredential, multibaseEncode } from "@opencred/crypto";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import type { DIDResolver, DIDResolutionResult, DIDDocument, VerificationMethod } from "@opencred/did";
import { verifyDataIntegrity } from "../data-integrity.js";

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
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

function createMockResolver(
  did: string,
  verificationMethod: VerificationMethod,
): DIDResolver {
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
          verificationMethod: [verificationMethod],
          assertionMethod: [verificationMethod.id],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

describe("verifyDataIntegrity", () => {
  it("should verify a valid Data Integrity credential with a JWK-based resolver", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const unsignedVC = createTestCredential();
    const jwk = publicKey.export({ format: "jwk" });

    const verificationMethodId = "did:web:university.example#key-1";
    const signedVC = await signCredential(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "P-256" },
      {
        verificationMethod: verificationMethodId,
        proofPurpose: "assertionMethod",
        created: "2026-01-01T00:00:00Z",
      },
    );

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: "did:web:university.example",
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyDataIntegrity(signedVC, resolver);
    expect(result.passed).toBe(true);
    expect(result.name).toBe("signature");
  });

  it("should verify a valid credential with a multibase key resolver", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const unsignedVC = createTestCredential();
    const jwk = publicKey.export({ format: "jwk" });

    // Build the multibase-encoded public key
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
    const compressedPoint = Buffer.alloc(33);
    compressedPoint[0] = prefix;
    x.copy(compressedPoint, 1);
    const multicodec = Buffer.alloc(2 + 33);
    multicodec[0] = 0x80;
    multicodec[1] = 0x24;
    compressedPoint.copy(multicodec, 2);
    const multibaseKey = multibaseEncode(multicodec);

    const verificationMethodId = "did:web:university.example#key-1";
    const signedVC = await signCredential(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "P-256" },
      {
        verificationMethod: verificationMethodId,
        proofPurpose: "assertionMethod",
        created: "2026-01-01T00:00:00Z",
      },
    );

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "Multikey",
      controller: "did:web:university.example",
      publicKeyMultibase: multibaseKey,
    });

    const result = await verifyDataIntegrity(signedVC, resolver);
    expect(result.passed).toBe(true);
  });

  it("should fail when no resolver is provided", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const unsignedVC = createTestCredential();

    const signedVC = await signCredential(
      unsignedVC,
      {
        id: "did:web:university.example#key-1",
        privateKey,
        publicKey,
        algorithm: "P-256",
      },
      {
        verificationMethod: "did:web:university.example#key-1",
        proofPurpose: "assertionMethod",
        created: "2026-01-01T00:00:00Z",
      },
    );

    const result = await verifyDataIntegrity(signedVC);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Unable to resolve");
  });

  it("should fail for a tampered credential", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const unsignedVC = createTestCredential();
    const jwk = publicKey.export({ format: "jwk" });

    const verificationMethodId = "did:web:university.example#key-1";
    const signedVC = await signCredential(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "P-256" },
      {
        verificationMethod: verificationMethodId,
        proofPurpose: "assertionMethod",
        created: "2026-01-01T00:00:00Z",
      },
    );

    const tampered: VerifiableCredential = {
      ...signedVC,
      credentialSubject: { ...signedVC.credentialSubject, name: "Evil Eve" },
    };

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: "did:web:university.example",
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyDataIntegrity(tampered, resolver);
    expect(result.passed).toBe(false);
  });

  it("should fail for unsupported proof type", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const unsignedVC = createTestCredential();
    const signedVC = await signCredential(
      unsignedVC,
      {
        id: "did:web:university.example#key-1",
        privateKey,
        publicKey,
        algorithm: "P-256",
      },
      {
        verificationMethod: "did:web:university.example#key-1",
        proofPurpose: "assertionMethod",
        created: "2026-01-01T00:00:00Z",
      },
    );

    const modified: VerifiableCredential = {
      ...signedVC,
      proof: { ...signedVC.proof, type: "Ed25519Signature2020" },
    };

    const result = await verifyDataIntegrity(modified);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("Unsupported proof type");
  });

  it("should fail when no proof is present", async () => {
    const vc = createTestCredential() as unknown as VerifiableCredential;
    // @ts-expect-error — deliberately testing missing proof
    delete vc.proof;

    const result = await verifyDataIntegrity(vc);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("No proof found");
  });
});
