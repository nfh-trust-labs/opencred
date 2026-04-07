import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { signCredential, signCredentialEdDsa, multibaseEncode } from "@opencred/crypto";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";
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

function createMockResolver(did: string, verificationMethod: VerificationMethod): DIDResolver {
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

  it("should verify a valid EdDSA (eddsa-rdfc-2022) credential with a JWK resolver", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const unsignedVC = createTestCredential();
    const jwk = publicKey.export({ format: "jwk" });

    const verificationMethodId = "did:web:university.example#key-ed25519";
    const signedVC = await signCredentialEdDsa(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "Ed25519" },
      {
        verificationMethod: verificationMethodId,
        proofPurpose: "assertionMethod",
        created: "2026-01-01T00:00:00Z",
      },
    );

    expect(signedVC.proof.cryptosuite).toBe("eddsa-rdfc-2022");

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

  it("should verify an EdDSA credential with a multibase key resolver", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const unsignedVC = createTestCredential();
    const jwk = publicKey.export({ format: "jwk" });

    // Build multibase-encoded Ed25519 public key
    const rawKey = Buffer.from(jwk.x!, "base64url");
    const multicodec = Buffer.alloc(2 + 32);
    multicodec[0] = 0xed;
    multicodec[1] = 0x01;
    rawKey.copy(multicodec, 2);
    const multibaseKey = multibaseEncode(multicodec);

    const verificationMethodId = "did:web:university.example#key-ed25519";
    const signedVC = await signCredentialEdDsa(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "Ed25519" },
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

  // Regression tests for nfh-trust-labs/opencred#311 — the JWK-fragment
  // fallback in data-integrity.ts allowed any DID method whose document did
  // not contain a verification method matching the credential's
  // `verificationMethod` to fall back to base64url-decoding the URL fragment
  // and trusting it as the signing key. The fix removes the fallback; the
  // verification key MUST come from the resolved DID document.
  describe("#311 — JWK-fragment bypass", () => {
    it("should NOT trust an attacker-controlled JWK encoded in the verificationMethod fragment", async () => {
      // The attacker forges a credential whose verificationMethod is the
      // legitimate did:web:victim.example#<base64url(JSON(jwk(P_attacker)))>
      // and signs with their own key. The legitimate issuer (P_legit) is
      // published in the DID document under id `did:web:victim.example#key-0`.
      // Verification MUST fail because the attacker-controlled fragment is
      // not in the resolved DID document.
      const { privateKey: attackerPriv, publicKey: attackerPub } = generateTestKeyPair();
      const { publicKey: legitPub } = generateTestKeyPair();
      const legitJwk = legitPub.export({ format: "jwk" });

      const attackerJwk = attackerPub.export({ format: "jwk" });
      const attackerJwkPublicOnly = {
        kty: attackerJwk.kty,
        crv: attackerJwk.crv,
        x: attackerJwk.x,
        y: attackerJwk.y,
      };
      const attackerFragment = Buffer.from(JSON.stringify(attackerJwkPublicOnly)).toString(
        "base64url",
      );

      const did = "did:web:victim.example";
      const forgedVmId = `${did}#${attackerFragment}`;

      const unsignedVC: UnsignedCredential = {
        ...createTestCredential(),
        issuer: did,
      };

      // Sign with the attacker's private key while claiming the verification
      // method is the legitimate-DID URL plus the attacker's JWK fragment.
      const signedVC = await signCredential(
        unsignedVC,
        { id: forgedVmId, privateKey: attackerPriv, publicKey: attackerPub, algorithm: "P-256" },
        {
          verificationMethod: forgedVmId,
          proofPurpose: "assertionMethod",
          created: "2026-01-01T00:00:00Z",
        },
      );

      // The DID document published by victim.example contains a single VM
      // bound to the LEGITIMATE issuer key, not the attacker's key.
      const legitVmId = `${did}#key-0`;
      const resolver = createMockResolver(did, {
        id: legitVmId,
        type: "JsonWebKey",
        controller: did,
        publicKeyJwk: legitJwk as import("@opencred/did").JWK,
      });

      const result = await verifyDataIntegrity(signedVC, resolver);
      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Unable to resolve");
    });

    it("should NOT trust a JWK fragment when the DID document is empty", async () => {
      // Even if the DID document has no verification methods at all, the
      // JWK fragment must not be honoured.
      const { privateKey: attackerPriv, publicKey: attackerPub } = generateTestKeyPair();
      const attackerJwk = attackerPub.export({ format: "jwk" });
      const attackerJwkPublicOnly = {
        kty: attackerJwk.kty,
        crv: attackerJwk.crv,
        x: attackerJwk.x,
        y: attackerJwk.y,
      };
      const attackerFragment = Buffer.from(JSON.stringify(attackerJwkPublicOnly)).toString(
        "base64url",
      );

      const did = "did:web:empty.example";
      const forgedVmId = `${did}#${attackerFragment}`;

      const unsignedVC: UnsignedCredential = {
        ...createTestCredential(),
        issuer: did,
      };
      const signedVC = await signCredential(
        unsignedVC,
        { id: forgedVmId, privateKey: attackerPriv, publicKey: attackerPub, algorithm: "P-256" },
        {
          verificationMethod: forgedVmId,
          proofPurpose: "assertionMethod",
          created: "2026-01-01T00:00:00Z",
        },
      );

      const emptyResolver: DIDResolver = {
        resolve: async (): Promise<DIDResolutionResult> => ({
          didDocument: {
            "@context": "https://www.w3.org/ns/did/v1",
            id: did,
            verificationMethod: [],
          } as DIDDocument,
          didResolutionMetadata: {},
          didDocumentMetadata: {},
        }),
      };

      const result = await verifyDataIntegrity(signedVC, emptyResolver);
      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Unable to resolve");
    });

    it("should NOT trust a did:key resolver fall-through with mismatched fragment", async () => {
      // Previously the fallback also "borrowed" the single VM from a
      // single-key did:key document when the fragment did not match. The
      // attacker can exploit this by claiming a did:key DID and presenting a
      // forged fragment — the fall-through would happily accept it. The fix
      // removes the fall-through entirely.
      const { privateKey: attackerPriv, publicKey: attackerPub } = generateTestKeyPair();
      const { publicKey: legitPub } = generateTestKeyPair();

      const did = "did:key:zSomeRealMultibaseValue";
      const legitVmId = `${did}#zSomeRealMultibaseValue`;
      const forgedVmId = `${did}#zUnrelatedFragment`;

      const unsignedVC: UnsignedCredential = {
        ...createTestCredential(),
        issuer: did,
      };

      const signedVC = await signCredential(
        unsignedVC,
        { id: forgedVmId, privateKey: attackerPriv, publicKey: attackerPub, algorithm: "P-256" },
        {
          verificationMethod: forgedVmId,
          proofPurpose: "assertionMethod",
          created: "2026-01-01T00:00:00Z",
        },
      );

      const legitJwk = legitPub.export({ format: "jwk" });
      const resolver = createMockResolver(did, {
        id: legitVmId,
        type: "JsonWebKey",
        controller: did,
        publicKeyJwk: legitJwk as import("@opencred/did").JWK,
      });

      const result = await verifyDataIntegrity(signedVC, resolver);
      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Unable to resolve");
    });

    it("should still accept a relative-fragment (#fragment) verification method id", async () => {
      // Some DID documents publish verification methods with relative ids
      // (e.g. `#key-0` instead of `did:web:example#key-0`). The strict lookup
      // in the fix accepts a bare fragment match too, so this case must
      // continue to verify successfully.
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
        // Note: relative id, no DID prefix.
        id: "#key-1",
        type: "JsonWebKey",
        controller: "did:web:university.example",
        publicKeyJwk: jwk as import("@opencred/did").JWK,
      });

      const result = await verifyDataIntegrity(signedVC, resolver);
      expect(result.passed).toBe(true);
    });
  });

  it("should fail for a tampered EdDSA credential", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const unsignedVC = createTestCredential();
    const jwk = publicKey.export({ format: "jwk" });

    const verificationMethodId = "did:web:university.example#key-ed25519";
    const signedVC = await signCredentialEdDsa(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "Ed25519" },
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
});
