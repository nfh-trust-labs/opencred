import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type { DIDResolver, DIDResolutionResult, DIDDocument, VerificationMethod } from "@opencred/did";
import { verifyVcJwt, extractVcJwtCredentialFields } from "../vc-jwt.js";

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
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

async function createVcJwt(
  privateKey: KeyObject,
  payload: Record<string, unknown>,
  alg: string = "ES256",
): Promise<string> {
  const key = await jose.importPKCS8(
    privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    alg,
  );
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg, typ: "JWT" })
    .setIssuedAt()
    .sign(key);
}

describe("verifyVcJwt", () => {
  it("should verify a valid VC-JWT with JWK resolver", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const jwk = publicKey.export({ format: "jwk" });
    const issuerDid = "did:web:university.example";

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
      sub: "did:example:holder123",
      nbf: Math.floor(Date.now() / 1000) - 60,
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
        credentialSubject: { name: "Jane Doe" },
      },
    });

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check, payload } = await verifyVcJwt(jwt, resolver);
    expect(check.passed).toBe(true);
    expect(check.name).toBe("signature");
    expect(payload?.iss).toBe(issuerDid);
    expect(payload?.vc).toBeDefined();
  });

  it("should fail when no resolver is provided", async () => {
    const { privateKey } = generateTestKeyPair();
    const jwt = await createVcJwt(privateKey, {
      iss: "did:web:university.example",
      vc: { type: ["VerifiableCredential"] },
    });

    const { check } = await verifyVcJwt(jwt);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("Unable to resolve");
  });

  it("should fail when JWT is missing iss claim", async () => {
    const { privateKey } = generateTestKeyPair();
    const jwt = await createVcJwt(privateKey, {
      sub: "did:example:holder123",
      vc: { type: ["VerifiableCredential"] },
    });

    const { check, payload } = await verifyVcJwt(jwt);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("missing 'iss'");
    expect(payload).toBeNull();
  });

  it("should fail when JWT is signed with a different key", async () => {
    const { privateKey } = generateTestKeyPair();
    const { publicKey: wrongPublicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
      vc: { type: ["VerifiableCredential"] },
    });

    const jwk = wrongPublicKey.export({ format: "jwk" });
    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check } = await verifyVcJwt(jwt, resolver);
    expect(check.passed).toBe(false);
  });

  it("should fail for malformed JWT string", async () => {
    const { check } = await verifyVcJwt("not.a.valid-jwt");
    expect(check.passed).toBe(false);
  });
});

describe("extractVcJwtCredentialFields", () => {
  it("should extract dates from nbf/exp claims", () => {
    const nbf = Math.floor(new Date("2026-01-01T00:00:00Z").getTime() / 1000);
    const exp = Math.floor(new Date("2027-01-01T00:00:00Z").getTime() / 1000);

    const result = extractVcJwtCredentialFields({
      iss: "did:web:example",
      nbf,
      exp,
      vc: { type: ["VerifiableCredential"] },
    });

    expect(result.validFrom).toBe("2026-01-01T00:00:00.000Z");
    expect(result.validUntil).toBe("2027-01-01T00:00:00.000Z");
    expect(result.issuer).toBe("did:web:example");
  });

  it("should extract dates from vc.validFrom/validUntil when nbf/exp not present", () => {
    const result = extractVcJwtCredentialFields({
      iss: "did:web:example",
      vc: {
        type: ["VerifiableCredential"],
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2027-01-01T00:00:00Z",
      },
    });

    expect(result.validFrom).toBe("2026-01-01T00:00:00Z");
    expect(result.validUntil).toBe("2027-01-01T00:00:00Z");
  });

  it("should extract credentialStatus from vc claim", () => {
    const result = extractVcJwtCredentialFields({
      iss: "did:web:example",
      vc: {
        type: ["VerifiableCredential"],
        credentialStatus: {
          type: "BitstringStatusListEntry",
          statusListIndex: "42",
          statusListCredential: "https://example.com/status/1",
        },
      },
    });

    expect(result.credentialStatus).toBeDefined();
    expect(result.credentialStatus?.["type"]).toBe("BitstringStatusListEntry");
  });
});
