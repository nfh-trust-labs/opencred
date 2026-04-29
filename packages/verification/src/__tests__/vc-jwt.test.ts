import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";
import {
  verifyVcJwt,
  extractVcJwtCredentialFields,
  crossValidateVcJwtClaims,
  decodeJwtPayloadUnsafe,
  type VcJwtPayload,
} from "../vc-jwt.js";

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
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

async function createVcJwt(
  privateKey: KeyObject,
  payload: Record<string, unknown>,
  alg: string = "ES256",
): Promise<string> {
  const key = await jose.importPKCS8(
    privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    alg,
  );
  return new jose.SignJWT(payload).setProtectedHeader({ alg, typ: "JWT" }).setIssuedAt().sign(key);
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

  it("should reject JWT with disallowed algorithm (algorithm confusion)", async () => {
    const { publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    // Create a JWT signed with ES256 but forge the header to claim HS256
    // by crafting a raw token with an unsupported alg.
    // Instead, we test that `none` algorithm is rejected.
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        iss: issuerDid,
        vc: { type: ["VerifiableCredential"] },
      }),
    ).toString("base64url");
    const forgedJwt = `${header}.${payload}.`;

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check } = await verifyVcJwt(forgedJwt, resolver);
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

  it("should extract fields from DM 2.0 payload (no vc wrapper)", () => {
    // DM 2.0 puts VC fields (type, credentialSubject, validFrom, etc.) directly on
    // the JWT payload rather than nesting them under `vc`. VcJwtPayload models the
    // shared JWT claims, so we widen via `unknown` to attach the extra VC fields.
    const result = extractVcJwtCredentialFields({
      iss: "did:web:example",
      sub: "did:example:holder456",
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      credentialSubject: { name: "Jane Doe", degree: "Computer Science" },
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
      credentialStatus: {
        type: "BitstringStatusListEntry",
        statusListIndex: "10",
        statusListCredential: "https://example.com/status/2",
      },
    } as unknown as VcJwtPayload);

    expect(result.validFrom).toBe("2026-01-01T00:00:00Z");
    expect(result.validUntil).toBe("2027-01-01T00:00:00Z");
    expect(result.credentialStatus).toBeDefined();
    expect(result.credentialStatus?.["type"]).toBe("BitstringStatusListEntry");
    expect(result.issuer).toBe("did:web:example");
    expect(result.credential).toBeDefined();
    const credentialSubject = (result.credential as Record<string, unknown> | undefined)?.[
      "credentialSubject"
    ] as Record<string, unknown> | undefined;
    expect(credentialSubject?.["name"]).toBe("Jane Doe");
  });

  it("should prefer nbf/exp over DM 2.0 validFrom/validUntil", () => {
    const nbf = Math.floor(new Date("2026-06-01T00:00:00Z").getTime() / 1000);
    const exp = Math.floor(new Date("2027-06-01T00:00:00Z").getTime() / 1000);

    // DM 2.0 validFrom/validUntil fields live alongside the standard JWT claims,
    // which VcJwtPayload does not model; widen via `unknown` to attach them.
    const result = extractVcJwtCredentialFields({
      iss: "did:web:example",
      nbf,
      exp,
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
    } as unknown as VcJwtPayload);

    // nbf/exp should take precedence
    expect(result.validFrom).toBe("2026-06-01T00:00:00.000Z");
    expect(result.validUntil).toBe("2027-06-01T00:00:00.000Z");
  });
});

describe("crossValidateVcJwtClaims (#156)", () => {
  it("should return no errors when jti matches vc.id", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      jti: "urn:uuid:12345",
      vc: {
        id: "urn:uuid:12345",
        type: ["VerifiableCredential"],
        credentialSubject: { name: "Jane" },
      },
    });
    expect(errors).toHaveLength(0);
  });

  it("should return error when jti does not match vc.id", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      jti: "urn:uuid:12345",
      vc: {
        id: "urn:uuid:67890",
        type: ["VerifiableCredential"],
        credentialSubject: { name: "Jane" },
      },
    });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("jti");
    expect(errors[0]).toContain("vc.id");
  });

  it("should return no errors when sub matches vc.credentialSubject.id", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      sub: "did:example:holder456",
      vc: {
        type: ["VerifiableCredential"],
        credentialSubject: { id: "did:example:holder456", name: "Jane" },
      },
    });
    expect(errors).toHaveLength(0);
  });

  it("should return error when sub does not match vc.credentialSubject.id", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      sub: "did:example:holder456",
      vc: {
        type: ["VerifiableCredential"],
        credentialSubject: { id: "did:example:different", name: "Jane" },
      },
    });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("sub");
    expect(errors[0]).toContain("credentialSubject.id");
  });

  it("should return both errors when both jti and sub mismatch", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      jti: "urn:uuid:12345",
      sub: "did:example:holder456",
      vc: {
        id: "urn:uuid:67890",
        type: ["VerifiableCredential"],
        credentialSubject: { id: "did:example:different", name: "Jane" },
      },
    });
    expect(errors).toHaveLength(2);
  });

  it("should skip validation when jti is absent", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      vc: {
        id: "urn:uuid:67890",
        type: ["VerifiableCredential"],
        credentialSubject: { name: "Jane" },
      },
    });
    expect(errors).toHaveLength(0);
  });

  it("should skip validation when vc.id is absent", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      jti: "urn:uuid:12345",
      vc: {
        type: ["VerifiableCredential"],
        credentialSubject: { name: "Jane" },
      },
    });
    expect(errors).toHaveLength(0);
  });

  it("should skip validation when sub is absent", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      vc: {
        type: ["VerifiableCredential"],
        credentialSubject: { id: "did:example:holder456", name: "Jane" },
      },
    });
    expect(errors).toHaveLength(0);
  });

  it("should skip validation for DM 2.0 payloads (no vc wrapper)", () => {
    const errors = crossValidateVcJwtClaims({
      iss: "did:web:example",
      jti: "urn:uuid:12345",
      sub: "did:example:holder",
    });
    expect(errors).toHaveLength(0);
  });
});

describe("decodeJwtPayloadUnsafe", () => {
  // This helper is the load-bearing primitive that lets workspace
  // packages decode JWT payloads without taking a direct `jose`
  // dependency. The `-Unsafe` suffix is load-bearing too: the function
  // intentionally skips signature verification, so its only safe
  // callers are offline rendering paths that preserve the original
  // token elsewhere (e.g. embedded in a QR for verifier-side checking).
  // Keep these tests pinned to the contract.

  function buildJwt(headerObj: object, payloadObj: object): string {
    // Produce a 3-segment "JWT" with a fake signature segment. We never
    // verify the signature in these tests — only payload decode.
    const header = Buffer.from(JSON.stringify(headerObj)).toString("base64url");
    const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
    return `${header}.${payload}.fakesig`;
  }

  it("returns the parsed payload for a well-formed JWT", () => {
    const jwt = buildJwt({ alg: "ES256" }, { iss: "did:web:example", iat: 1700000000 });
    const result = decodeJwtPayloadUnsafe(jwt);
    expect(result).toEqual({ iss: "did:web:example", iat: 1700000000 });
  });

  it("preserves nested objects and arrays in the payload", () => {
    const jwt = buildJwt(
      { alg: "ES256" },
      {
        iss: "did:web:example",
        vc: {
          credentialSubject: { name: "Alice", roles: ["doctor", "trainer"] },
        },
      },
    );
    const result = decodeJwtPayloadUnsafe(jwt) as Record<string, unknown> & {
      vc: { credentialSubject: { name: string; roles: string[] } };
    };
    expect(result.vc.credentialSubject.name).toBe("Alice");
    expect(result.vc.credentialSubject.roles).toEqual(["doctor", "trainer"]);
  });

  it("throws on empty input", () => {
    // jose.decodeJwt rejects empty strings before we even hit assertJwtSize;
    // the contract is "throws Error", not a specific subclass.
    expect(() => decodeJwtPayloadUnsafe("")).toThrow();
  });

  it("throws on a single-segment input (no dots)", () => {
    expect(() => decodeJwtPayloadUnsafe("not-a-jwt")).toThrow();
  });

  it("throws on a two-segment input (one dot — header.payload only)", () => {
    expect(() => decodeJwtPayloadUnsafe("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0")).toThrow();
  });

  it("throws on oversized input via assertJwtSize", () => {
    // MAX_JWT_BYTES is 1 MiB; a JWT > that should be rejected before
    // jose ever sees it. Build a payload large enough to overflow.
    const bigPayload = { iss: "did:web:example", junk: "x".repeat(2 * 1024 * 1024) };
    const oversized = buildJwt({ alg: "ES256" }, bigPayload);
    expect(() => decodeJwtPayloadUnsafe(oversized)).toThrow();
  });

  it("throws on a non-JSON payload segment", () => {
    // header.<not-json>.signature — base64url decodes but JSON.parse fails
    const headerSeg = Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url");
    const garbageSeg = Buffer.from("not valid json").toString("base64url");
    const malformed = `${headerSeg}.${garbageSeg}.fakesig`;
    expect(() => decodeJwtPayloadUnsafe(malformed)).toThrow();
  });
});
