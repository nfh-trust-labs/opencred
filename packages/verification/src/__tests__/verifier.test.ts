import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync, createHash, type KeyObject } from "node:crypto";
import * as jose from "jose";
import forge from "node-forge";
import { signCredential } from "@opencred/crypto";
import type { UnsignedCredential } from "@opencred/vc-core";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";
import type { DeDiClient } from "@opencred/dedi-client";
import { verifyCredential, detectFormat } from "../verifier.js";

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

function createDisclosure(salt: string, name: string, value: unknown): string {
  return Buffer.from(JSON.stringify([salt, name, value])).toString("base64url");
}

function computeDigest(disclosure: string): string {
  const hash = createHash("sha256").update(disclosure).digest();
  return Buffer.from(hash).toString("base64url");
}

async function createSdJwtVc(
  privateKey: KeyObject,
  payload: Record<string, unknown>,
  disclosures: string[],
  alg: string = "ES256",
): Promise<string> {
  const key = await jose.importPKCS8(
    privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    alg,
  );
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg, typ: "vc+sd-jwt" })
    .setIssuedAt()
    .sign(key);
  return jwt + "~" + disclosures.join("~") + "~";
}

describe("detectFormat", () => {
  it("should detect Data Integrity format", () => {
    expect(detectFormat({ proof: {} })).toBe("data-integrity");
  });

  it("should detect VC-JWT format (with vc claim in payload)", () => {
    // A proper VC-JWT has a `vc` claim in the payload
    const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({ iss: "did:example:issuer", vc: { type: ["VerifiableCredential"] } }),
    ).toString("base64url");
    expect(detectFormat(`${header}.${payload}.fakesig`)).toBe("vc-jwt");
  });

  it("should detect JWS format (full VC in payload)", () => {
    // A JWS wraps the full unsigned VC — has @context and credentialSubject directly
    const header = Buffer.from(JSON.stringify({ alg: "PS256", kid: "did:jwk:test#0" })).toString(
      "base64url",
    );
    const payload = Buffer.from(
      JSON.stringify({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        credentialSubject: { name: "Jane" },
      }),
    ).toString("base64url");
    expect(detectFormat(`${header}.${payload}.fakesig`)).toBe("jws");
  });

  it("should detect VC-JWT format via typ header fallback", () => {
    // When payload can't distinguish, falls back to header typ
    const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: "did:example:issuer" })).toString(
      "base64url",
    );
    expect(detectFormat(`${header}.${payload}.fakesig`)).toBe("vc-jwt");
  });

  it("should fall back to jws for non-decodable payloads", () => {
    expect(detectFormat("header.payload.signature")).toBe("jws");
  });

  it("should detect SD-JWT VC format", () => {
    expect(detectFormat("header.payload.sig~disclosure~")).toBe("sd-jwt-vc");
  });

  it("should throw for object without proof", () => {
    expect(() => detectFormat({ type: "VerifiableCredential" })).toThrow();
  });

  it("should throw for invalid string format", () => {
    expect(() => detectFormat("just-a-string")).toThrow();
  });
});

describe("verifyCredential — Data Integrity", () => {
  it("should return VALID for a correctly signed credential", async () => {
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
      },
    );

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: "did:web:university.example",
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: resolver,
    });

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
    expect(result.checks.some((c) => c.name === "signature" && c.passed)).toBe(true);
    expect(result.checks.some((c) => c.name === "date" && c.passed)).toBe(true);
  });

  it("should return EXPIRED for an expired credential", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const unsignedVC: UnsignedCredential = {
      ...createTestCredential(),
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2021-01-01T00:00:00Z",
    };
    const jwk = publicKey.export({ format: "jwk" });
    const verificationMethodId = "did:web:university.example#key-1";

    const signedVC = await signCredential(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "P-256" },
      {
        verificationMethod: verificationMethodId,
        proofPurpose: "assertionMethod",
      },
    );

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: "did:web:university.example",
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: resolver,
    });

    expect(result.code).toBe("EXPIRED");
    expect(result.verified).toBe(false);
  });

  it("should return INVALID for a tampered credential", async () => {
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
      },
    );

    const tampered = {
      ...signedVC,
      credentialSubject: { ...signedVC.credentialSubject, name: "Tampered" },
    };

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: "did:web:university.example",
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(tampered as unknown as Record<string, unknown>, {
      didResolver: resolver,
    });

    expect(result.code).toBe("INVALID");
    expect(result.verified).toBe(false);
  });

  it("should return UNRESOLVABLE when DID cannot be resolved", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const unsignedVC = createTestCredential();
    const verificationMethodId = "did:web:university.example#key-1";

    const signedVC = await signCredential(
      unsignedVC,
      { id: verificationMethodId, privateKey, publicKey, algorithm: "P-256" },
      {
        verificationMethod: verificationMethodId,
        proofPurpose: "assertionMethod",
      },
    );

    const resolver: DIDResolver = {
      resolve: async () => ({
        didDocument: null,
        didResolutionMetadata: { error: "notFound" },
        didDocumentMetadata: {},
      }),
    };

    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: resolver,
    });

    expect(result.code).toBe("UNRESOLVABLE");
    expect(result.verified).toBe(false);
  });

  it("should return REVOKED when DeDi reports revocation", async () => {
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
      },
    );

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: "did:web:university.example",
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const mockDediClient = {
      queryRevocationHash: vi.fn().mockResolvedValue({
        revoked: true,
        revokedAt: "2026-06-01T00:00:00Z",
      }),
    } as unknown as DeDiClient;

    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: resolver,
      dediClient: mockDediClient,
    });

    expect(result.code).toBe("REVOKED");
    expect(result.verified).toBe(false);
  });
});

describe("verifyCredential — VC-JWT", () => {
  it("should return VALID for a valid VC-JWT", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

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

    const result = await verifyCredential(jwt, { didResolver: resolver });

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
  });

  it("should return EXPIRED for an expired VC-JWT", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
      nbf: Math.floor(new Date("2020-01-01T00:00:00Z").getTime() / 1000),
      exp: Math.floor(new Date("2021-01-01T00:00:00Z").getTime() / 1000),
      vc: { type: ["VerifiableCredential"] },
    });

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(jwt, { didResolver: resolver });
    expect(result.verified).toBe(false);
    // Result-code consistency across proof formats: expired vc-jwt must
    // surface as EXPIRED (like data-integrity), not INVALID — jose's
    // exp-claim rejection happens after signature validation and must not
    // masquerade as a signature failure.
    expect(result.code).toBe("EXPIRED");
    expect(result.checks.some((c) => c.name === "signature" && c.passed)).toBe(true);
  });

  describe("JsonWebSignature2020 envelope (canonical vc-jwt issuance output)", () => {
    /**
     * Build the exact shape the Desktop Client and Docker image emit for
     * proofFormat "vc-jwt": the unsigned credential wrapped around its
     * compact token, with registered claims lifted out of the `vc` claim
     * exactly as `buildVcJwtClaims` does at signing time.
     */
    async function createEnvelopeCredential() {
      const { privateKey, publicKey } = generateTestKeyPair();
      const issuerDid = "did:web:university.example";
      const jwk = publicKey.export({ format: "jwk" });

      const unsigned = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: "urn:uuid:envelope-test-001",
        type: ["VerifiableCredential"],
        issuer: issuerDid,
        validFrom: "2026-01-01T00:00:00Z",
        credentialSubject: { id: "did:example:holder123", name: "Jane Doe" },
      };

      const vc: Record<string, unknown> = { ...unsigned };
      delete vc.issuer;
      delete vc.validFrom;
      vc.credentialSubject = { name: "Jane Doe" };

      const jwt = await createVcJwt(privateKey, {
        iss: issuerDid,
        sub: "did:example:holder123",
        jti: "urn:uuid:envelope-test-001",
        nbf: Math.floor(Date.parse("2026-01-01T00:00:00Z") / 1000),
        vc,
      });

      const envelope = { ...unsigned, proof: { type: "JsonWebSignature2020", jwt } };
      const resolver = createMockResolver(issuerDid, {
        id: `${issuerDid}#key-1`,
        type: "JsonWebKey",
        controller: issuerDid,
        publicKeyJwk: jwk as import("@opencred/did").JWK,
      });
      return { envelope, resolver };
    }

    it("verifies the canonical issuance envelope as VALID", async () => {
      const { envelope, resolver } = await createEnvelopeCredential();

      const result = await verifyCredential(envelope as unknown as Record<string, unknown>, {
        didResolver: resolver,
      });

      expect(result.code).toBe("VALID");
      expect(result.verified).toBe(true);
      expect(result.checks.some((c) => c.name === "envelope-consistency" && c.passed)).toBe(true);
      expect(result.checks.some((c) => c.name === "signature" && c.passed)).toBe(true);
    });

    it("rejects an envelope whose outer credentialSubject was swapped", async () => {
      const { envelope, resolver } = await createEnvelopeCredential();
      const tampered = {
        ...envelope,
        credentialSubject: { id: "did:example:holder123", name: "Mallory" },
      };

      const result = await verifyCredential(tampered as unknown as Record<string, unknown>, {
        didResolver: resolver,
      });

      expect(result.code).toBe("INVALID");
      expect(result.verified).toBe(false);
      const row = result.checks.find((c) => c.name === "envelope-consistency");
      expect(row?.passed).toBe(false);
      expect(row?.detail).toMatch(/does not match/);
    });

    it("rejects an envelope whose outer validFrom was altered", async () => {
      const { envelope, resolver } = await createEnvelopeCredential();
      const tampered = { ...envelope, validFrom: "2020-01-01T00:00:00Z" };

      const result = await verifyCredential(tampered as unknown as Record<string, unknown>, {
        didResolver: resolver,
      });

      expect(result.verified).toBe(false);
      expect(result.checks.find((c) => c.name === "envelope-consistency")?.passed).toBe(false);
    });

    it("returns a structured failure when proof.jwt is garbage", async () => {
      const { envelope, resolver } = await createEnvelopeCredential();
      const broken = { ...envelope, proof: { type: "JsonWebSignature2020", jwt: "garbage" } };

      const result = await verifyCredential(broken as unknown as Record<string, unknown>, {
        didResolver: resolver,
      });

      expect(result.verified).toBe(false);
      expect(result.checks[0]?.name).toBe("envelope-consistency");
      expect(result.checks[0]?.passed).toBe(false);
    });
  });

  it("surfaces a 'revocation NOT checked' row when credentialStatus is present but DeDi is not configured", async () => {
    // An issuer that commits to a revocation registry (credentialStatus)
    // must not have a revoked credential silently verify as VALID just
    // because this verifier lacks a DeDi client. The headline result stays
    // VALID (signature is sound), but the skip must be visible in checks.
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
      nbf: Math.floor(Date.now() / 1000) - 60,
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
        credentialSubject: { name: "Jane Doe" },
        credentialStatus: {
          id: "https://dedi.example.com/dedi/lookup/example.com/vc-revocation-registry/abc123",
          type: "RevocationList2020Status",
        },
      },
    });

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(jwt, { didResolver: resolver });

    expect(result.code).toBe("VALID");
    const revocationRow = result.checks.find((c) => c.name === "revocation");
    expect(revocationRow).toBeDefined();
    expect(revocationRow!.passed).toBe(true);
    expect(revocationRow!.detail).toMatch(/NOT checked/);
  });

  it("does NOT add a revocation row when neither credentialStatus nor DeDi is present", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
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

    const result = await verifyCredential(jwt, { didResolver: resolver });

    expect(result.code).toBe("VALID");
    expect(result.checks.find((c) => c.name === "revocation")).toBeUndefined();
  });

  it("returns INVALID when jti does not match vc.id (VC-JOSE-COSE §3.3.1)", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
      jti: "urn:uuid:aaaa-aaaa",
      nbf: Math.floor(Date.now() / 1000) - 60,
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: "urn:uuid:bbbb-bbbb", // mismatched
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

    const result = await verifyCredential(jwt, { didResolver: resolver });
    expect(result.code).toBe("INVALID");
    expect(result.verified).toBe(false);
    const crossCheck = result.checks.find((c) => c.name === "vc-jwt-claims");
    expect(crossCheck?.passed).toBe(false);
    expect(crossCheck?.detail).toMatch(/jti/i);
  });

  it("returns INVALID when sub does not match vc.credentialSubject.id (VC-JOSE-COSE §3.3.2)", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
      sub: "did:example:holder-A",
      nbf: Math.floor(Date.now() / 1000) - 60,
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential"],
        credentialSubject: { id: "did:example:holder-B", name: "Jane Doe" }, // mismatched
      },
    });

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(jwt, { didResolver: resolver });
    expect(result.code).toBe("INVALID");
    expect(result.verified).toBe(false);
    const crossCheck = result.checks.find((c) => c.name === "vc-jwt-claims");
    expect(crossCheck?.passed).toBe(false);
    expect(crossCheck?.detail).toMatch(/sub/i);
  });

  it("passes the vc-jwt-claims check when jti/sub match vc.id / credentialSubject.id", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const jwt = await createVcJwt(privateKey, {
      iss: issuerDid,
      jti: "urn:uuid:matching-id",
      sub: "did:example:holder",
      nbf: Math.floor(Date.now() / 1000) - 60,
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: "urn:uuid:matching-id",
        type: ["VerifiableCredential"],
        credentialSubject: { id: "did:example:holder", name: "Jane Doe" },
      },
    });

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(jwt, { didResolver: resolver });
    expect(result.code).toBe("VALID");
    const crossCheck = result.checks.find((c) => c.name === "vc-jwt-claims");
    expect(crossCheck?.passed).toBe(true);
  });
});

describe("verifyCredential — SD-JWT VC", () => {
  it("should return VALID for a valid SD-JWT VC", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const d1 = createDisclosure("salt1", "given_name", "Jane");
    const digest1 = computeDigest(d1);

    const sdJwtVc = await createSdJwtVc(
      privateKey,
      {
        iss: issuerDid,
        vct: "VerifiableCredential",
        nbf: Math.floor(Date.now() / 1000) - 60,
        _sd: [digest1],
        _sd_alg: "sha-256",
      },
      [d1],
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(sdJwtVc, { didResolver: resolver });

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
  });

  it("should return INVALID for wrong key", async () => {
    const { privateKey } = generateTestKeyPair();
    const { publicKey: wrongPublicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = wrongPublicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVc(
      privateKey,
      {
        iss: issuerDid,
        vct: "VerifiableCredential",
      },
      [],
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(sdJwtVc, { didResolver: resolver });

    expect(result.code).toBe("INVALID");
    expect(result.verified).toBe(false);
  });
});
// Regression test for nfh-trust-labs/opencred#316: a Data Integrity credential
// carrying an x5c chain MUST NOT verify as VALID when no trust anchor is
// configured. This is the verifier-level wiring test — the X.509 chain check
// itself is exercised in `x509-chain-check.test.ts`.
describe("verifyCredential — X.509 chain check wiring (#316)", () => {
  /** Generate a self-signed cert and return its DER body as base64 (x5c form). */
  function makeSelfSignedDerBase64(): string {
    const k = forge.pki.rsa.generateKeyPair(2048);
    const c = forge.pki.createCertificate();
    c.publicKey = k.publicKey;
    c.serialNumber = "01";
    c.validity.notBefore = new Date(Date.now() - 1000 * 60);
    c.validity.notAfter = new Date(Date.now() + 1000 * 60 * 60 * 24);
    c.setSubject([{ shortName: "CN", value: "Wiring Test" }]);
    c.setIssuer([{ shortName: "CN", value: "Wiring Test" }]);
    // node-forge's @types declares extensions as `any[]`; use a loose record
    // type to keep the test compiling under strict TS.
    const extensions: Array<Record<string, unknown>> = [
      { name: "basicConstraints", cA: false },
      { name: "keyUsage", digitalSignature: true },
    ];
    c.setExtensions(extensions);
    c.sign(k.privateKey, forge.md.sha256.create());
    const pem = forge.pki.certificateToPem(c);
    return pem
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s+/g, "");
  }

  it("returns INVALID when an x5c chain is present and no trustAnchors are configured", async () => {
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
      },
    );

    // Inject a self-signed x5c chain into the proof. The wiring test only
    // needs to confirm the verifier passes trustAnchors through and treats a
    // failing chain check as INVALID.
    const proof = signedVC.proof as Record<string, unknown>;
    proof["x5c"] = [makeSelfSignedDerBase64()];

    const resolver = createMockResolver("did:web:university.example", {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: "did:web:university.example",
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: resolver,
      // trustAnchors deliberately omitted.
    });

    expect(result.code).toBe("INVALID");
    expect(result.verified).toBe(false);
    // The wiring test only needs to confirm the verifier ran the X.509 chain
    // check and that the check failed (so a credential carrying x5c cannot
    // sneak past as VALID). The detailed failure case-by-case is exercised in
    // x509-chain-check.test.ts.
    const x509Check = result.checks.find((c) => c.name === "x509-chain");
    expect(x509Check).toBeDefined();
    expect(x509Check?.passed).toBe(false);
  });
});
