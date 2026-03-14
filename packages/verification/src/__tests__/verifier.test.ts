import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync, createHash, type KeyObject } from "node:crypto";
import * as jose from "jose";
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
    const payload = Buffer.from(JSON.stringify({ iss: "did:example:issuer", vc: { type: ["VerifiableCredential"] } })).toString("base64url");
    expect(detectFormat(`${header}.${payload}.fakesig`)).toBe("vc-jwt");
  });

  it("should detect JWS format (full VC in payload)", () => {
    // A JWS wraps the full unsigned VC — has @context and credentialSubject directly
    const header = Buffer.from(JSON.stringify({ alg: "PS256", kid: "did:jwk:test#0" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ "@context": ["https://www.w3.org/ns/credentials/v2"], credentialSubject: { name: "Jane" } })).toString("base64url");
    expect(detectFormat(`${header}.${payload}.fakesig`)).toBe("jws");
  });

  it("should detect VC-JWT format via typ header fallback", () => {
    // When payload can't distinguish, falls back to header typ
    const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: "did:example:issuer" })).toString("base64url");
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
        created: "2026-01-01T00:00:00Z",
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
        created: "2020-01-01T00:00:00Z",
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
        created: "2026-01-01T00:00:00Z",
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
        created: "2026-01-01T00:00:00Z",
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
        created: "2026-01-01T00:00:00Z",
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
        hash: "abc",
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

describe("verifyCredential — Attestation Chain Integration", () => {
  it("should return ATTESTATION_INVALID when attestation is expired at proof time", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const opencredKeyPair = generateTestKeyPair();

    const issuerDid = "did:web:university.example";
    const issuerVmId = `${issuerDid}#key-1`;
    const opencredDid = "did:key:z6MkOpenCred";
    const opencredVmId = `${opencredDid}#z6MkOpenCred`;

    // Create an attestation that expired before the credential was signed
    const unsignedAttestation = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:attestation-expired",
      type: ["VerifiableCredential", "KeyAttestationCredential"],
      issuer: opencredDid,
      validFrom: "2024-01-01T00:00:00Z",
      validUntil: "2025-06-01T00:00:00Z", // Expired before credential proof.created
      credentialSubject: {
        id: issuerDid,
        verificationMethodId: issuerVmId,
      },
    } as UnsignedCredential;

    const signedAttestation = await signCredential(
      unsignedAttestation,
      { id: opencredVmId, privateKey: opencredKeyPair.privateKey, publicKey: opencredKeyPair.publicKey, algorithm: "P-256" },
      { verificationMethod: opencredVmId, proofPurpose: "assertionMethod", created: "2024-01-01T00:00:00Z" },
    );

    // Create and sign a credential with the expired attestation
    const unsignedVC = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:test-credential-attested",
      type: ["VerifiableCredential"],
      issuer: issuerDid,
      validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { id: "did:example:holder", name: "Jane Doe" },
    } as UnsignedCredential;

    const signedVC = await signCredential(
      unsignedVC,
      { id: issuerVmId, privateKey: issuerKeyPair.privateKey, publicKey: issuerKeyPair.publicKey, algorithm: "P-256" },
      { verificationMethod: issuerVmId, proofPurpose: "assertionMethod", created: "2026-06-01T00:00:00Z" },
    );

    // Embed the attestation in the proof
    const vcObj = signedVC as unknown as Record<string, unknown>;
    const proof = vcObj["proof"] as Record<string, unknown>;
    proof["keyAttestationCredential"] = signedAttestation;

    const issuerJwk = issuerKeyPair.publicKey.export({ format: "jwk" });
    const resolver = createMockResolver(issuerDid, {
      id: issuerVmId,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: issuerJwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(vcObj, {
      didResolver: resolver,
      opencredPublicKey: opencredKeyPair.publicKey,
    });

    expect(result.code).toBe("ATTESTATION_INVALID");
    expect(result.verified).toBe(false);
    expect(result.checks.some((c) => c.name === "attestation" && !c.passed)).toBe(true);
  });

  it("should return VALID for a correctly attested credential", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const opencredKeyPair = generateTestKeyPair();

    const issuerDid = "did:web:university.example";
    const issuerVmId = `${issuerDid}#key-1`;
    const opencredDid = "did:key:z6MkOpenCred";
    const opencredVmId = `${opencredDid}#z6MkOpenCred`;

    // Create a valid attestation
    const unsignedAttestation = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:attestation-valid",
      type: ["VerifiableCredential", "KeyAttestationCredential"],
      issuer: opencredDid,
      validFrom: "2025-01-01T00:00:00Z",
      validUntil: "2027-12-31T00:00:00Z",
      credentialSubject: {
        id: issuerDid,
        verificationMethodId: issuerVmId,
      },
    } as UnsignedCredential;

    const signedAttestation = await signCredential(
      unsignedAttestation,
      { id: opencredVmId, privateKey: opencredKeyPair.privateKey, publicKey: opencredKeyPair.publicKey, algorithm: "P-256" },
      { verificationMethod: opencredVmId, proofPurpose: "assertionMethod", created: "2025-01-01T00:00:00Z" },
    );

    // Create and sign a credential
    const unsignedVC = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:test-credential-valid-attested",
      type: ["VerifiableCredential"],
      issuer: issuerDid,
      validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { id: "did:example:holder", name: "Jane Doe" },
    } as UnsignedCredential;

    const signedVC = await signCredential(
      unsignedVC,
      { id: issuerVmId, privateKey: issuerKeyPair.privateKey, publicKey: issuerKeyPair.publicKey, algorithm: "P-256" },
      { verificationMethod: issuerVmId, proofPurpose: "assertionMethod", created: "2026-06-01T00:00:00Z" },
    );

    // Embed the attestation in the proof
    const vcObj = signedVC as unknown as Record<string, unknown>;
    const proof = vcObj["proof"] as Record<string, unknown>;
    proof["keyAttestationCredential"] = signedAttestation;

    const issuerJwk = issuerKeyPair.publicKey.export({ format: "jwk" });
    const resolver = createMockResolver(issuerDid, {
      id: issuerVmId,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: issuerJwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(vcObj, {
      didResolver: resolver,
      opencredPublicKey: opencredKeyPair.publicKey,
    });

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
    expect(result.checks.some((c) => c.name === "attestation" && c.passed)).toBe(true);
  });

  it("should return ATTESTATION_INVALID when attestation was signed by wrong key", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const opencredKeyPair = generateTestKeyPair();
    const wrongKeyPair = generateTestKeyPair();

    const issuerDid = "did:web:university.example";
    const issuerVmId = `${issuerDid}#key-1`;
    const opencredDid = "did:key:z6MkOpenCred";
    const opencredVmId = `${opencredDid}#z6MkOpenCred`;

    // Sign attestation with wrong key
    const unsignedAttestation = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:attestation-wrong-key",
      type: ["VerifiableCredential", "KeyAttestationCredential"],
      issuer: opencredDid,
      validFrom: "2025-01-01T00:00:00Z",
      validUntil: "2027-12-31T00:00:00Z",
      credentialSubject: {
        id: issuerDid,
        verificationMethodId: issuerVmId,
      },
    } as UnsignedCredential;

    const signedAttestation = await signCredential(
      unsignedAttestation,
      { id: opencredVmId, privateKey: wrongKeyPair.privateKey, publicKey: wrongKeyPair.publicKey, algorithm: "P-256" },
      { verificationMethod: opencredVmId, proofPurpose: "assertionMethod", created: "2025-01-01T00:00:00Z" },
    );

    const unsignedVC = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:test-credential-wrong-attestation-key",
      type: ["VerifiableCredential"],
      issuer: issuerDid,
      validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { id: "did:example:holder", name: "Jane Doe" },
    } as UnsignedCredential;

    const signedVC = await signCredential(
      unsignedVC,
      { id: issuerVmId, privateKey: issuerKeyPair.privateKey, publicKey: issuerKeyPair.publicKey, algorithm: "P-256" },
      { verificationMethod: issuerVmId, proofPurpose: "assertionMethod", created: "2026-06-01T00:00:00Z" },
    );

    const vcObj = signedVC as unknown as Record<string, unknown>;
    const proof = vcObj["proof"] as Record<string, unknown>;
    proof["keyAttestationCredential"] = signedAttestation;

    const issuerJwk = issuerKeyPair.publicKey.export({ format: "jwk" });
    const resolver = createMockResolver(issuerDid, {
      id: issuerVmId,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: issuerJwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(vcObj, {
      didResolver: resolver,
      opencredPublicKey: opencredKeyPair.publicKey, // Expects opencredKeyPair, but attestation was signed by wrongKeyPair
    });

    expect(result.code).toBe("ATTESTATION_INVALID");
    expect(result.verified).toBe(false);
  });

  it("should return VALID for non-attested credential (no regression)", async () => {
    // Non-attested credential should go through normal verification
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const vmId = `${issuerDid}#key-1`;

    const unsignedVC = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:test-credential-no-attestation",
      type: ["VerifiableCredential"],
      issuer: issuerDid,
      validFrom: "2026-01-01T00:00:00Z",
      credentialSubject: { id: "did:example:holder", name: "Jane Doe" },
    } as UnsignedCredential;

    const signedVC = await signCredential(
      unsignedVC,
      { id: vmId, privateKey, publicKey, algorithm: "P-256" },
      { verificationMethod: vmId, proofPurpose: "assertionMethod", created: "2026-01-01T00:00:00Z" },
    );

    const jwk = publicKey.export({ format: "jwk" });
    const resolver = createMockResolver(issuerDid, {
      id: vmId,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: resolver,
    });

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
    // Attestation check should be skipped (passed with detail)
    const attestationCheck = result.checks.find((c) => c.name === "attestation");
    expect(attestationCheck?.passed).toBe(true);
    expect(attestationCheck?.detail).toContain("No attestation reference");
  });
});
