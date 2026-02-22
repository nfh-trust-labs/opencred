import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject, createHash } from "node:crypto";
import * as jose from "jose";
import type { DIDResolver, DIDResolutionResult, DIDDocument, VerificationMethod } from "@opencred/did";
import {
  parseSdJwtVc,
  decodeDisclosure,
  processDisclosures,
  verifySdJwtVc,
  extractSdJwtVcCredentialFields,
} from "../sd-jwt-vc.js";

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

describe("parseSdJwtVc", () => {
  it("should parse an SD-JWT VC with disclosures", () => {
    const components = parseSdJwtVc("header.payload.sig~d1~d2~");
    expect(components.issuerJwt).toBe("header.payload.sig");
    expect(components.disclosures).toEqual(["d1", "d2"]);
    expect(components.keyBindingJwt).toBeUndefined();
  });

  it("should parse an SD-JWT VC with no disclosures", () => {
    const components = parseSdJwtVc("header.payload.sig~");
    expect(components.issuerJwt).toBe("header.payload.sig");
    expect(components.disclosures).toEqual([]);
  });

  it("should parse an SD-JWT VC with key binding JWT", () => {
    const components = parseSdJwtVc("header.payload.sig~d1~d2~kb.header.sig");
    expect(components.issuerJwt).toBe("header.payload.sig");
    expect(components.disclosures).toEqual(["d1", "d2"]);
    expect(components.keyBindingJwt).toBe("kb.header.sig");
  });

  it("should throw for invalid format", () => {
    expect(() => parseSdJwtVc("just-a-jwt")).toThrow("Invalid SD-JWT VC format");
  });
});

describe("decodeDisclosure", () => {
  it("should decode a valid disclosure", () => {
    const disclosure = createDisclosure("salt123", "given_name", "John");
    const decoded = decodeDisclosure(disclosure);
    expect(decoded[0]).toBe("salt123");
    expect(decoded[1]).toBe("given_name");
    expect(decoded[2]).toBe("John");
  });

  it("should decode a disclosure with complex value", () => {
    const disclosure = createDisclosure("salt456", "address", { street: "123 Main" });
    const decoded = decodeDisclosure(disclosure);
    expect(decoded[1]).toBe("address");
    expect(decoded[2]).toEqual({ street: "123 Main" });
  });

  it("should throw for invalid disclosure", () => {
    const invalid = Buffer.from(JSON.stringify(["only", "two"])).toString("base64url");
    expect(() => decodeDisclosure(invalid)).toThrow("Invalid disclosure format");
  });
});

describe("processDisclosures", () => {
  it("should reconstruct claims from disclosures", async () => {
    const d1 = createDisclosure("salt1", "given_name", "John");
    const d2 = createDisclosure("salt2", "family_name", "Doe");
    const digest1 = computeDigest(d1);
    const digest2 = computeDigest(d2);

    const payload = {
      iss: "did:web:example",
      _sd: [digest1, digest2],
      _sd_alg: "sha-256",
    };

    const result = await processDisclosures(payload, [d1, d2]);
    expect(result["given_name"]).toBe("John");
    expect(result["family_name"]).toBe("Doe");
    expect(result["_sd"]).toBeUndefined();
    expect(result["_sd_alg"]).toBeUndefined();
  });

  it("should handle payload with no _sd field", async () => {
    const payload = { iss: "did:web:example", vct: "VerifiableCredential" };
    const result = await processDisclosures(payload, []);
    expect(result["iss"]).toBe("did:web:example");
    expect(result["vct"]).toBe("VerifiableCredential");
  });
});

describe("verifySdJwtVc", () => {
  it("should verify a valid SD-JWT VC", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = publicKey.export({ format: "jwk" });

    const d1 = createDisclosure("salt1", "given_name", "Jane");
    const digest1 = computeDigest(d1);

    const sdJwtVc = await createSdJwtVc(privateKey, {
      iss: issuerDid,
      vct: "VerifiableCredential",
      nbf: Math.floor(Date.now() / 1000) - 60,
      _sd: [digest1],
      _sd_alg: "sha-256",
    }, [d1]);

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check, payload, resolvedClaims } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(true);
    expect(payload?.iss).toBe(issuerDid);
    expect(resolvedClaims?.["given_name"]).toBe("Jane");
  });

  it("should fail when no resolver is provided", async () => {
    const { privateKey } = generateTestKeyPair();
    const sdJwtVc = await createSdJwtVc(privateKey, {
      iss: "did:web:example",
      vct: "VerifiableCredential",
    }, []);

    const { check } = await verifySdJwtVc(sdJwtVc);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("Unable to resolve");
  });

  it("should fail when signed with a different key", async () => {
    const { privateKey } = generateTestKeyPair();
    const { publicKey: wrongPublicKey } = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = wrongPublicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVc(privateKey, {
      iss: issuerDid,
      vct: "VerifiableCredential",
    }, []);

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(false);
  });
});

describe("extractSdJwtVcCredentialFields", () => {
  it("should extract dates from nbf/exp", () => {
    const nbf = Math.floor(new Date("2026-01-01T00:00:00Z").getTime() / 1000);
    const exp = Math.floor(new Date("2027-01-01T00:00:00Z").getTime() / 1000);

    const result = extractSdJwtVcCredentialFields(
      { iss: "did:web:example", nbf, exp },
      { iss: "did:web:example" },
    );

    expect(result.validFrom).toBe("2026-01-01T00:00:00.000Z");
    expect(result.validUntil).toBe("2027-01-01T00:00:00.000Z");
    expect(result.issuer).toBe("did:web:example");
  });

  it("should extract credentialStatus from resolved claims", () => {
    const result = extractSdJwtVcCredentialFields(
      { iss: "did:web:example" },
      {
        credentialStatus: {
          type: "BitstringStatusListEntry",
          statusListIndex: "5",
        },
      },
    );

    expect(result.credentialStatus).toBeDefined();
    expect(result.credentialStatus?.["type"]).toBe("BitstringStatusListEntry");
  });
});
