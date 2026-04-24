import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject, createHash } from "node:crypto";
import * as jose from "jose";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";
import {
  parseSdJwtVc,
  decodeDisclosure,
  processDisclosures,
  verifySdJwtVc,
  extractSdJwtVcCredentialFields,
} from "../sd-jwt-vc.js";
import type { SdJwtVcVerifyOptions } from "../sd-jwt-vc.js";

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

function createDisclosure(salt: string, name: string, value: unknown): string {
  return Buffer.from(JSON.stringify([salt, name, value])).toString("base64url");
}

function computeDigest(disclosure: string): string {
  const hash = createHash("sha256").update(disclosure).digest();
  return Buffer.from(hash).toString("base64url");
}

async function createSdJwtVc(
  issuerKeyPair: { privateKey: KeyObject; publicKey: KeyObject },
  payload: Record<string, unknown>,
  disclosures: string[],
  alg: string = "ES256",
): Promise<string> {
  const key = await jose.importPKCS8(
    issuerKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    alg,
  );
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg, typ: "vc+sd-jwt" })
    .setIssuedAt()
    .sign(key);
  return jwt + "~" + disclosures.join("~") + "~";
}

/**
 * Create an SD-JWT VC with a Key Binding JWT for testing.
 * The issuer payload includes a cnf claim with the holder's public key.
 * The KB-JWT is signed by the holder and includes sd_hash.
 */
async function createSdJwtVcWithKeyBinding(
  issuerKeyPair: { privateKey: KeyObject; publicKey: KeyObject },
  holderKeyPair: { privateKey: KeyObject; publicKey: KeyObject },
  payload: Record<string, unknown>,
  disclosures: string[],
  kbClaims: Record<string, unknown> = {},
  alg: string = "ES256",
): Promise<string> {
  const holderJwk = holderKeyPair.publicKey.export({ format: "jwk" });
  const issuerKey = await jose.importPKCS8(
    issuerKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    alg,
  );

  const payloadWithCnf = { ...payload, cnf: { jwk: holderJwk } };
  const issuerJwt = await new jose.SignJWT(payloadWithCnf)
    .setProtectedHeader({ alg, typ: "vc+sd-jwt" })
    .setIssuedAt()
    .sign(issuerKey);

  const sdJwtWithoutKb = issuerJwt + "~" + disclosures.join("~") + "~";

  const sdHash = createHash("sha256").update(sdJwtWithoutKb, "ascii").digest();
  const sdHashB64 = Buffer.from(sdHash).toString("base64url");

  const holderKey = await jose.importPKCS8(
    holderKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    alg,
  );
  const kbJwt = await new jose.SignJWT({ ...kbClaims, sd_hash: sdHashB64 })
    .setProtectedHeader({ alg, typ: "kb+jwt" })
    .setIssuedAt()
    .sign(holderKey);

  return sdJwtWithoutKb + kbJwt;
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

  it("decodes a 2-tuple as an array-element disclosure (§4.2.5)", () => {
    const disclosure = Buffer.from(JSON.stringify(["salt", "a-value"])).toString("base64url");
    const decoded = decodeDisclosure(disclosure);
    expect(decoded.length).toBe(2);
    expect(decoded[0]).toBe("salt");
    expect(decoded[1]).toBe("a-value");
  });

  it("should throw for a 1-tuple (neither object nor array disclosure)", () => {
    const invalid = Buffer.from(JSON.stringify(["one-element"])).toString("base64url");
    expect(() => decodeDisclosure(invalid)).toThrow("Invalid disclosure format");
  });

  it("should throw for a 4-tuple", () => {
    const invalid = Buffer.from(JSON.stringify(["a", "b", "c", "d"])).toString("base64url");
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

  it("recursively resolves nested _sd digests (§4.2.4)", async () => {
    // Nested object: address.{street, locality}. Both disclosed via _sd.
    const streetDisc = createDisclosure("s1", "street", "221B Baker St");
    const localityDisc = createDisclosure("s2", "locality", "London");
    const addressDisc = createDisclosure("s3", "address", {
      _sd: [computeDigest(streetDisc), computeDigest(localityDisc)],
    });

    const payload = {
      iss: "did:web:example",
      _sd: [computeDigest(addressDisc)],
      _sd_alg: "sha-256",
    };

    const result = await processDisclosures(payload, [addressDisc, streetDisc, localityDisc]);
    expect(result["address"]).toBeDefined();
    const addr = result["address"] as Record<string, unknown>;
    expect(addr["street"]).toBe("221B Baker St");
    expect(addr["locality"]).toBe("London");
    // _sd must be stripped at EVERY level.
    expect(addr["_sd"]).toBeUndefined();
    expect(result["_sd"]).toBeUndefined();
  });

  it("resolves array-element disclosures (§4.2.5)", async () => {
    // Array disclosure is a 2-tuple [salt, value] — not [salt, name, value].
    const nickDisc = Buffer.from(JSON.stringify(["salt-a", "Sherlock"])).toString("base64url");
    const nickDigest = computeDigest(nickDisc);

    const payload = {
      iss: "did:web:example",
      nicknames: [{ "...": nickDigest }, "Holmes"],
      _sd_alg: "sha-256",
    };

    const result = await processDisclosures(payload, [nickDisc]);
    expect(result["nicknames"]).toEqual(["Sherlock", "Holmes"]);
  });

  it("rejects supplied disclosures that no digest references (§7.1)", async () => {
    const usedDisc = createDisclosure("s1", "given_name", "John");
    const smuggledDisc = createDisclosure("s2", "ssn", "123-45-6789");

    const payload = {
      iss: "did:web:example",
      _sd: [computeDigest(usedDisc)],
      _sd_alg: "sha-256",
    };

    await expect(processDisclosures(payload, [usedDisc, smuggledDisc])).rejects.toThrow(
      /not referenced by any _sd digest/,
    );
  });

  it("leaves unmatched digests as decoys (does not fail verification)", async () => {
    const realDisc = createDisclosure("s1", "given_name", "John");
    const payload = {
      iss: "did:web:example",
      _sd: [computeDigest(realDisc), "fakehashnotreferencedbyanydisclosure"],
      _sd_alg: "sha-256",
    };

    const result = await processDisclosures(payload, [realDisc]);
    expect(result["given_name"]).toBe("John");
  });
});

describe("verifySdJwtVc", () => {
  it("should verify a valid SD-JWT VC", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const d1 = createDisclosure("salt1", "given_name", "Jane");
    const digest1 = computeDigest(d1);

    const sdJwtVc = await createSdJwtVc(
      issuerKeyPair,
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

    const { check, payload, resolvedClaims } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(true);
    expect(payload?.iss).toBe(issuerDid);
    expect(resolvedClaims?.["given_name"]).toBe("Jane");
  });

  it("should fail when no resolver is provided", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const sdJwtVc = await createSdJwtVc(
      issuerKeyPair,
      {
        iss: "did:web:example",
        vct: "VerifiableCredential",
      },
      [],
    );

    const { check } = await verifySdJwtVc(sdJwtVc);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("Unable to resolve");
  });

  it("should fail when signed with a different key", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const wrongKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = wrongKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVc(
      issuerKeyPair,
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

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(false);
  });
});

describe("verifySdJwtVc — vct claim validation (#130)", () => {
  it("should fail when vct claim is missing", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    // Create SD-JWT VC without vct claim
    const sdJwtVc = await createSdJwtVc(issuerKeyPair, { iss: issuerDid }, []);

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("vct");
    expect(check.detail).toContain("missing required 'vct' claim");
  });

  it("should fail when vct does not match expectedVct", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVc(
      issuerKeyPair,
      { iss: issuerDid, vct: "UniversityDegreeCredential" },
      [],
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const options: SdJwtVcVerifyOptions = { expectedVct: "DriverLicenseCredential" };
    const { check } = await verifySdJwtVc(sdJwtVc, resolver, options);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("vct");
    expect(check.detail).toContain("does not match expected type");
  });

  it("should pass when vct matches expectedVct", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVc(
      issuerKeyPair,
      { iss: issuerDid, vct: "UniversityDegreeCredential" },
      [],
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const options: SdJwtVcVerifyOptions = { expectedVct: "UniversityDegreeCredential" };
    const { check } = await verifySdJwtVc(sdJwtVc, resolver, options);
    expect(check.passed).toBe(true);
  });

  it("should pass when vct matches one of multiple expectedVct values", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVc(
      issuerKeyPair,
      { iss: issuerDid, vct: "DriverLicenseCredential" },
      [],
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const options: SdJwtVcVerifyOptions = {
      expectedVct: ["UniversityDegreeCredential", "DriverLicenseCredential"],
    };
    const { check } = await verifySdJwtVc(sdJwtVc, resolver, options);
    expect(check.passed).toBe(true);
  });

  it("should pass when vct is present and no expectedVct is specified", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVc(
      issuerKeyPair,
      { iss: issuerDid, vct: "VerifiableCredential" },
      [],
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(true);
  });
});

describe("verifySdJwtVc — Key Binding JWT verification (#129)", () => {
  it("should verify a valid SD-JWT VC with Key Binding JWT", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVcWithKeyBinding(
      issuerKeyPair,
      holderKeyPair,
      {
        iss: issuerDid,
        vct: "VerifiableCredential",
        _sd_alg: "sha-256",
      },
      [],
      { aud: "https://verifier.example", nonce: "abc123" },
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(true);
  });

  it("should fail when KB-JWT is signed with wrong key", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const wrongKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const issuerJwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    // Build the issuer JWT with the holder's public key in cnf, but sign
    // the KB-JWT with the wrong key
    const holderJwk = holderKeyPair.publicKey.export({ format: "jwk" });
    const issuerKey = await jose.importPKCS8(
      issuerKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );

    const issuerJwt = await new jose.SignJWT({
      iss: issuerDid,
      vct: "VerifiableCredential",
      cnf: { jwk: holderJwk },
    })
      .setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt" })
      .setIssuedAt()
      .sign(issuerKey);

    const sdJwtWithoutKb = issuerJwt + "~";
    const sdHash = createHash("sha256").update(sdJwtWithoutKb, "ascii").digest();
    const sdHashB64 = Buffer.from(sdHash).toString("base64url");

    // Sign with the wrong key (not the holder's key)
    const wrongKey = await jose.importPKCS8(
      wrongKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );
    const kbJwt = await new jose.SignJWT({ sd_hash: sdHashB64, aud: "https://verifier.example" })
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .setIssuedAt()
      .sign(wrongKey);

    const sdJwtVc = sdJwtWithoutKb + kbJwt;

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: issuerJwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("key_binding");
    expect(check.detail).toContain("Key Binding JWT verification failed");
  });

  it("should fail when issuer payload is missing cnf claim", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const issuerJwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    // Create issuer JWT without cnf claim
    const issuerKey = await jose.importPKCS8(
      issuerKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );
    const issuerJwt = await new jose.SignJWT({
      iss: issuerDid,
      vct: "VerifiableCredential",
      // No cnf claim
    })
      .setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt" })
      .setIssuedAt()
      .sign(issuerKey);

    const sdJwtWithoutKb = issuerJwt + "~";

    // Create a KB-JWT (it doesn't matter what key signs it, since cnf is missing)
    const holderKey = await jose.importPKCS8(
      holderKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );
    const kbJwt = await new jose.SignJWT({ sd_hash: "dummy", aud: "https://verifier.example" })
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .setIssuedAt()
      .sign(holderKey);

    const sdJwtVc = sdJwtWithoutKb + kbJwt;

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: issuerJwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("key_binding");
    expect(check.detail).toContain("missing 'cnf' claim");
  });

  it("should fail when KB-JWT has wrong typ header", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const issuerJwk = issuerKeyPair.publicKey.export({ format: "jwk" });
    const holderJwk = holderKeyPair.publicKey.export({ format: "jwk" });

    const issuerKey = await jose.importPKCS8(
      issuerKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );
    const issuerJwt = await new jose.SignJWT({
      iss: issuerDid,
      vct: "VerifiableCredential",
      cnf: { jwk: holderJwk },
    })
      .setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt" })
      .setIssuedAt()
      .sign(issuerKey);

    const sdJwtWithoutKb = issuerJwt + "~";

    const holderKey = await jose.importPKCS8(
      holderKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );
    // Sign KB-JWT with wrong typ header
    const kbJwt = await new jose.SignJWT({ sd_hash: "dummy" })
      .setProtectedHeader({ alg: "ES256", typ: "JWT" })
      .setIssuedAt()
      .sign(holderKey);

    const sdJwtVc = sdJwtWithoutKb + kbJwt;

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: issuerJwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("key_binding");
    expect(check.detail).toContain("typ");
    expect(check.detail).toContain("kb+jwt");
  });

  it("should fail when sd_hash does not match", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const issuerJwk = issuerKeyPair.publicKey.export({ format: "jwk" });
    const holderJwk = holderKeyPair.publicKey.export({ format: "jwk" });

    const issuerKey = await jose.importPKCS8(
      issuerKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );
    const issuerJwt = await new jose.SignJWT({
      iss: issuerDid,
      vct: "VerifiableCredential",
      cnf: { jwk: holderJwk },
    })
      .setProtectedHeader({ alg: "ES256", typ: "vc+sd-jwt" })
      .setIssuedAt()
      .sign(issuerKey);

    const sdJwtWithoutKb = issuerJwt + "~";

    const holderKey = await jose.importPKCS8(
      holderKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      "ES256",
    );
    // Create KB-JWT with a wrong sd_hash
    const kbJwt = await new jose.SignJWT({ sd_hash: "wrong-hash-value" })
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .setIssuedAt()
      .sign(holderKey);

    const sdJwtVc = sdJwtWithoutKb + kbJwt;

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: issuerJwk as import("@opencred/did").JWK,
    });

    const { check } = await verifySdJwtVc(sdJwtVc, resolver);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("key_binding");
    expect(check.detail).toContain("sd_hash");
  });

  it("should verify KB-JWT with expected audience", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVcWithKeyBinding(
      issuerKeyPair,
      holderKeyPair,
      { iss: issuerDid, vct: "VerifiableCredential", _sd_alg: "sha-256" },
      [],
      { aud: "https://verifier.example", nonce: "test-nonce" },
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const options: SdJwtVcVerifyOptions = { expectedAudience: "https://verifier.example" };
    const { check } = await verifySdJwtVc(sdJwtVc, resolver, options);
    expect(check.passed).toBe(true);
  });

  it("should fail when KB-JWT audience does not match expected", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVcWithKeyBinding(
      issuerKeyPair,
      holderKeyPair,
      { iss: issuerDid, vct: "VerifiableCredential", _sd_alg: "sha-256" },
      [],
      { aud: "https://verifier.example", nonce: "test-nonce" },
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const options: SdJwtVcVerifyOptions = {
      expectedAudience: "https://different-verifier.example",
    };
    const { check } = await verifySdJwtVc(sdJwtVc, resolver, options);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("key_binding");
    expect(check.detail).toContain("aud");
  });

  it("should fail when KB-JWT nonce does not match expected", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVcWithKeyBinding(
      issuerKeyPair,
      holderKeyPair,
      { iss: issuerDid, vct: "VerifiableCredential", _sd_alg: "sha-256" },
      [],
      { aud: "https://verifier.example", nonce: "original-nonce" },
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const options: SdJwtVcVerifyOptions = { expectedNonce: "different-nonce" };
    const { check } = await verifySdJwtVc(sdJwtVc, resolver, options);
    expect(check.passed).toBe(false);
    expect(check.name).toBe("key_binding");
    expect(check.detail).toContain("nonce");
  });

  it("should verify KB-JWT with both expected audience and nonce", async () => {
    const issuerKeyPair = generateTestKeyPair();
    const holderKeyPair = generateTestKeyPair();
    const issuerDid = "did:web:university.example";
    const jwk = issuerKeyPair.publicKey.export({ format: "jwk" });

    const sdJwtVc = await createSdJwtVcWithKeyBinding(
      issuerKeyPair,
      holderKeyPair,
      { iss: issuerDid, vct: "VerifiableCredential", _sd_alg: "sha-256" },
      [],
      { aud: "https://verifier.example", nonce: "test-nonce-123" },
    );

    const resolver = createMockResolver(issuerDid, {
      id: `${issuerDid}#key-1`,
      type: "JsonWebKey",
      controller: issuerDid,
      publicKeyJwk: jwk as import("@opencred/did").JWK,
    });

    const options: SdJwtVcVerifyOptions = {
      expectedAudience: "https://verifier.example",
      expectedNonce: "test-nonce-123",
    };
    const { check } = await verifySdJwtVc(sdJwtVc, resolver, options);
    expect(check.passed).toBe(true);
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
