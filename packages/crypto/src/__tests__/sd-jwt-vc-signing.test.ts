import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createHash, sign as cryptoSign, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type { UnsignedCredential } from "@opencred/vc-core";
import {
  signCredentialSdJwtVc,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
} from "../sd-jwt-vc-signing.js";
import { signingAlgorithmToJwsAlg } from "../alg-mapping.js";
import type { SigningKey, SdJwtVcSigningOptions } from "../types.js";

function generateEcP256KeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

function generateEcP384KeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-384" });
}

function generateRsaKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
}

function createP256SigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateEcP256KeyPair();
  return { id, privateKey, publicKey, algorithm: "P-256" };
}

function createP384SigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateEcP384KeyPair();
  return { id, privateKey, publicKey, algorithm: "P-384" };
}

function createRsaSigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateRsaKeyPair();
  return { id, privateKey, publicKey, algorithm: "RSA-2048" };
}

const unsignedVC: UnsignedCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:test-sd-jwt-credential",
  type: ["VerifiableCredential"],
  issuer: "did:example:issuer123",
  validFrom: "2024-01-01T00:00:00Z",
  validUntil: "2030-12-31T23:59:59Z",
  credentialSubject: {
    id: "did:example:subject456",
    name: "Alice",
    email: "alice@example.com",
    degree: "Computer Science",
  },
};

const verificationMethod = "did:key:zTest#zTest";

const baseOptions: SdJwtVcSigningOptions = {
  selectiveDisclosureClaims: ["name", "email"],
  vct: "EducationalCredential",
  verificationMethod,
  created: "2024-06-01T00:00:00Z",
};

/**
 * Parse an SD-JWT VC string into its components.
 */
function parseSdJwtVc(sdJwtVc: string): {
  issuerJwt: string;
  disclosures: string[];
} {
  const parts = sdJwtVc.split("~");
  const issuerJwt = parts[0];
  const disclosures = parts.slice(1).filter((p) => p !== "");
  return { issuerJwt, disclosures };
}

/**
 * Decode a disclosure from base64url to [salt, name, value].
 */
function decodeDisclosure(disclosure: string): [string, string, unknown] {
  const json = Buffer.from(disclosure, "base64url").toString("utf-8");
  return JSON.parse(json) as [string, string, unknown];
}

/**
 * Compute the SHA-256 digest of a disclosure (base64url string → SHA-256 → base64url).
 */
function computeDigest(disclosureB64: string): string {
  const hash = createHash("sha256").update(disclosureB64, "ascii").digest();
  return Buffer.from(hash).toString("base64url");
}

describe("signingAlgorithmToJwsAlg", () => {
  it("should map P-256 to ES256", () => {
    expect(signingAlgorithmToJwsAlg("P-256")).toBe("ES256");
  });

  it("should map P-384 to ES384", () => {
    expect(signingAlgorithmToJwsAlg("P-384")).toBe("ES384");
  });

  it("should map RSA variants to PS256", () => {
    expect(signingAlgorithmToJwsAlg("RSA-2048")).toBe("PS256");
    expect(signingAlgorithmToJwsAlg("RSA-3072")).toBe("PS256");
    expect(signingAlgorithmToJwsAlg("RSA-4096")).toBe("PS256");
  });

  it("should throw for unsupported algorithms", () => {
    expect(() => signingAlgorithmToJwsAlg("INVALID" as never)).toThrow("Unsupported algorithm");
  });
});

describe("signCredentialSdJwtVc", () => {
  it("should produce a valid SD-JWT VC string with EC P-256", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    expect(typeof result).toBe("string");
    // Must end with ~
    expect(result.endsWith("~")).toBe(true);

    const { issuerJwt, disclosures } = parseSdJwtVc(result);

    // Issuer JWT must have 3 dot-separated parts
    const jwtParts = issuerJwt.split(".");
    expect(jwtParts.length).toBe(3);
    for (const part of jwtParts) {
      expect(part.length).toBeGreaterThan(0);
    }

    // Must have 2 disclosures (name and email)
    expect(disclosures.length).toBe(2);
  });

  it("should set typ to vc+sd-jwt and alg to ES256 in the header", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const header = jose.decodeProtectedHeader(issuerJwt);
    expect(header.typ).toBe("vc+sd-jwt");
    expect(header.alg).toBe("ES256");
    expect(header.kid).toBe(verificationMethod);
  });

  it("should set vct in the JWT payload", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const payload = jose.decodeJwt(issuerJwt);
    expect(payload.vct).toBe("EducationalCredential");
  });

  it("should set iss, sub, iat, nbf, exp in the JWT payload", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const payload = jose.decodeJwt(issuerJwt);

    expect(payload.iss).toBe("did:example:issuer123");
    expect(payload.sub).toBe("did:example:subject456");
    expect(typeof payload.iat).toBe("number");
    expect(typeof payload.nbf).toBe("number");
    expect(typeof payload.exp).toBe("number");
  });

  it("should include non-SD claims directly in the payload", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const payload = jose.decodeJwt(issuerJwt) as Record<string, unknown>;

    // 'degree' is not in selectiveDisclosureClaims, so it should be in the payload directly
    expect(payload.degree).toBe("Computer Science");

    // 'name' and 'email' should NOT be in the payload (they are SD claims)
    expect(payload.name).toBeUndefined();
    expect(payload.email).toBeUndefined();
  });

  it("should produce valid disclosures with [salt, name, value] format", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { disclosures } = parseSdJwtVc(result);

    const disclosedNames = new Set<string>();
    for (const d of disclosures) {
      const decoded = decodeDisclosure(d);
      expect(Array.isArray(decoded)).toBe(true);
      expect(decoded.length).toBe(3);

      const [salt, name, value] = decoded;

      // Salt should be a base64url string of 16 bytes (CSPRNG)
      const saltBytes = Buffer.from(salt, "base64url");
      expect(saltBytes.length).toBe(16);

      expect(typeof name).toBe("string");
      disclosedNames.add(name);

      // Value should match the original credential subject
      if (name === "name") expect(value).toBe("Alice");
      if (name === "email") expect(value).toBe("alice@example.com");
    }

    expect(disclosedNames.has("name")).toBe(true);
    expect(disclosedNames.has("email")).toBe(true);
  });

  it("should include _sd digests that match disclosures", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt, disclosures } = parseSdJwtVc(result);
    const payload = jose.decodeJwt(issuerJwt) as Record<string, unknown>;

    const sdDigests = payload._sd as string[];
    expect(Array.isArray(sdDigests)).toBe(true);
    expect(sdDigests.length).toBe(disclosures.length);

    // Each disclosure's digest must appear in _sd
    for (const d of disclosures) {
      const digest = computeDigest(d);
      expect(sdDigests).toContain(digest);
    }
  });

  it("should set _sd_alg to sha-256", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const payload = jose.decodeJwt(issuerJwt) as Record<string, unknown>;
    expect(payload._sd_alg).toBe("sha-256");
  });

  it("should include cnf with holder public key JWK when provided", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const holderKey = generateEcP256KeyPair();
    const holderJwk = holderKey.publicKey.export({ format: "jwk" });

    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, {
      ...baseOptions,
      holderPublicKeyJwk: holderJwk as Record<string, unknown>,
    });

    const { issuerJwt } = parseSdJwtVc(result);
    const payload = jose.decodeJwt(issuerJwt) as Record<string, unknown>;

    const cnf = payload.cnf as { jwk: Record<string, unknown> };
    expect(cnf).toBeDefined();
    expect(cnf.jwk).toBeDefined();
    expect(cnf.jwk.kty).toBe("EC");
    expect(cnf.jwk.crv).toBe("P-256");
  });

  it("should verify the JWT signature with the issuer's public key", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);

    // Signature verification should succeed
    const { payload } = await jose.jwtVerify(issuerJwt, signingKey.publicKey, {
      algorithms: ["ES256"],
    });
    expect(payload.iss).toBe("did:example:issuer123");
  });

  it("should work with P-384 keys (ES384)", async () => {
    const signingKey = createP384SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const header = jose.decodeProtectedHeader(issuerJwt);
    expect(header.alg).toBe("ES384");

    // Signature should verify
    const { payload } = await jose.jwtVerify(issuerJwt, signingKey.publicKey, {
      algorithms: ["ES384"],
    });
    expect(payload.vct).toBe("EducationalCredential");
  });

  it("should work with RSA keys (PS256)", async () => {
    const signingKey = createRsaSigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const header = jose.decodeProtectedHeader(issuerJwt);
    expect(header.alg).toBe("PS256");

    const { payload } = await jose.jwtVerify(issuerJwt, signingKey.publicKey, {
      algorithms: ["PS256"],
    });
    expect(payload.vct).toBe("EducationalCredential");
  });

  it("should handle zero selective disclosure claims", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, {
      ...baseOptions,
      selectiveDisclosureClaims: [],
    });

    const { issuerJwt, disclosures } = parseSdJwtVc(result);
    expect(disclosures.length).toBe(0);

    // All claims should be directly in the payload
    const payload = jose.decodeJwt(issuerJwt) as Record<string, unknown>;
    expect(payload.name).toBe("Alice");
    expect(payload.email).toBe("alice@example.com");
    expect(payload._sd).toBeUndefined();
  });

  it("should handle issuer as an object with id", async () => {
    const vcWithIssuerObject: UnsignedCredential = {
      ...unsignedVC,
      issuer: { id: "did:example:issuer-object", name: "Test Issuer" },
    };

    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(vcWithIssuerObject, signingKey, baseOptions);

    const { issuerJwt } = parseSdJwtVc(result);
    const payload = jose.decodeJwt(issuerJwt);
    expect(payload.iss).toBe("did:example:issuer-object");
  });
});

describe("prepareSdJwtVcProof", () => {
  it("should return signingInput with header.payload format", () => {
    const prepared = prepareSdJwtVcProof(unsignedVC, "P-256", baseOptions);

    expect(typeof prepared.signingInput).toBe("string");
    const parts = prepared.signingInput.split(".");
    expect(parts.length).toBe(2);

    // Decode and check the header
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("vc+sd-jwt");
    expect(header.kid).toBe(verificationMethod);
  });

  it("should return the correct JWS algorithm", () => {
    const prepared = prepareSdJwtVcProof(unsignedVC, "P-256", baseOptions);
    expect(prepared.algorithm).toBe("ES256");
  });

  it("should return disclosures matching the SD claims", () => {
    const prepared = prepareSdJwtVcProof(unsignedVC, "P-256", baseOptions);

    expect(prepared.disclosures.length).toBe(2);
    const disclosedNames = new Set<string>();
    for (const d of prepared.disclosures) {
      const decoded = decodeDisclosure(d);
      disclosedNames.add(decoded[1]);
    }
    expect(disclosedNames.has("name")).toBe(true);
    expect(disclosedNames.has("email")).toBe(true);
  });

  it("should include _sd digests in the payload", () => {
    const prepared = prepareSdJwtVcProof(unsignedVC, "P-256", baseOptions);

    const payloadB64 = prepared.signingInput.split(".")[1];
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

    expect(Array.isArray(payload._sd)).toBe(true);
    expect(payload._sd.length).toBe(2);

    // Verify each digest matches a disclosure
    for (const d of prepared.disclosures) {
      const digest = computeDigest(d);
      expect(payload._sd).toContain(digest);
    }
  });
});

describe("completeSdJwtVcProof", () => {
  it("should produce a valid SD-JWT VC string from signingInput, signature, and disclosures", () => {
    const signingInput = "aGVhZGVy.cGF5bG9hZA";
    const signatureBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const disclosures = ["ZGlzYzE", "ZGlzYzI"];

    const result = completeSdJwtVcProof(signingInput, signatureBytes, disclosures);

    // Should be jwt~disc1~disc2~
    const parts = result.split("~");
    expect(parts[0]).toContain("aGVhZGVy.cGF5bG9hZA.");
    expect(parts[1]).toBe("ZGlzYzE");
    expect(parts[2]).toBe("ZGlzYzI");
    // Trailing empty string from final ~
    expect(parts[parts.length - 1]).toBe("");
  });

  it("should throw for invalid signing input (no dot)", () => {
    expect(() =>
      completeSdJwtVcProof("nodot", new Uint8Array([1]), []),
    ).toThrow("Invalid signing input");
  });

  it("should handle empty disclosures", () => {
    const result = completeSdJwtVcProof("header.payload", new Uint8Array([1]), []);
    expect(result).toMatch(/^header\.payload\..+~$/);
  });
});

describe("Interface Signing round-trip", () => {
  it("should produce a valid SD-JWT VC structure through prepare → complete", () => {
    // Phase 1: prepare
    const prepared = prepareSdJwtVcProof(unsignedVC, "P-256", baseOptions);

    // Phase 3: complete (using dummy signature for structure verification)
    const dummySignature = new Uint8Array(64); // ES256 produces 64-byte raw signatures
    const sdJwtVc = completeSdJwtVcProof(
      prepared.signingInput,
      dummySignature,
      prepared.disclosures,
    );

    // Verify structure
    expect(sdJwtVc.endsWith("~")).toBe(true);
    const parts = sdJwtVc.split("~");
    const jwt = parts[0];
    expect(jwt.split(".").length).toBe(3);

    // Disclosures should match
    const outputDisclosures = parts.slice(1).filter((p) => p !== "");
    expect(outputDisclosures.length).toBe(prepared.disclosures.length);
    for (let i = 0; i < prepared.disclosures.length; i++) {
      expect(outputDisclosures[i]).toBe(prepared.disclosures[i]);
    }
  });

  it("should produce a verifiable SD-JWT VC with real signing", async () => {
    const { privateKey, publicKey } = generateEcP256KeyPair();

    // Phase 1: prepare
    const prepared = prepareSdJwtVcProof(unsignedVC, "P-256", baseOptions);

    // Phase 2: sign externally with node:crypto
    // ECDSA with SHA-256 produces a DER-encoded signature; jose expects IEEE P1363 (raw r||s)
    const inputBytes = Buffer.from(prepared.signingInput, "ascii");
    const derSig = cryptoSign("SHA256", inputBytes, {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    const signatureBytes = new Uint8Array(derSig);

    // Phase 3: complete
    const sdJwtVc = completeSdJwtVcProof(
      prepared.signingInput,
      signatureBytes,
      prepared.disclosures,
    );

    // Verify the JWT signature using jose
    const { issuerJwt } = parseSdJwtVc(sdJwtVc);
    const { payload } = await jose.jwtVerify(issuerJwt, publicKey, {
      algorithms: ["ES256"],
    });

    expect(payload.iss).toBe("did:example:issuer123");
    expect(payload.vct).toBe("EducationalCredential");

    // Verify disclosures round-trip
    const outputDisclosures = sdJwtVc.split("~").slice(1).filter((p) => p !== "");
    expect(outputDisclosures.length).toBe(2);
    for (const d of outputDisclosures) {
      const decoded = decodeDisclosure(d);
      expect(decoded.length).toBe(3);
      expect(typeof decoded[0]).toBe("string"); // salt
      expect(typeof decoded[1]).toBe("string"); // name
    }
  });
});

describe("CSPRNG salt verification", () => {
  it("should produce unique salts for each disclosure", async () => {
    const signingKey = createP256SigningKey(verificationMethod);

    // Run multiple times and collect salts
    const allSalts = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);
      const { disclosures } = parseSdJwtVc(result);
      for (const d of disclosures) {
        const [salt] = decodeDisclosure(d);
        allSalts.add(salt);
      }
    }

    // With CSPRNG, 5 runs × 2 disclosures = 10 salts, all should be unique
    expect(allSalts.size).toBe(10);
  });

  it("should produce 16-byte salts", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    const { disclosures } = parseSdJwtVc(result);
    for (const d of disclosures) {
      const [salt] = decodeDisclosure(d);
      const saltBytes = Buffer.from(salt, "base64url");
      expect(saltBytes.length).toBe(16);
    }
  });
});

describe("cross-verification with verifier logic", () => {
  /**
   * Replicate the verification module's disclosure processing to confirm
   * that our signing output is compatible with the verifier.
   */
  async function processDisclosures(
    payload: Record<string, unknown>,
    disclosureStrings: string[],
  ): Promise<Record<string, unknown>> {
    const result: Record<string, unknown> = { ...payload };
    const sdDigests = (payload._sd as string[] | undefined) ?? [];
    const disclosureMap = new Map<string, [string, string, unknown]>();

    for (const d of disclosureStrings) {
      const digest = computeDigest(d);
      disclosureMap.set(digest, decodeDisclosure(d));
    }

    for (const digest of sdDigests) {
      const disclosure = disclosureMap.get(digest);
      if (disclosure) {
        const [, name, value] = disclosure;
        result[name] = value;
      }
    }

    delete result._sd;
    delete result._sd_alg;
    return result;
  }

  it("should produce output that reconstructs to full claims via disclosure processing", async () => {
    const signingKey = createP256SigningKey(verificationMethod);
    const result = await signCredentialSdJwtVc(unsignedVC, signingKey, baseOptions);

    // Parse
    const { issuerJwt, disclosures: disclosureStrings } = parseSdJwtVc(result);
    expect(issuerJwt).toBeTruthy();
    expect(disclosureStrings.length).toBe(2);

    // Verify JWT signature
    const { payload } = await jose.jwtVerify(issuerJwt, signingKey.publicKey, {
      algorithms: ["ES256"],
    });

    // Process disclosures to reconstruct claims
    const resolved = await processDisclosures(
      payload as Record<string, unknown>,
      disclosureStrings,
    );

    // Selectively disclosed claims should be reconstructed
    expect(resolved.name).toBe("Alice");
    expect(resolved.email).toBe("alice@example.com");
    // Non-SD claim should also be present
    expect(resolved.degree).toBe("Computer Science");
    // Standard JWT claims preserved
    expect(resolved.iss).toBe("did:example:issuer123");
    expect(resolved.vct).toBe("EducationalCredential");
  });
});
