import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { signCredentialJws } from "@opencred/crypto";
import type { UnsignedCredential } from "@opencred/vc-core";
import { encodeDidJwk, didJwkVerificationMethodId } from "@opencred/did";
import * as jose from "jose";
import { verifyJwsProof, ALLOWED_JWS_ALGORITHMS } from "../jws-proof.js";

function generateRsaKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
}

const unsignedVC: UnsignedCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:test-jws-verification",
  type: ["VerifiableCredential"],
  issuer: "did:example:issuer",
  validFrom: "2024-01-01T00:00:00Z",
  credentialSubject: { id: "did:example:subject", name: "Test" },
};

/**
 * Helper: generate an RSA key pair and derive a did:jwk DID + verification method ID.
 */
function createRsaDidJwkFixture() {
  const { privateKey, publicKey } = generateRsaKeyPair();
  const jwk = publicKey.export({ format: "jwk" });
  const did = encodeDidJwk(jwk as import("@opencred/did").JWK);
  const verificationMethodId = didJwkVerificationMethodId(did);

  return { privateKey, publicKey, did, verificationMethodId };
}

describe("verifyJwsProof — valid signatures", () => {
  it("should verify a validly-signed JWS and return passed: true", async () => {
    const { privateKey, publicKey, verificationMethodId } = createRsaDidJwkFixture();

    const jws = await signCredentialJws(
      unsignedVC,
      {
        id: verificationMethodId,
        privateKey,
        publicKey,
        algorithm: "RSA-2048",
      },
      { verificationMethod: verificationMethodId },
    );

    const result = await verifyJwsProof(jws);
    expect(result.passed).toBe(true);
    expect(result.name).toBe("signature");
  });
});

describe("verifyJwsProof — tampered signatures", () => {
  it("should return passed: false for a tampered signature", async () => {
    const { privateKey, publicKey, verificationMethodId } = createRsaDidJwkFixture();

    const jws = await signCredentialJws(
      unsignedVC,
      {
        id: verificationMethodId,
        privateKey,
        publicKey,
        algorithm: "RSA-2048",
      },
      { verificationMethod: verificationMethodId },
    );

    // Tamper with the signature (last part)
    const parts = jws.split(".");
    const sigBytes = Buffer.from(parts[2], "base64url");
    // Flip a byte in the signature
    sigBytes[0] = sigBytes[0] ^ 0xff;
    const tamperedJws = `${parts[0]}.${parts[1]}.${sigBytes.toString("base64url")}`;

    const result = await verifyJwsProof(tamperedJws);
    expect(result.passed).toBe(false);
    expect(result.detail).toBeDefined();
  });
});

describe("verifyJwsProof — invalid format", () => {
  it("should return passed: false for a string with fewer than 3 parts", async () => {
    const result = await verifyJwsProof("only.twoparts");
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("3 dot-separated parts");
  });

  it("should return passed: false for a string with more than 3 parts", async () => {
    const result = await verifyJwsProof("one.two.three.four");
    // This has 4 parts, so it should fail the 3-part check
    expect(result.passed).toBe(false);
  });

  it("should return passed: false for a non-base64url header", async () => {
    // Create a JWS-like string with invalid base64url in the header
    const result = await verifyJwsProof("!!!invalid!!!.cGF5bG9hZA.c2ln");
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("decode");
  });
});

describe("verifyJwsProof — missing kid", () => {
  it("should return passed: false when kid is missing from the header", async () => {
    // Create a JWS-like string with a header that has no kid
    const headerNoKid = { alg: "PS256" };
    const headerB64 = Buffer.from(JSON.stringify(headerNoKid)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(unsignedVC)).toString("base64url");
    const fakeJws = `${headerB64}.${payloadB64}.fakesignature`;

    const result = await verifyJwsProof(fakeJws);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("kid");
  });
});

describe("verifyJwsProof — missing alg", () => {
  it("should return passed: false when alg is missing from the header", async () => {
    const headerNoAlg = { kid: "did:jwk:test#0" };
    const headerB64 = Buffer.from(JSON.stringify(headerNoAlg)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(unsignedVC)).toString("base64url");
    const fakeJws = `${headerB64}.${payloadB64}.fakesignature`;

    const result = await verifyJwsProof(fakeJws);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("alg");
  });
});

describe("verifyJwsProof — unresolvable DID", () => {
  it("should return passed: false when the DID cannot be resolved", async () => {
    // Create a JWS header pointing to a did:web that DIDJwkResolver cannot resolve
    const header = { alg: "PS256", kid: "did:web:nonexistent.example#key-1" };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(unsignedVC)).toString("base64url");
    const fakeJws = `${headerB64}.${payloadB64}.fakesignature`;

    const result = await verifyJwsProof(fakeJws);
    expect(result.passed).toBe(false);
    expect(result.detail).toBeDefined();
  });
});

describe("verifyJwsProof - algorithm allowlist", () => {
  async function buildJws(
    alg: string,
    privateKey: KeyObject,
    publicKey: KeyObject,
  ): Promise<string> {
    const publicJwk = publicKey.export({ format: "jwk" });
    const did = encodeDidJwk(publicJwk as import("@opencred/did").JWK);
    const kid = didJwkVerificationMethodId(did);
    const joseKey = await jose.importPKCS8(
      privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      alg,
    );
    const payload = new TextEncoder().encode(JSON.stringify(unsignedVC));
    return new jose.CompactSign(payload).setProtectedHeader({ alg, kid }).sign(joseKey);
  }

  it("exposes the expected allowlist", () => {
    expect([...ALLOWED_JWS_ALGORITHMS]).toEqual(["ES256", "ES384", "PS256", "EdDSA"]);
  });

  it("accepts a validly-signed ES256 JWS", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jws = await buildJws("ES256", privateKey, publicKey);
    const result = await verifyJwsProof(jws);
    expect(result.passed).toBe(true);
  });

  it("accepts a validly-signed ES384 JWS", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const jws = await buildJws("ES384", privateKey, publicKey);
    const result = await verifyJwsProof(jws);
    expect(result.passed).toBe(true);
  });

  it("accepts a validly-signed EdDSA JWS", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const jws = await buildJws("EdDSA", privateKey, publicKey);
    const result = await verifyJwsProof(jws);
    expect(result.passed).toBe(true);
  });

  it("accepts a validly-signed PS256 JWS (RSA via signCredentialJws)", async () => {
    // signCredentialJws produces PS256 for RSA keys (see signingAlgorithmToJwsAlg)
    const { privateKey, publicKey } = generateRsaKeyPair();
    const publicJwk = publicKey.export({ format: "jwk" });
    const did = encodeDidJwk(publicJwk as import("@opencred/did").JWK);
    const kid = didJwkVerificationMethodId(did);
    const jws = await signCredentialJws(
      unsignedVC,
      { id: kid, privateKey, publicKey, algorithm: "RSA-2048" },
      { verificationMethod: kid },
    );
    const result = await verifyJwsProof(jws);
    expect(result.passed).toBe(true);
  });

  it("rejects a JWS whose header declares alg none", async () => {
    // Classic JWS attack: attacker flips alg to none to bypass sig check.
    const header = { alg: "none", kid: "did:jwk:ignored#0" };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(unsignedVC)).toString("base64url");
    const fakeJws = `${headerB64}.${payloadB64}.`;

    const result = await verifyJwsProof(fakeJws);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/not permitted/);
    expect(result.detail).toMatch(/none/);
  });

  it("rejects a JWS with a disallowed symmetric algorithm (HS256)", async () => {
    const header = { alg: "HS256", kid: "did:jwk:ignored#0" };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(unsignedVC)).toString("base64url");
    const fakeJws = `${headerB64}.${payloadB64}.fakesignature`;

    const result = await verifyJwsProof(fakeJws);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/not permitted/);
    expect(result.detail).toMatch(/HS256/);
  });

  it("rejects a JWS with ES512 (not on the OpenCred allowlist)", async () => {
    // ES512 is a valid JWS algorithm but OpenCred does not produce it.
    const header = { alg: "ES512", kid: "did:jwk:ignored#0" };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(unsignedVC)).toString("base64url");
    const fakeJws = `${headerB64}.${payloadB64}.fakesignature`;

    const result = await verifyJwsProof(fakeJws);
    expect(result.passed).toBe(false);
    expect(result.detail).toMatch(/not permitted/);
    expect(result.detail).toMatch(/ES512/);
  });
});
