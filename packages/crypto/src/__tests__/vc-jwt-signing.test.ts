import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign, type KeyObject } from "node:crypto";
import * as jose from "jose";
import type { SigningKey, SigningAlgorithm } from "../types.js";
import {
  signCredentialVcJwt,
  prepareVcJwtProof,
  completeVcJwtProof,
} from "../vc-jwt-signing.js";

function generateEcKeyPair(curve = "P-256"): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: curve });
}

function generateRsaKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
}

function createSigningKey(
  id: string,
  algorithm: SigningAlgorithm,
  keys: { privateKey: KeyObject; publicKey: KeyObject },
): SigningKey {
  return { id, privateKey: keys.privateKey, publicKey: keys.publicKey, algorithm };
}

const verificationMethod = "did:key:zTest123#zTest123";

const unsignedVC = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  type: ["VerifiableCredential"],
  id: "urn:uuid:test-credential",
  issuer: "did:key:zTestIssuer",
  issuanceDate: "2024-01-01T00:00:00Z",
  credentialSubject: {
    id: "did:example:subject",
    name: "Test Subject",
  },
};

const unsignedVCWithExpiry = {
  ...unsignedVC,
  expirationDate: "2025-12-31T23:59:59Z",
};

const unsignedVCDm2 = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  type: ["VerifiableCredential"],
  id: "urn:uuid:test-credential-v2",
  issuer: "did:key:zTestIssuer",
  validFrom: "2024-01-01T00:00:00Z",
  validUntil: "2025-12-31T23:59:59Z",
  credentialSubject: {
    id: "did:example:subject",
    name: "Test Subject",
  },
};

const unsignedVCObjectIssuer = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  type: ["VerifiableCredential"],
  id: "urn:uuid:test-credential-obj-issuer",
  issuer: { id: "did:key:zTestIssuer", name: "Test Org" },
  issuanceDate: "2024-06-15T12:00:00Z",
  credentialSubject: {
    name: "No Subject ID",
  },
};

describe("signCredentialVcJwt", () => {
  it("should produce a valid JWT with 3 dot-separated parts (P-256)", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVC, signingKey, { verificationMethod });

    expect(typeof jwt).toBe("string");
    const parts = jwt.split(".");
    expect(parts).toHaveLength(3);
    for (const part of parts) {
      expect(part.length).toBeGreaterThan(0);
    }
  });

  it("should set correct JWT header: alg=ES256, typ=JWT, kid", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVC, signingKey, { verificationMethod });

    const header = jose.decodeProtectedHeader(jwt);
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(verificationMethod);
  });

  it("should map JWT claims correctly: iss, sub, jti, nbf, vc", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVC, signingKey, { verificationMethod });

    const payload = jose.decodeJwt(jwt);
    expect(payload.iss).toBe("did:key:zTestIssuer");
    expect(payload.sub).toBe("did:example:subject");
    expect(payload.jti).toBe("urn:uuid:test-credential");
    // nbf: 2024-01-01T00:00:00Z = 1704067200
    expect(payload.nbf).toBe(1704067200);
    expect(payload.exp).toBeUndefined();
  });

  it("should include vc claim with @context, type, and credentialSubject", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVC, signingKey, { verificationMethod });

    const payload = jose.decodeJwt(jwt) as Record<string, unknown>;
    const vc = payload.vc as Record<string, unknown>;
    expect(vc).toBeDefined();
    expect(vc["@context"]).toEqual(["https://www.w3.org/2018/credentials/v1"]);
    expect(vc["type"]).toEqual(["VerifiableCredential"]);
    expect(vc["credentialSubject"]).toEqual({
      id: "did:example:subject",
      name: "Test Subject",
    });
  });

  it("should set exp claim when expirationDate is present", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVCWithExpiry, signingKey, { verificationMethod });

    const payload = jose.decodeJwt(jwt);
    // 2025-12-31T23:59:59Z = 1767225599
    expect(payload.exp).toBe(1767225599);
  });

  it("should use validFrom/validUntil (DM 2.0 fields)", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVCDm2, signingKey, { verificationMethod });

    const payload = jose.decodeJwt(jwt);
    expect(payload.nbf).toBe(1704067200);
    expect(payload.exp).toBe(1767225599);
  });

  it("should handle issuer as object with id", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVCObjectIssuer, signingKey, { verificationMethod });

    const payload = jose.decodeJwt(jwt);
    expect(payload.iss).toBe("did:key:zTestIssuer");
  });

  it("should omit sub when credentialSubject has no id", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVCObjectIssuer, signingKey, { verificationMethod });

    const payload = jose.decodeJwt(jwt);
    expect(payload.sub).toBeUndefined();
  });

  it("should verify the signature with jose.jwtVerify (P-256 round-trip)", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVC, signingKey, { verificationMethod });

    const { payload } = await jose.jwtVerify(jwt, keys.publicKey, {
      algorithms: ["ES256"],
    });
    expect(payload.iss).toBe("did:key:zTestIssuer");
    expect(payload.sub).toBe("did:example:subject");
  });

  it("should produce nbf/exp as Unix timestamps in seconds (not milliseconds)", async () => {
    const keys = generateEcKeyPair("P-256");
    const signingKey = createSigningKey(verificationMethod, "P-256", keys);
    const jwt = await signCredentialVcJwt(unsignedVCWithExpiry, signingKey, { verificationMethod });

    const payload = jose.decodeJwt(jwt);
    // Unix timestamps should be 10-digit numbers (seconds), not 13-digit (milliseconds)
    expect(payload.nbf!.toString()).toHaveLength(10);
    expect(payload.exp!.toString()).toHaveLength(10);
  });
});

describe("signCredentialVcJwt with P-384", () => {
  it("should use ES384 algorithm for P-384 keys", async () => {
    const keys = generateEcKeyPair("P-384");
    const signingKey = createSigningKey(verificationMethod, "P-384", keys);
    const jwt = await signCredentialVcJwt(unsignedVC, signingKey, { verificationMethod });

    const header = jose.decodeProtectedHeader(jwt);
    expect(header.alg).toBe("ES384");

    // Verify the signature
    const { payload } = await jose.jwtVerify(jwt, keys.publicKey, {
      algorithms: ["ES384"],
    });
    expect(payload.iss).toBe("did:key:zTestIssuer");
  });
});

describe("signCredentialVcJwt with RSA (PS256)", () => {
  it("should use PS256 algorithm for RSA-2048 keys", async () => {
    const keys = generateRsaKeyPair();
    const signingKey = createSigningKey(verificationMethod, "RSA-2048", keys);
    const jwt = await signCredentialVcJwt(unsignedVC, signingKey, { verificationMethod });

    const header = jose.decodeProtectedHeader(jwt);
    expect(header.alg).toBe("PS256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(verificationMethod);

    // Verify the signature
    const { payload } = await jose.jwtVerify(jwt, keys.publicKey, {
      algorithms: ["PS256"],
    });
    expect(payload.iss).toBe("did:key:zTestIssuer");
    expect(payload.jti).toBe("urn:uuid:test-credential");
  });
});

describe("prepareVcJwtProof", () => {
  it("should return signingInput with correct header.payload format", () => {
    const prepared = prepareVcJwtProof(unsignedVC, "P-256", { verificationMethod });

    expect(typeof prepared.signingInput).toBe("string");
    const parts = prepared.signingInput.split(".");
    expect(parts).toHaveLength(2);

    // Decode and verify header
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(verificationMethod);

    // Decode and verify payload claims
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    expect(payload.iss).toBe("did:key:zTestIssuer");
    expect(payload.sub).toBe("did:example:subject");
    expect(payload.jti).toBe("urn:uuid:test-credential");
    expect(payload.nbf).toBe(1704067200);
    expect(payload.vc).toBeDefined();
  });

  it("should return the protectedHeader object", () => {
    const prepared = prepareVcJwtProof(unsignedVC, "P-256", { verificationMethod });
    expect(prepared.protectedHeader).toEqual({
      alg: "ES256",
      typ: "JWT",
      kid: verificationMethod,
    });
  });

  it("should use PS256 for RSA algorithms", () => {
    const prepared = prepareVcJwtProof(unsignedVC, "RSA-2048", { verificationMethod });
    expect(prepared.protectedHeader.alg).toBe("PS256");
  });
});

describe("completeVcJwtProof", () => {
  it("should produce a valid 3-part JWT from signingInput and signatureBytes", () => {
    const signingInput = "aGVhZGVy.cGF5bG9hZA";
    const signatureBytes = new Uint8Array([1, 2, 3, 4, 5]);

    const jwt = completeVcJwtProof(signingInput, signatureBytes);
    const parts = jwt.split(".");
    expect(parts).toHaveLength(3);
    expect(parts[0]).toBe("aGVhZGVy");
    expect(parts[1]).toBe("cGF5bG9hZA");
    expect(Buffer.from(parts[2], "base64url")).toEqual(Buffer.from(signatureBytes));
  });

  it("should throw for invalid signing input (no dot separator)", () => {
    expect(() => completeVcJwtProof("nodot", new Uint8Array([1]))).toThrow(
      "Invalid signing input",
    );
  });
});

describe("Interface Signing round-trip (prepare → sign externally → complete)", () => {
  it("should produce a valid JWT when signed externally with P-256", async () => {
    const keys = generateEcKeyPair("P-256");
    const prepared = prepareVcJwtProof(unsignedVC, "P-256", { verificationMethod });

    // Sign externally using Node crypto
    const signer = createSign("SHA256");
    signer.update(prepared.signingInput);
    const derSignature = signer.sign(keys.privateKey);

    // jose expects raw R||S for EC, not DER. Convert DER → raw.
    const rawSig = ecDerToRaw(derSignature, 32);

    const jwt = completeVcJwtProof(prepared.signingInput, rawSig);

    // Verify the assembled JWT
    const { payload } = await jose.jwtVerify(jwt, keys.publicKey, {
      algorithms: ["ES256"],
    });
    expect(payload.iss).toBe("did:key:zTestIssuer");
    expect(payload.sub).toBe("did:example:subject");
  });

  it("should produce a valid JWT when signed externally with RSA", async () => {
    const keys = generateRsaKeyPair();
    const prepared = prepareVcJwtProof(unsignedVC, "RSA-2048", { verificationMethod });

    // Sign externally using Node crypto (PSS padding)
    const signer = createSign("SHA256");
    signer.update(prepared.signingInput);
    const signature = signer.sign({
      key: keys.privateKey,
      padding: 6, // RSA_PKCS1_PSS_PADDING
      saltLength: 32,
    });

    const jwt = completeVcJwtProof(prepared.signingInput, new Uint8Array(signature));

    // Verify the assembled JWT
    const { payload } = await jose.jwtVerify(jwt, keys.publicKey, {
      algorithms: ["PS256"],
    });
    expect(payload.iss).toBe("did:key:zTestIssuer");
  });
});

/**
 * Convert a DER-encoded ECDSA signature to the raw R||S format used by JWS.
 * Each component is padded/trimmed to exactly `componentLength` bytes.
 */
function ecDerToRaw(derSig: Buffer, componentLength: number): Uint8Array {
  // DER: 0x30 <total-len> 0x02 <r-len> <r-bytes> 0x02 <s-len> <s-bytes>
  let offset = 2; // skip 0x30 and total length
  // R
  offset += 1; // skip 0x02
  const rLen = derSig[offset++];
  const rStart = offset;
  offset += rLen;
  // S
  offset += 1; // skip 0x02
  const sLen = derSig[offset++];
  const sStart = offset;

  const raw = new Uint8Array(componentLength * 2);

  // Copy R, right-aligned (strip leading zero padding if present)
  const rBytes = derSig.subarray(rStart, rStart + rLen);
  const rTrimmed = rBytes[0] === 0 && rLen > componentLength ? rBytes.subarray(1) : rBytes;
  raw.set(rTrimmed, componentLength - rTrimmed.length);

  // Copy S, right-aligned
  const sBytes = derSig.subarray(sStart, sStart + sLen);
  const sTrimmed = sBytes[0] === 0 && sLen > componentLength ? sBytes.subarray(1) : sBytes;
  raw.set(sTrimmed, componentLength * 2 - sTrimmed.length);

  return raw;
}
