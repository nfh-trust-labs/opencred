import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import type { UnsignedCredential } from "@opencred/vc-core";
import {
  signCredentialJws,
  prepareJwsProof,
  completeJwsProof,
  signCredentialAuto,
} from "../jws-proof.js";
import type { SigningKey } from "../types.js";

function generateRsaKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
}

function generateEcKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

function createRsaSigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateRsaKeyPair();
  return { id, privateKey, publicKey, algorithm: "RSA-2048" };
}

function createEcSigningKey(id: string): SigningKey {
  const { privateKey, publicKey } = generateEcKeyPair();
  return { id, privateKey, publicKey, algorithm: "P-256" };
}

const unsignedVC: UnsignedCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:test-jws-credential",
  type: ["VerifiableCredential"],
  issuer: "did:example:issuer",
  validFrom: "2024-01-01T00:00:00Z",
  credentialSubject: { id: "did:example:subject", name: "Test" },
};

const verificationMethod = "did:jwk:test#0";

describe("signCredentialJws", () => {
  it("should produce a valid JWS string with 3 dot-separated parts", async () => {
    const signingKey = createRsaSigningKey(verificationMethod);
    const jws = await signCredentialJws(unsignedVC, signingKey, { verificationMethod });

    expect(typeof jws).toBe("string");
    const parts = jws.split(".");
    expect(parts.length).toBe(3);
    // Each part should be non-empty base64url
    for (const part of parts) {
      expect(part.length).toBeGreaterThan(0);
    }
  });

  it("should set alg to PS256 and kid in the header", async () => {
    const signingKey = createRsaSigningKey(verificationMethod);
    const jws = await signCredentialJws(unsignedVC, signingKey, { verificationMethod });

    const headerB64 = jws.split(".")[0];
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
    expect(header.alg).toBe("PS256");
    expect(header.kid).toBe(verificationMethod);
  });

  it("should encode the original VC in the payload", async () => {
    const signingKey = createRsaSigningKey(verificationMethod);
    const jws = await signCredentialJws(unsignedVC, signingKey, { verificationMethod });

    const payloadB64 = jws.split(".")[1];
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    expect(payload["@context"]).toEqual(unsignedVC["@context"]);
    expect(payload.type).toEqual(unsignedVC.type);
    expect(payload.issuer).toBe(unsignedVC.issuer);
    expect(payload.validFrom).toBe(unsignedVC.validFrom);
    expect(payload.credentialSubject).toEqual(unsignedVC.credentialSubject);
  });

  it("should reject non-RSA keys", async () => {
    const ecKey = createEcSigningKey(verificationMethod);
    await expect(signCredentialJws(unsignedVC, ecKey, { verificationMethod })).rejects.toThrow(
      "signCredentialJws only supports RSA keys",
    );
  });
});

describe("prepareJwsProof", () => {
  it("should return signingInput with correct base64url(header).base64url(payload) format", () => {
    const prepared = prepareJwsProof(unsignedVC, "RSA-2048", { verificationMethod });

    expect(typeof prepared.signingInput).toBe("string");
    const parts = prepared.signingInput.split(".");
    expect(parts.length).toBe(2);

    // Decode header
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    expect(header.alg).toBe("PS256");
    expect(header.kid).toBe(verificationMethod);

    // Decode payload
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    expect(payload.issuer).toBe(unsignedVC.issuer);
  });

  it("should return the protectedHeader object", () => {
    const prepared = prepareJwsProof(unsignedVC, "RSA-2048", { verificationMethod });
    expect(prepared.protectedHeader).toEqual({ alg: "PS256", kid: verificationMethod });
  });
});

describe("completeJwsProof", () => {
  it("should produce a valid 3-part JWS from signingInput and signatureBytes", () => {
    const signingInput = "aGVhZGVy.cGF5bG9hZA";
    const signatureBytes = new Uint8Array([1, 2, 3, 4, 5]);

    const jws = completeJwsProof(signingInput, signatureBytes);
    const parts = jws.split(".");
    expect(parts.length).toBe(3);
    expect(parts[0]).toBe("aGVhZGVy");
    expect(parts[1]).toBe("cGF5bG9hZA");
    // Third part is base64url of the signature bytes
    expect(Buffer.from(parts[2], "base64url")).toEqual(Buffer.from(signatureBytes));
  });

  it("should throw for invalid signing input (no dot separator)", () => {
    expect(() => completeJwsProof("nodot", new Uint8Array([1]))).toThrow("Invalid signing input");
  });
});

describe("signCredentialAuto", () => {
  it("should dispatch RSA keys to VC-JWT and return a JWT string", async () => {
    const signingKey = createRsaSigningKey(verificationMethod);
    const result = await signCredentialAuto(unsignedVC, signingKey, { verificationMethod });

    expect(typeof result).toBe("string");
    const parts = (result as string).split(".");
    expect(parts.length).toBe(3);

    // Verify it's a VC-JWT (typ: "JWT")
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    expect(header.typ).toBe("JWT");
  });

  it("should dispatch EC keys to VC-JWT and return a JWT string", async () => {
    const signingKey = createEcSigningKey(verificationMethod);
    const result = await signCredentialAuto(unsignedVC, signingKey, {
      verificationMethod,
      proofPurpose: "assertionMethod",
    });

    expect(typeof result).toBe("string");
    const parts = (result as string).split(".");
    expect(parts.length).toBe(3);

    // Verify it's a VC-JWT (typ: "JWT")
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    expect(header.typ).toBe("JWT");
  });
});
