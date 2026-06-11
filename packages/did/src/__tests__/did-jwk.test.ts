import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { DIDJwkResolver, encodeDidJwk, didJwkVerificationMethodId } from "../did-jwk.js";
import { DIDResolutionError } from "@opencred/shared";
import type { JWK } from "../types.js";

function createRsaJwk(): JWK {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  return jwk as JWK;
}

function createEcJwk(): JWK {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  return jwk as JWK;
}

describe("encodeDidJwk", () => {
  it("should encode an RSA JWK as did:jwk", () => {
    const jwk = createRsaJwk();
    const did = encodeDidJwk(jwk);

    expect(did).toMatch(/^did:jwk:/);
    const encoded = did.split(":")[2];
    const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf-8"));
    expect(decoded.kty).toBe("RSA");
    expect(decoded.n).toBeDefined();
    expect(decoded.e).toBeDefined();
  });

  it("should encode an EC JWK as did:jwk", () => {
    const jwk = createEcJwk();
    const did = encodeDidJwk(jwk);

    expect(did).toMatch(/^did:jwk:/);
    const encoded = did.split(":")[2];
    const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf-8"));
    expect(decoded.kty).toBe("EC");
    expect(decoded.crv).toBe("P-256");
  });

  it("should strip private key component 'd'", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = privateKey.export({ format: "jwk" }) as JWK;
    expect(jwk.d).toBeDefined();

    const did = encodeDidJwk(jwk);
    const encoded = did.split(":")[2];
    const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf-8"));
    expect(decoded.d).toBeUndefined();
  });

  it("should produce deterministic output for the same JWK", () => {
    const jwk = createRsaJwk();
    const did1 = encodeDidJwk(jwk);
    const did2 = encodeDidJwk(jwk);
    expect(did1).toBe(did2);
  });
});

describe("didJwkVerificationMethodId", () => {
  it("should append #0 to the DID", () => {
    const did = "did:jwk:eyJrdHkiOiJSU0EifQ";
    expect(didJwkVerificationMethodId(did)).toBe(`${did}#0`);
  });
});

describe("DIDJwkResolver", () => {
  const resolver = new DIDJwkResolver();

  it("should resolve a valid RSA did:jwk", async () => {
    const jwk = createRsaJwk();
    const did = encodeDidJwk(jwk);
    const result = await resolver.resolve(did);

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
    expect(result.didDocument!.verificationMethod).toHaveLength(1);

    const vm = result.didDocument!.verificationMethod![0];
    expect(vm.type).toBe("JsonWebKey");
    expect(vm.controller).toBe(did);
    expect(vm.publicKeyJwk).toBeDefined();
    expect(vm.publicKeyJwk!.kty).toBe("RSA");
    expect(vm.id).toBe(`${did}#0`);
  });

  it("should resolve a valid EC did:jwk", async () => {
    const jwk = createEcJwk();
    const did = encodeDidJwk(jwk);
    const result = await resolver.resolve(did);

    expect(result.didDocument).not.toBeNull();
    const vm = result.didDocument!.verificationMethod![0];
    expect(vm.publicKeyJwk!.kty).toBe("EC");
    expect(vm.publicKeyJwk!.crv).toBe("P-256");
  });

  it("should include all verification relationships", async () => {
    const jwk = createRsaJwk();
    const did = encodeDidJwk(jwk);
    const result = await resolver.resolve(did);
    const doc = result.didDocument!;

    const expectedId = `${did}#0`;
    expect(doc.authentication).toEqual([expectedId]);
    expect(doc.assertionMethod).toEqual([expectedId]);
    expect(doc.capabilityInvocation).toEqual([expectedId]);
    expect(doc.capabilityDelegation).toEqual([expectedId]);
  });

  it("should return correct resolution metadata", async () => {
    const jwk = createRsaJwk();
    const did = encodeDidJwk(jwk);
    const result = await resolver.resolve(did);

    expect(result.didResolutionMetadata.contentType).toBe("application/did+ld+json");
    expect(result.didDocumentMetadata).toEqual({});
  });

  it("should round-trip: encode → resolve → extract JWK", async () => {
    const jwk = createRsaJwk();
    const did = encodeDidJwk(jwk);
    const result = await resolver.resolve(did);
    const resolvedJwk = result.didDocument!.verificationMethod![0].publicKeyJwk!;

    expect(resolvedJwk.kty).toBe(jwk.kty);
    expect(resolvedJwk.n).toBe(jwk.n);
    expect(resolvedJwk.e).toBe(jwk.e);
  });

  it("should reject a malformed DID", async () => {
    await expect(resolver.resolve("did:jwk")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject unsupported DID methods", async () => {
    await expect(resolver.resolve("did:key:z1234")).rejects.toThrow("Unsupported DID method: key");
  });

  it("should reject empty encoded data", async () => {
    await expect(resolver.resolve("did:jwk:")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject invalid base64url data", async () => {
    await expect(resolver.resolve("did:jwk:notvalidjson!!!")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject JWK without kty", async () => {
    const encoded = Buffer.from(JSON.stringify({ x: "test" })).toString("base64url");
    await expect(resolver.resolve(`did:jwk:${encoded}`)).rejects.toThrow("missing required 'kty'");
  });

  it("should reject null/undefined DID", async () => {
    await expect(resolver.resolve(null as unknown as string)).rejects.toThrow(DIDResolutionError);
    await expect(resolver.resolve(undefined as unknown as string)).rejects.toThrow(
      DIDResolutionError,
    );
  });
});
