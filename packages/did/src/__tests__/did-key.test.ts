import { describe, it, expect } from "vitest";
import { createECDH } from "node:crypto";
import { DIDKeyResolver } from "../did-key.js";
import { encodeBase58btc } from "../multibase.js";
import { DIDResolutionError } from "@opencred/shared";

const P256_MULTICODEC_VARINT = new Uint8Array([0x80, 0x24]);

function createP256DID(): { did: string; compressedKey: Uint8Array } {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const compressedKey = ecdh.getPublicKey(null, "compressed");

  const multicodecKey = new Uint8Array(P256_MULTICODEC_VARINT.length + compressedKey.length);
  multicodecKey.set(P256_MULTICODEC_VARINT, 0);
  multicodecKey.set(compressedKey, P256_MULTICODEC_VARINT.length);

  const multibaseKey = "z" + encodeBase58btc(multicodecKey);
  return { did: `did:key:${multibaseKey}`, compressedKey: new Uint8Array(compressedKey) };
}

describe("DIDKeyResolver", () => {
  const resolver = new DIDKeyResolver();

  it("should resolve a valid P-256 did:key", async () => {
    const { did } = createP256DID();
    const result = await resolver.resolve(did);

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
    expect(result.didDocument!["@context"]).toContain("https://www.w3.org/ns/did/v1");
    expect(result.didDocument!.verificationMethod).toHaveLength(1);

    const vm = result.didDocument!.verificationMethod![0];
    expect(vm.type).toBe("Multikey");
    expect(vm.controller).toBe(did);
    expect(vm.publicKeyMultibase).toBeDefined();
    expect(vm.publicKeyMultibase!.startsWith("z")).toBe(true);
  });

  it("should include all verification relationships", async () => {
    const { did } = createP256DID();
    const result = await resolver.resolve(did);
    const doc = result.didDocument!;

    const expectedId = `${did}#${did.split(":")[2]}`;
    expect(doc.authentication).toEqual([expectedId]);
    expect(doc.assertionMethod).toEqual([expectedId]);
    expect(doc.capabilityInvocation).toEqual([expectedId]);
    expect(doc.capabilityDelegation).toEqual([expectedId]);
  });

  it("should return correct resolution metadata", async () => {
    const { did } = createP256DID();
    const result = await resolver.resolve(did);

    expect(result.didResolutionMetadata.contentType).toBe("application/did+ld+json");
    expect(result.didDocumentMetadata).toEqual({});
  });

  it("should resolve multiple different P-256 DIDs correctly", async () => {
    const { did: did1 } = createP256DID();
    const { did: did2 } = createP256DID();

    expect(did1).not.toBe(did2);

    const result1 = await resolver.resolve(did1);
    const result2 = await resolver.resolve(did2);

    expect(result1.didDocument!.id).toBe(did1);
    expect(result2.didDocument!.id).toBe(did2);
  });

  it("should reject a malformed DID (missing parts)", async () => {
    await expect(resolver.resolve("did:key")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject a malformed DID (no did: prefix)", async () => {
    await expect(resolver.resolve("key:z1234")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject unsupported DID methods", async () => {
    await expect(resolver.resolve("did:web:example.com")).rejects.toThrow(
      "Unsupported DID method: web",
    );
  });

  it("should reject non-base58btc multibase encoding", async () => {
    await expect(resolver.resolve("did:key:f01020304")).rejects.toThrow("Only base58btc");
  });

  it("should reject unsupported key types (non-P-256 multicodec)", async () => {
    // Ed25519 multicodec prefix is 0xed01 (varint: [0xed, 0x01])
    const fakeKey = new Uint8Array(34);
    fakeKey[0] = 0xed;
    fakeKey[1] = 0x01;
    const multibase = "z" + encodeBase58btc(fakeKey);
    const did = `did:key:${multibase}`;

    await expect(resolver.resolve(did)).rejects.toThrow("Unsupported key type");
  });

  it("should reject P-256 key with invalid length", async () => {
    // P-256 prefix but only 20 bytes of key (should be 33)
    const shortKey = new Uint8Array(22);
    shortKey[0] = 0x80;
    shortKey[1] = 0x24;
    shortKey[2] = 0x02;
    const multibase = "z" + encodeBase58btc(shortKey);
    const did = `did:key:${multibase}`;

    await expect(resolver.resolve(did)).rejects.toThrow("Invalid P-256 key length");
  });

  it("should reject P-256 key with invalid compression prefix", async () => {
    const badKey = new Uint8Array(35);
    badKey[0] = 0x80;
    badKey[1] = 0x24;
    badKey[2] = 0x05; // invalid: should be 0x02 or 0x03
    const multibase = "z" + encodeBase58btc(badKey);
    const did = `did:key:${multibase}`;

    await expect(resolver.resolve(did)).rejects.toThrow("Invalid P-256 compressed key");
  });

  it("should reject empty DID string", async () => {
    await expect(resolver.resolve("")).rejects.toThrow(DIDResolutionError);
  });

  it("should reject null/undefined DID", async () => {
    await expect(resolver.resolve(null as unknown as string)).rejects.toThrow(DIDResolutionError);
    await expect(resolver.resolve(undefined as unknown as string)).rejects.toThrow(
      DIDResolutionError,
    );
  });
});
