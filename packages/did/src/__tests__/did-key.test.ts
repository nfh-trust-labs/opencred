import { describe, it, expect } from "vitest";
import { createECDH, generateKeyPairSync } from "node:crypto";
import {
  DIDKeyResolver,
  deriveDidKeyId,
  deriveDidKeyIdFromCompressedKey,
  getCompressedPublicKey,
  computeKeyFingerprint,
} from "../did-key.js";
import { encodeBase58btc } from "../multibase.js";
import { DIDResolutionError } from "@opencred/shared";

const P256_MULTICODEC_VARINT = new Uint8Array([0x80, 0x24]);
const P384_MULTICODEC_VARINT = new Uint8Array([0x81, 0x24]);

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

function createP384DID(): { did: string; compressedKey: Uint8Array } {
  const ecdh = createECDH("secp384r1");
  ecdh.generateKeys();
  const compressedKey = ecdh.getPublicKey(null, "compressed");

  const multicodecKey = new Uint8Array(P384_MULTICODEC_VARINT.length + compressedKey.length);
  multicodecKey.set(P384_MULTICODEC_VARINT, 0);
  multicodecKey.set(compressedKey, P384_MULTICODEC_VARINT.length);

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

  it("should resolve a valid Ed25519 did:key", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    const rawKey = Buffer.from(jwk.x!, "base64url");

    const prefix = new Uint8Array([0xed, 0x01]);
    const multicodecKey = new Uint8Array(prefix.length + rawKey.length);
    multicodecKey.set(prefix, 0);
    multicodecKey.set(rawKey, prefix.length);

    const multibase = "z" + encodeBase58btc(multicodecKey);
    const did = `did:key:${multibase}`;

    const result = await resolver.resolve(did);

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
    expect(result.didDocument!.verificationMethod).toHaveLength(1);

    const vm = result.didDocument!.verificationMethod![0];
    expect(vm.type).toBe("Multikey");
    expect(vm.controller).toBe(did);
    expect(vm.publicKeyMultibase).toBeDefined();
  });

  it("should reject Ed25519 key with invalid length", async () => {
    const prefix = new Uint8Array([0xed, 0x01]);
    const badKey = new Uint8Array(20); // should be 32
    const multicodecKey = new Uint8Array(prefix.length + badKey.length);
    multicodecKey.set(prefix, 0);
    multicodecKey.set(badKey, prefix.length);

    const multibase = "z" + encodeBase58btc(multicodecKey);
    const did = `did:key:${multibase}`;

    await expect(resolver.resolve(did)).rejects.toThrow("Invalid key length");
  });

  it("should reject unsupported key types (unknown multicodec)", async () => {
    const fakeKey = new Uint8Array(34);
    fakeKey[0] = 0xaa;
    fakeKey[1] = 0xbb;
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

    await expect(resolver.resolve(did)).rejects.toThrow("Invalid key length");
  });

  it("should reject P-256 key with invalid compression prefix", async () => {
    const badKey = new Uint8Array(35);
    badKey[0] = 0x80;
    badKey[1] = 0x24;
    badKey[2] = 0x05; // invalid: should be 0x02 or 0x03
    const multibase = "z" + encodeBase58btc(badKey);
    const did = `did:key:${multibase}`;

    await expect(resolver.resolve(did)).rejects.toThrow("Invalid compressed key");
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

  // P-384 tests
  it("should resolve a valid P-384 did:key", async () => {
    const { did } = createP384DID();
    const result = await resolver.resolve(did);

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
    expect(result.didDocument!.verificationMethod).toHaveLength(1);

    const vm = result.didDocument!.verificationMethod![0];
    expect(vm.type).toBe("Multikey");
    expect(vm.controller).toBe(did);
    expect(vm.publicKeyMultibase).toBeDefined();
    expect(vm.publicKeyMultibase!.startsWith("z")).toBe(true);
  });

  it("should resolve multiple different P-384 DIDs correctly", async () => {
    const { did: did1 } = createP384DID();
    const { did: did2 } = createP384DID();

    expect(did1).not.toBe(did2);

    const result1 = await resolver.resolve(did1);
    const result2 = await resolver.resolve(did2);

    expect(result1.didDocument!.id).toBe(did1);
    expect(result2.didDocument!.id).toBe(did2);
  });

  it("should reject P-384 key with invalid length", async () => {
    // P-384 prefix but only 33 bytes of key (should be 49)
    const shortKey = new Uint8Array(35);
    shortKey[0] = 0x81;
    shortKey[1] = 0x24;
    shortKey[2] = 0x02;
    const multibase = "z" + encodeBase58btc(shortKey);
    const did = `did:key:${multibase}`;

    await expect(resolver.resolve(did)).rejects.toThrow("Invalid key length");
  });
});

describe("deriveDidKeyId", () => {
  it("should derive a did:key ID from a P-256 KeyObject", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const id = deriveDidKeyId(publicKey);

    expect(id).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);
  });

  it("should derive a did:key ID from a P-384 KeyObject", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const id = deriveDidKeyId(publicKey);

    expect(id).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);
  });

  it("should produce deterministic output for the same key", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const id1 = deriveDidKeyId(publicKey);
    const id2 = deriveDidKeyId(publicKey);
    expect(id1).toBe(id2);
  });

  it("should produce different IDs for different keys", () => {
    const { publicKey: key1 } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const { publicKey: key2 } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(deriveDidKeyId(key1)).not.toBe(deriveDidKeyId(key2));
  });

  it("P-256 and P-384 IDs should differ for different curves", () => {
    const { publicKey: p256 } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const { publicKey: p384 } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    expect(deriveDidKeyId(p256)).not.toBe(deriveDidKeyId(p384));
  });

  it("derived ID should be resolvable by DIDKeyResolver", async () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const id = deriveDidKeyId(publicKey);
    const did = id.split("#")[0];

    const resolver = new DIDKeyResolver();
    const result = await resolver.resolve(did);
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
  });

  it("P-384 derived ID should be resolvable by DIDKeyResolver", async () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const id = deriveDidKeyId(publicKey);
    const did = id.split("#")[0];

    const resolver = new DIDKeyResolver();
    const result = await resolver.resolve(did);
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
  });

  it("should derive a did:key ID from an Ed25519 KeyObject", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const id = deriveDidKeyId(publicKey);

    expect(id).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);
  });

  it("Ed25519 derived ID should be deterministic", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const id1 = deriveDidKeyId(publicKey);
    const id2 = deriveDidKeyId(publicKey);
    expect(id1).toBe(id2);
  });

  it("Ed25519 derived ID should be resolvable by DIDKeyResolver", async () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const id = deriveDidKeyId(publicKey);
    const did = id.split("#")[0];

    const resolver = new DIDKeyResolver();
    const result = await resolver.resolve(did);
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
  });

  it("Ed25519 and P-256 IDs should differ", () => {
    const { publicKey: ed25519Key } = generateKeyPairSync("ed25519");
    const { publicKey: p256Key } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(deriveDidKeyId(ed25519Key)).not.toBe(deriveDidKeyId(p256Key));
  });
});

describe("deriveDidKeyIdFromCompressedKey", () => {
  it("should derive from a P-256 compressed key", () => {
    const ecdh = createECDH("prime256v1");
    ecdh.generateKeys();
    const compressed = new Uint8Array(ecdh.getPublicKey(null, "compressed"));
    const id = deriveDidKeyIdFromCompressedKey(compressed, "P-256");

    expect(id).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);
  });

  it("should derive from a P-384 compressed key", () => {
    const ecdh = createECDH("secp384r1");
    ecdh.generateKeys();
    const compressed = new Uint8Array(ecdh.getPublicKey(null, "compressed"));
    const id = deriveDidKeyIdFromCompressedKey(compressed, "P-384");

    expect(id).toMatch(/^did:key:z[a-zA-Z0-9]+#z[a-zA-Z0-9]+$/);
  });

  it("should match deriveDidKeyId output for the same P-256 key", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const compressed = getCompressedPublicKey(publicKey);

    const fromKeyObject = deriveDidKeyId(publicKey);
    const fromCompressed = deriveDidKeyIdFromCompressedKey(compressed, "P-256");
    expect(fromKeyObject).toBe(fromCompressed);
  });

  it("should reject wrong length for P-256", () => {
    const badKey = new Uint8Array(49); // P-384 length
    badKey[0] = 0x02;
    expect(() => deriveDidKeyIdFromCompressedKey(badKey, "P-256")).toThrow("Invalid compressed");
  });
});

describe("getCompressedPublicKey", () => {
  it("should return 33 bytes for P-256", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const compressed = getCompressedPublicKey(publicKey);
    expect(compressed.length).toBe(33);
    expect(compressed[0] === 0x02 || compressed[0] === 0x03).toBe(true);
  });

  it("should return 49 bytes for P-384", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const compressed = getCompressedPublicKey(publicKey);
    expect(compressed.length).toBe(49);
    expect(compressed[0] === 0x02 || compressed[0] === 0x03).toBe(true);
  });
});

describe("computeKeyFingerprint", () => {
  it("should return a hex SHA-256 string", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const fp = computeKeyFingerprint(publicKey);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should be deterministic", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(computeKeyFingerprint(publicKey)).toBe(computeKeyFingerprint(publicKey));
  });

  it("should differ for different keys", () => {
    const { publicKey: k1 } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const { publicKey: k2 } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(computeKeyFingerprint(k1)).not.toBe(computeKeyFingerprint(k2));
  });

  it("should work for RSA keys too", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const fp = computeKeyFingerprint(publicKey);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });
});
