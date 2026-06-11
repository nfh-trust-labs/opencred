import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { CryptoError } from "@opencred/shared";
import { LocalSigningKeyProvider } from "../signing-key-provider.js";
import type { SigningKeyProvider } from "../signing-key-provider.js";

/**
 * Generate a PEM-encoded ECDSA P-256 private key for testing.
 */
function generateTestPem(): string {
  const { privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey as unknown as string;
}

describe("LocalSigningKeyProvider — key generation", () => {
  it("should auto-generate a P-256 key pair when no options are provided", () => {
    const provider = new LocalSigningKeyProvider();
    const key = provider.getActiveKey();

    expect(key.algorithm).toBe("P-256");
    expect(key.privateKey).toBeDefined();
    expect(key.publicKey).toBeDefined();
    expect(key.id).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+#z[1-9A-HJ-NP-Za-km-z]+$/);
  });

  it("should produce unique keys on each instantiation", () => {
    const provider1 = new LocalSigningKeyProvider();
    const provider2 = new LocalSigningKeyProvider();

    expect(provider1.getActiveKey().id).not.toBe(provider2.getActiveKey().id);
  });

  it("should list exactly one key after construction", () => {
    const provider = new LocalSigningKeyProvider();
    const keys = provider.listKeys();

    expect(keys).toHaveLength(1);
    expect(keys[0].isActive).toBe(true);
    expect(keys[0].algorithm).toBe("P-256");
    expect(keys[0].createdAt).toBeDefined();
    expect(new Date(keys[0].createdAt).toISOString()).toBe(keys[0].createdAt);
  });
});

describe("LocalSigningKeyProvider — PEM loading", () => {
  it("should load a key from a PEM string", () => {
    const pem = generateTestPem();
    const provider = new LocalSigningKeyProvider({ privateKeyPem: pem });
    const key = provider.getActiveKey();

    expect(key.algorithm).toBe("P-256");
    expect(key.id).toMatch(/^did:key:z/);
  });

  it("should produce a deterministic key ID from the same PEM", () => {
    const pem = generateTestPem();
    const provider1 = new LocalSigningKeyProvider({ privateKeyPem: pem });
    const provider2 = new LocalSigningKeyProvider({ privateKeyPem: pem });

    expect(provider1.getActiveKey().id).toBe(provider2.getActiveKey().id);
  });

  it("should load a key from a file path", () => {
    const pem = generateTestPem();
    const dir = join(tmpdir(), `opencred-test-${Date.now()}`);
    const keyPath = join(dir, "test-key.pem");

    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(keyPath, pem);

      const provider = new LocalSigningKeyProvider({ privateKeyPath: keyPath });
      const key = provider.getActiveKey();

      expect(key.algorithm).toBe("P-256");
      expect(key.id).toMatch(/^did:key:z/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("should reject non-P-256 PEM keys", () => {
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "secp384r1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    expect(
      () => new LocalSigningKeyProvider({ privateKeyPem: privateKey as unknown as string }),
    ).toThrow(CryptoError);
    expect(
      () => new LocalSigningKeyProvider({ privateKeyPem: privateKey as unknown as string }),
    ).toThrow("Only P-256 is supported");
  });

  it("should reject invalid PEM data", () => {
    expect(() => new LocalSigningKeyProvider({ privateKeyPem: "not-a-pem" })).toThrow(CryptoError);
    expect(() => new LocalSigningKeyProvider({ privateKeyPem: "not-a-pem" })).toThrow(
      "Failed to load signing key from PEM",
    );
  });

  it("should reject non-existent file path", () => {
    expect(
      () => new LocalSigningKeyProvider({ privateKeyPath: "/nonexistent/path/key.pem" }),
    ).toThrow();
  });
});

describe("LocalSigningKeyProvider — signing and verification round-trip", () => {
  it("should sign data and produce a 64-byte P-256 signature", () => {
    const provider = new LocalSigningKeyProvider();
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    const signature = provider.sign(data);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });

  it("should produce signatures that verify with the corresponding public key", () => {
    const provider = new LocalSigningKeyProvider();
    const key = provider.getActiveKey();
    const data = new Uint8Array(Buffer.from("test data for signing"));

    const signature = provider.sign(data);

    // Verify using Node.js crypto
    const verifier = createVerify("SHA256");
    verifier.update(data);
    const verified = verifier.verify({ key: key.publicKey, dsaEncoding: "ieee-p1363" }, signature);

    expect(verified).toBe(true);
  });

  it("should produce different signatures for different data", () => {
    const provider = new LocalSigningKeyProvider();
    const data1 = new Uint8Array([1, 2, 3]);
    const data2 = new Uint8Array([4, 5, 6]);

    const sig1 = provider.sign(data1);
    const sig2 = provider.sign(data2);

    expect(sig1).not.toEqual(sig2);
  });

  it("should sign with a specific key ID", () => {
    const provider = new LocalSigningKeyProvider();
    const key = provider.getActiveKey();
    const data = new Uint8Array([1, 2, 3]);

    const signature = provider.sign(data, key.id);

    const verifier = createVerify("SHA256");
    verifier.update(data);
    const verified = verifier.verify({ key: key.publicKey, dsaEncoding: "ieee-p1363" }, signature);

    expect(verified).toBe(true);
  });

  it("should throw CryptoError for unknown key ID in sign()", () => {
    const provider = new LocalSigningKeyProvider();

    expect(() => provider.sign(new Uint8Array([1, 2, 3]), "did:key:unknown#unknown")).toThrow(
      CryptoError,
    );
    expect(() => provider.sign(new Uint8Array([1, 2, 3]), "did:key:unknown#unknown")).toThrow(
      "Unknown key ID",
    );
  });
});

describe("LocalSigningKeyProvider — key rotation", () => {
  it("should generate a new active key on rotation", () => {
    const provider = new LocalSigningKeyProvider();
    const originalKey = provider.getActiveKey();

    const newKey = provider.rotateKey();

    expect(newKey.id).not.toBe(originalKey.id);
    expect(provider.getActiveKey().id).toBe(newKey.id);
  });

  it("should keep old key available after rotation", () => {
    const provider = new LocalSigningKeyProvider();
    const originalKey = provider.getActiveKey();

    provider.rotateKey();

    const retrieved = provider.getKeyById(originalKey.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(originalKey.id);
  });

  it("should list all keys after rotation", () => {
    const provider = new LocalSigningKeyProvider();
    const originalId = provider.getActiveKey().id;

    provider.rotateKey();

    const keys = provider.listKeys();
    expect(keys).toHaveLength(2);

    const activeKeys = keys.filter((k) => k.isActive);
    expect(activeKeys).toHaveLength(1);
    expect(activeKeys[0].id).not.toBe(originalId);

    const inactiveKeys = keys.filter((k) => !k.isActive);
    expect(inactiveKeys).toHaveLength(1);
    expect(inactiveKeys[0].id).toBe(originalId);
  });

  it("should still verify old signatures after rotation", () => {
    const provider = new LocalSigningKeyProvider();
    const originalKey = provider.getActiveKey();
    const data = new Uint8Array(Buffer.from("signed before rotation"));

    // Sign with original key
    const signature = provider.sign(data);

    // Rotate
    provider.rotateKey();

    // Verify old signature using original key
    const verifier = createVerify("SHA256");
    verifier.update(data);
    const verified = verifier.verify(
      { key: originalKey.publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );

    expect(verified).toBe(true);
  });

  it("should sign with new key after rotation", () => {
    const provider = new LocalSigningKeyProvider();
    provider.rotateKey();

    const newKey = provider.getActiveKey();
    const data = new Uint8Array(Buffer.from("signed after rotation"));

    const signature = provider.sign(data);

    const verifier = createVerify("SHA256");
    verifier.update(data);
    const verified = verifier.verify(
      { key: newKey.publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );

    expect(verified).toBe(true);
  });

  it("should allow signing with old key by explicit ID after rotation", () => {
    const provider = new LocalSigningKeyProvider();
    const originalKey = provider.getActiveKey();

    provider.rotateKey();

    const data = new Uint8Array(Buffer.from("explicit old key signing"));
    const signature = provider.sign(data, originalKey.id);

    const verifier = createVerify("SHA256");
    verifier.update(data);
    const verified = verifier.verify(
      { key: originalKey.publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );

    expect(verified).toBe(true);
  });

  it("should support multiple rotations", () => {
    const provider = new LocalSigningKeyProvider();

    provider.rotateKey();
    provider.rotateKey();
    provider.rotateKey();

    const keys = provider.listKeys();
    expect(keys).toHaveLength(4);

    const activeKeys = keys.filter((k) => k.isActive);
    expect(activeKeys).toHaveLength(1);
  });
});

describe("LocalSigningKeyProvider — did:key format", () => {
  it("should produce a valid did:key identifier", () => {
    const provider = new LocalSigningKeyProvider();
    const key = provider.getActiveKey();

    // Format: did:key:z<multibase>#z<multibase>
    const parts = key.id.split("#");
    expect(parts).toHaveLength(2);

    const did = parts[0];
    const fragment = parts[1];

    expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    expect(fragment).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/);

    // The fragment should match the method-specific identifier
    expect(did).toBe(`did:key:${fragment}`);
  });

  it("should produce different did:key IDs for different keys", () => {
    const provider = new LocalSigningKeyProvider();
    const key1 = provider.getActiveKey();
    const key2 = provider.rotateKey();

    expect(key1.id).not.toBe(key2.id);
  });

  it("should produce deterministic did:key IDs from the same key material", () => {
    const pem = generateTestPem();
    const provider1 = new LocalSigningKeyProvider({ privateKeyPem: pem });
    const provider2 = new LocalSigningKeyProvider({ privateKeyPem: pem });

    expect(provider1.getActiveKey().id).toBe(provider2.getActiveKey().id);
  });
});

describe("LocalSigningKeyProvider — getKeyById", () => {
  it("should return the key for a valid ID", () => {
    const provider = new LocalSigningKeyProvider();
    const activeKey = provider.getActiveKey();

    const retrieved = provider.getKeyById(activeKey.id);

    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(activeKey.id);
    expect(retrieved!.algorithm).toBe("P-256");
  });

  it("should return undefined for an unknown ID", () => {
    const provider = new LocalSigningKeyProvider();

    const retrieved = provider.getKeyById("did:key:zNonexistent#zNonexistent");

    expect(retrieved).toBeUndefined();
  });

  it("should return rotated keys by ID", () => {
    const provider = new LocalSigningKeyProvider();
    const originalId = provider.getActiveKey().id;
    provider.rotateKey();

    const original = provider.getKeyById(originalId);
    expect(original).toBeDefined();
    expect(original!.id).toBe(originalId);
  });
});

describe("LocalSigningKeyProvider — getPublicKeyJwk", () => {
  it("should return a valid EC P-256 JWK", () => {
    const provider = new LocalSigningKeyProvider();
    const keyId = provider.getActiveKey().id;

    const jwk = provider.getPublicKeyJwk(keyId);

    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
    // base64url strings (no padding, no + or /)
    expect(jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(jwk.y).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("should not include private key material in JWK", () => {
    const provider = new LocalSigningKeyProvider();
    const keyId = provider.getActiveKey().id;

    const jwk = provider.getPublicKeyJwk(keyId) as unknown as Record<string, unknown>;

    expect(jwk).not.toHaveProperty("d");
  });

  it("should throw CryptoError for unknown key ID", () => {
    const provider = new LocalSigningKeyProvider();

    expect(() => provider.getPublicKeyJwk("did:key:zUnknown#zUnknown")).toThrow(CryptoError);
    expect(() => provider.getPublicKeyJwk("did:key:zUnknown#zUnknown")).toThrow("Unknown key ID");
  });

  it("should return consistent JWK for the same key", () => {
    const pem = generateTestPem();
    const provider1 = new LocalSigningKeyProvider({ privateKeyPem: pem });
    const provider2 = new LocalSigningKeyProvider({ privateKeyPem: pem });
    const keyId = provider1.getActiveKey().id;

    const jwk1 = provider1.getPublicKeyJwk(keyId);
    const jwk2 = provider2.getPublicKeyJwk(keyId);

    expect(jwk1).toEqual(jwk2);
  });
});

describe("SigningKeyProvider — interface contract", () => {
  function assertProviderContract(provider: SigningKeyProvider) {
    // getActiveKey returns a valid signing key
    const activeKey = provider.getActiveKey();
    expect(activeKey.id).toBeTruthy();
    expect(activeKey.algorithm).toBe("P-256");
    expect(activeKey.privateKey).toBeDefined();
    expect(activeKey.publicKey).toBeDefined();

    // getKeyById returns the active key
    const retrieved = provider.getKeyById(activeKey.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(activeKey.id);

    // getKeyById returns undefined for unknown
    expect(provider.getKeyById("nonexistent")).toBeUndefined();

    // listKeys includes the active key
    const keys = provider.listKeys();
    expect(keys.length).toBeGreaterThanOrEqual(1);
    expect(keys.some((k) => k.id === activeKey.id && k.isActive)).toBe(true);

    // getPublicKeyJwk returns a valid JWK
    const jwk = provider.getPublicKeyJwk(activeKey.id);
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");

    // sign produces a valid signature
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const sig = provider.sign(data);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);

    // Signature verifies with the active key's public key
    const verifier = createVerify("SHA256");
    verifier.update(data);
    expect(verifier.verify({ key: activeKey.publicKey, dsaEncoding: "ieee-p1363" }, sig)).toBe(
      true,
    );
  }

  it("should satisfy the contract with auto-generated key", () => {
    assertProviderContract(new LocalSigningKeyProvider());
  });

  it("should satisfy the contract with PEM-loaded key", () => {
    const pem = generateTestPem();
    assertProviderContract(new LocalSigningKeyProvider({ privateKeyPem: pem }));
  });

  it("should satisfy the contract after key rotation", () => {
    const provider = new LocalSigningKeyProvider();
    provider.rotateKey();
    assertProviderContract(provider);
  });
});
