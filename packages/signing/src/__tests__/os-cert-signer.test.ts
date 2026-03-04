/**
 * Tests for the OS certificate store signer.
 *
 * Since native addons (macOS Security.framework, Windows CNG) cannot be
 * assumed available in CI, these tests use mock providers that simulate
 * the OsCertProvider interface. Tests verify:
 *
 *  - Platform dispatch (darwin -> macOS, win32 -> Windows, linux -> error)
 *  - Signer creation with correct metadata (did:key derivation, fingerprint)
 *  - Multi-algorithm support: P-256, P-384 (did:key), RSA-2048 (did:jwk)
 *  - Signature format validation (algorithm-dependent)
 *  - Certificate chain attachment to signer metadata
 *  - Error handling (unsupported platform, missing certificate, etc.)
 *  - Security invariants (no key material in errors)
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign, createHash } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type { OsCertProvider, OsCertInfo } from "../os-cert-types.js";
import {
  createOsCertSigner,
  listOsCertificates,
  getProviderForPlatform,
} from "../os-cert-signer.js";

// ---------------------------------------------------------------------------
// Generate real key pairs for testing
// ---------------------------------------------------------------------------

// P-256
const p256KeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const p256Jwk = p256KeyPair.publicKey.export({ format: "jwk" });
const p256XBytes = Buffer.from(p256Jwk.x!, "base64url");
const p256YBytes = Buffer.from(p256Jwk.y!, "base64url");

const compressedP256Key = new Uint8Array(33);
compressedP256Key[0] = p256YBytes[p256YBytes.length - 1] % 2 === 0 ? 0x02 : 0x03;
compressedP256Key.set(p256XBytes, 1);

// P-384
const p384KeyPair = generateKeyPairSync("ec", { namedCurve: "P-384" });
const p384Jwk = p384KeyPair.publicKey.export({ format: "jwk" });
const p384XBytes = Buffer.from(p384Jwk.x!, "base64url");
const p384YBytes = Buffer.from(p384Jwk.y!, "base64url");

const compressedP384Key = new Uint8Array(49);
compressedP384Key[0] = p384YBytes[p384YBytes.length - 1] % 2 === 0 ? 0x02 : 0x03;
compressedP384Key.set(p384XBytes, 1);

// RSA-2048
const rsaKeyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsaSpkiDer = rsaKeyPair.publicKey.export({ format: "der", type: "spki" });

// ---------------------------------------------------------------------------
// Mock certificate infos
// ---------------------------------------------------------------------------

const testCertInfoP256: OsCertInfo = {
  id: "test-cert-p256",
  subject: "CN=Test User P256",
  issuer: "CN=Test CA",
  serialNumber: "0102030405",
  validFrom: "2024-01-01T00:00:00Z",
  validUntil: "2030-12-31T23:59:59Z",
  keyAlgorithm: "P-256",
  isExportable: false,
  thumbprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
};

const mockCertChain = [
  "-----BEGIN CERTIFICATE-----\nMIIB...mock-dsc...\n-----END CERTIFICATE-----",
  "-----BEGIN CERTIFICATE-----\nMIIB...mock-intermediate...\n-----END CERTIFICATE-----",
];

// ---------------------------------------------------------------------------
// Mock provider factory
// ---------------------------------------------------------------------------

function createMockProvider(options?: {
  certificates?: OsCertInfo[];
  signatureOverride?: Uint8Array;
  publicKeyOverride?: Uint8Array;
  certificateChain?: string[];
  supportsCertChain?: boolean;
  throwOnSign?: boolean;
  throwOnList?: boolean;
  throwOnGetPublicKey?: boolean;
}): OsCertProvider {
  const provider: OsCertProvider = {
    async listCertificates(): Promise<OsCertInfo[]> {
      if (options?.throwOnList) {
        throw new CryptoError("Mock list error");
      }
      return options?.certificates ?? [testCertInfoP256];
    },

    async sign(_certificateId: string, data: Uint8Array): Promise<Uint8Array> {
      if (options?.throwOnSign) {
        throw new CryptoError("Mock sign error");
      }
      if (options?.signatureOverride) {
        return options.signatureOverride;
      }

      // Default: sign with P-256 key
      const hash = createHash("sha256").update(data).digest();
      const signer = createSign("SHA256");
      signer.update(hash);
      const derSig = signer.sign({
        key: p256KeyPair.privateKey,
        dsaEncoding: "ieee-p1363",
      });
      return new Uint8Array(derSig);
    },

    async getPublicKey(_certificateId: string): Promise<Uint8Array> {
      if (options?.throwOnGetPublicKey) {
        throw new CryptoError("Mock getPublicKey error");
      }
      return options?.publicKeyOverride ?? compressedP256Key;
    },
  };

  // Add getCertificateChain if supported
  if (options?.supportsCertChain !== false) {
    provider.getCertificateChain = async (_certificateId: string): Promise<string[]> => {
      return options?.certificateChain ?? [];
    };
  }

  return provider;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("OS Certificate Store Signer", () => {
  describe("getProviderForPlatform", () => {
    it("should throw CryptoError for linux platform", () => {
      expect(() => getProviderForPlatform("linux")).toThrow(CryptoError);
      expect(() => getProviderForPlatform("linux")).toThrow(
        /Linux does not have a native OS certificate store/,
      );
    });

    it("should accept a provider override for any platform", () => {
      const mockProvider = createMockProvider();
      const provider = getProviderForPlatform("darwin", mockProvider);
      expect(provider).toBe(mockProvider);
    });

    it("should accept a provider override for linux", () => {
      const mockProvider = createMockProvider();
      const provider = getProviderForPlatform("linux", mockProvider);
      expect(provider).toBe(mockProvider);
    });
  });

  describe("listOsCertificates", () => {
    it("should return certificates with platform metadata", async () => {
      const mockProvider = createMockProvider();
      const result = await listOsCertificates("darwin", mockProvider);

      expect(result.certificates).toHaveLength(1);
      expect(result.certificates[0].id).toBe("test-cert-p256");
      expect(result.certificates[0].subject).toBe("CN=Test User P256");
      expect(result.platform).toBe("darwin");
      expect(result.storeName).toBe("macOS Keychain");
    });

    it("should return correct store name for windows", async () => {
      const mockProvider = createMockProvider();
      const result = await listOsCertificates("win32", mockProvider);

      expect(result.platform).toBe("win32");
      expect(result.storeName).toBe("Windows Certificate Store");
    });

    it("should propagate errors from the provider", async () => {
      const mockProvider = createMockProvider({ throwOnList: true });
      await expect(listOsCertificates("darwin", mockProvider)).rejects.toThrow(CryptoError);
    });

    it("should return empty array when no certificates found", async () => {
      const mockProvider = createMockProvider({ certificates: [] });
      const result = await listOsCertificates("darwin", mockProvider);

      expect(result.certificates).toHaveLength(0);
    });
  });

  describe("createOsCertSigner — P-256 (default)", () => {
    it("should create a signer with correct metadata", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-p256",
          label: "My macOS Cert",
        },
        mockProvider,
      );

      expect(signer).toBeDefined();
      expect(signer.algorithm).toBe("P-256");
      expect(signer.type).toBe("os-cert");
      expect(signer.id).toMatch(/^did:key:z/);
      expect(signer.id).toContain("#");
      expect(signer.metadata.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(signer.metadata.type).toBe("os-cert");
      expect(signer.metadata.label).toBe("My macOS Cert");
    });

    it("should produce a valid did:key ID", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      const [did, fragment] = signer.id.split("#");
      expect(did).toMatch(/^did:key:z[a-zA-Z0-9]+$/);
      expect(fragment).toBe(did.replace("did:key:", ""));
    });

    it("should produce a deterministic fingerprint", async () => {
      const mockProvider = createMockProvider();

      const { signer: signer1 } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      const { signer: signer2 } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      expect(signer1.metadata.fingerprint).toBe(signer2.metadata.fingerprint);
      expect(signer1.id).toBe(signer2.id);
    });

    it("should produce a 64-byte signature from sign()", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      testData.fill(0xab);

      const signature = await signer.sign(testData);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
    });

    it("should produce non-zero signatures", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      testData.fill(0xcd);

      const signature = await signer.sign(testData);
      const r = signature.slice(0, 32);
      const s = signature.slice(32, 64);
      const allZeroR = r.every((b) => b === 0);
      const allZeroS = s.every((b) => b === 0);
      expect(allZeroR && allZeroS).toBe(false);
    });

    it("should throw CryptoError on signing failure", async () => {
      const mockProvider = createMockProvider({ throwOnSign: true });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      await expect(signer.sign(testData)).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError if public key extraction fails", async () => {
      const mockProvider = createMockProvider({ throwOnGetPublicKey: true });

      await expect(
        createOsCertSigner({ platform: "darwin", certificateId: "test-cert-p256" }, mockProvider),
      ).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError for invalid public key length", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(32), // Wrong length
      });

      await expect(
        createOsCertSigner({ platform: "darwin", certificateId: "test-cert-p256" }, mockProvider),
      ).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError for linux platform without provider", async () => {
      await expect(
        createOsCertSigner({
          platform: "linux",
          certificateId: "test-cert-p256",
        }),
      ).rejects.toThrow(CryptoError);
    });

    it("should work with win32 platform via mock provider", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "win32", certificateId: "test-cert-p256" },
        mockProvider,
      );

      expect(signer).toBeDefined();
      expect(signer.type).toBe("os-cert");
      expect(signer.algorithm).toBe("P-256");
    });

    it("should not include key material in signer metadata", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      const meta = signer.metadata;
      expect(meta.id).toMatch(/^did:key:/);
      expect(meta.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(meta.algorithm).toBe("P-256");
      expect(meta.type).toBe("os-cert");
      expect(JSON.stringify(meta)).not.toContain("privateKey");
      expect(JSON.stringify(meta)).not.toContain("secret");
    });

    it("should reject signatures with wrong length", async () => {
      const mockProvider = createMockProvider({
        signatureOverride: new Uint8Array(48), // Wrong length for P-256
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      await expect(signer.sign(testData)).rejects.toThrow(CryptoError);
      await expect(signer.sign(testData)).rejects.toThrow(/expected 64 bytes/);
    });
  });

  describe("createOsCertSigner — P-384", () => {
    it("should create a P-384 signer with did:key ID", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: compressedP384Key,
        // P-384 signature: 96 bytes
        signatureOverride: new Uint8Array(96).fill(0xcc),
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-p384",
          keyAlgorithm: "P-384",
        },
        mockProvider,
      );

      expect(signer.algorithm).toBe("P-384");
      expect(signer.id).toMatch(/^did:key:z/);
      expect(signer.id).toContain("#");
      expect(signer.metadata.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should produce a 96-byte signature for P-384", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: compressedP384Key,
        signatureOverride: new Uint8Array(96).fill(0xdd),
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-p384",
          keyAlgorithm: "P-384",
        },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      const signature = await signer.sign(testData);
      expect(signature.length).toBe(96);
    });

    it("should reject wrong-length signatures for P-384", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: compressedP384Key,
        signatureOverride: new Uint8Array(64), // Wrong for P-384
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-p384",
          keyAlgorithm: "P-384",
        },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      await expect(signer.sign(testData)).rejects.toThrow(/expected 96 bytes/);
    });
  });

  describe("createOsCertSigner — RSA", () => {
    it("should create an RSA signer with did:jwk ID", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(rsaSpkiDer),
        signatureOverride: new Uint8Array(256).fill(0xee), // RSA-2048 = 256 byte sig
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-rsa",
          keyAlgorithm: "RSA-2048",
        },
        mockProvider,
      );

      expect(signer.algorithm).toBe("RSA-2048");
      expect(signer.id).toMatch(/^did:jwk:/);
      expect(signer.id).toContain("#0");
      expect(signer.metadata.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });

    it("should produce a valid signature for RSA", async () => {
      const rsaSig = new Uint8Array(256).fill(0xff);
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(rsaSpkiDer),
        signatureOverride: rsaSig,
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-rsa",
          keyAlgorithm: "RSA-2048",
        },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      const signature = await signer.sign(testData);
      expect(signature.length).toBe(256);
    });

    it("should reject empty RSA signatures", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(rsaSpkiDer),
        signatureOverride: new Uint8Array(0),
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-rsa",
          keyAlgorithm: "RSA-2048",
        },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      await expect(signer.sign(testData)).rejects.toThrow(/empty signature/);
    });

    it("should not include key material in RSA signer metadata", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(rsaSpkiDer),
        signatureOverride: new Uint8Array(256).fill(0xaa),
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-rsa",
          keyAlgorithm: "RSA-2048",
        },
        mockProvider,
      );

      const meta = signer.metadata;
      expect(meta.id).toMatch(/^did:jwk:/);
      expect(JSON.stringify(meta)).not.toContain("privateKey");
      expect(JSON.stringify(meta)).not.toContain("secret");
    });
  });

  describe("DID derivation dispatch", () => {
    it("should use did:key for EC keys (P-256)", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: compressedP256Key,
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256", keyAlgorithm: "P-256" },
        mockProvider,
      );

      expect(signer.id).toMatch(/^did:key:z/);
    });

    it("should use did:key for EC keys (P-384)", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: compressedP384Key,
        signatureOverride: new Uint8Array(96).fill(0xaa),
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p384", keyAlgorithm: "P-384" },
        mockProvider,
      );

      expect(signer.id).toMatch(/^did:key:z/);
    });

    it("should use did:jwk for RSA keys", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(rsaSpkiDer),
        signatureOverride: new Uint8Array(256).fill(0xbb),
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-rsa", keyAlgorithm: "RSA-2048" },
        mockProvider,
      );

      expect(signer.id).toMatch(/^did:jwk:/);
    });
  });

  describe("certificate chain attachment", () => {
    it("should attach certificate chain to metadata when available", async () => {
      const mockProvider = createMockProvider({
        certificateChain: mockCertChain,
        supportsCertChain: true,
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      expect(signer.metadata.certificateChain).toEqual(mockCertChain);
      expect(signer.metadata.certificateChain).toHaveLength(2);
    });

    it("should not attach certificate chain when empty", async () => {
      const mockProvider = createMockProvider({
        certificateChain: [],
        supportsCertChain: true,
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      expect(signer.metadata.certificateChain).toBeUndefined();
    });

    it("should handle providers without getCertificateChain support", async () => {
      const mockProvider = createMockProvider({
        supportsCertChain: false,
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-p256" },
        mockProvider,
      );

      expect(signer.metadata.certificateChain).toBeUndefined();
    });

    it("should attach chain to RSA signer metadata", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(rsaSpkiDer),
        signatureOverride: new Uint8Array(256).fill(0xcc),
        certificateChain: mockCertChain,
        supportsCertChain: true,
      });

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-rsa",
          keyAlgorithm: "RSA-2048",
        },
        mockProvider,
      );

      expect(signer.metadata.certificateChain).toEqual(mockCertChain);
    });
  });
});
