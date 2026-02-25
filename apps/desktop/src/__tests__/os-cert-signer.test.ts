/**
 * Tests for the OS certificate store signer.
 *
 * Since native addons (macOS Security.framework, Windows CNG) cannot be
 * assumed available in CI, these tests use mock providers that simulate
 * the OsCertProvider interface. Tests verify:
 *
 *  - Platform dispatch (darwin -> macOS, win32 -> Windows, linux -> error)
 *  - Signer creation with correct metadata (did:key derivation, fingerprint)
 *  - Signature format validation (64-byte raw r||s for P-256)
 *  - Error handling (unsupported platform, missing certificate, etc.)
 *  - Security invariants (no key material in errors)
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign, createHash } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type { OsCertProvider, OsCertInfo } from "../signing/os-cert-types.js";
import {
  createOsCertSigner,
  listOsCertificates,
  getProviderForPlatform,
} from "../signing/os-cert-signer.js";

// ---------------------------------------------------------------------------
// Generate a real EC key pair for testing
// ---------------------------------------------------------------------------

const testKeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const testPublicKeyJwk = testKeyPair.publicKey.export({ format: "jwk" });
const xBytes = Buffer.from(testPublicKeyJwk.x!, "base64url");
const yBytes = Buffer.from(testPublicKeyJwk.y!, "base64url");

/**
 * SEC1 compressed public key (33 bytes: prefix + x coordinate).
 * The prefix is 0x02 if y is even, 0x03 if y is odd.
 */
const compressedPublicKey = new Uint8Array(33);
compressedPublicKey[0] = yBytes[yBytes.length - 1] % 2 === 0 ? 0x02 : 0x03;
compressedPublicKey.set(xBytes, 1);

/**
 * Mock test certificate info.
 */
const testCertInfo: OsCertInfo = {
  id: "test-cert-id-001",
  subject: "CN=Test User",
  issuer: "CN=Test CA",
  serialNumber: "0102030405",
  validFrom: "2024-01-01T00:00:00Z",
  validUntil: "2030-12-31T23:59:59Z",
  keyAlgorithm: "ECDSA P-256",
  isExportable: false,
  thumbprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
};

/**
 * Create a mock OsCertProvider that uses the real test key pair for signing.
 */
function createMockProvider(options?: {
  certificates?: OsCertInfo[];
  signatureOverride?: Uint8Array;
  publicKeyOverride?: Uint8Array;
  throwOnSign?: boolean;
  throwOnList?: boolean;
  throwOnGetPublicKey?: boolean;
}): OsCertProvider {
  return {
    async listCertificates(): Promise<OsCertInfo[]> {
      if (options?.throwOnList) {
        throw new CryptoError("Mock list error");
      }
      return options?.certificates ?? [testCertInfo];
    },

    async sign(_certificateId: string, data: Uint8Array): Promise<Uint8Array> {
      if (options?.throwOnSign) {
        throw new CryptoError("Mock sign error");
      }
      if (options?.signatureOverride) {
        return options.signatureOverride;
      }

      // Hash the data with SHA-256, then sign with ECDSA
      const hash = createHash("sha256").update(data).digest();
      const signer = createSign("SHA256");
      signer.update(hash);
      const derSig = signer.sign({
        key: testKeyPair.privateKey,
        dsaEncoding: "ieee-p1363",
      });
      return new Uint8Array(derSig);
    },

    async getPublicKey(_certificateId: string): Promise<Uint8Array> {
      if (options?.throwOnGetPublicKey) {
        throw new CryptoError("Mock getPublicKey error");
      }
      return options?.publicKeyOverride ?? compressedPublicKey;
    },
  };
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
      // With an override, even linux should work
      const provider = getProviderForPlatform("linux", mockProvider);
      expect(provider).toBe(mockProvider);
    });
  });

  describe("listOsCertificates", () => {
    it("should return certificates with platform metadata", async () => {
      const mockProvider = createMockProvider();
      const result = await listOsCertificates("darwin", mockProvider);

      expect(result.certificates).toHaveLength(1);
      expect(result.certificates[0].id).toBe("test-cert-id-001");
      expect(result.certificates[0].subject).toBe("CN=Test User");
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

  describe("createOsCertSigner", () => {
    it("should create a signer with correct metadata", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        {
          platform: "darwin",
          certificateId: "test-cert-id-001",
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
        { platform: "darwin", certificateId: "test-cert-id-001" },
        mockProvider,
      );

      // did:key format: did:key:z<multibase>#z<multibase>
      const [did, fragment] = signer.id.split("#");
      expect(did).toMatch(/^did:key:z[a-zA-Z0-9]+$/);
      expect(fragment).toBe(did.replace("did:key:", ""));
    });

    it("should produce a deterministic fingerprint", async () => {
      const mockProvider = createMockProvider();

      const { signer: signer1 } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-id-001" },
        mockProvider,
      );

      const { signer: signer2 } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-id-001" },
        mockProvider,
      );

      expect(signer1.metadata.fingerprint).toBe(signer2.metadata.fingerprint);
      expect(signer1.id).toBe(signer2.id);
    });

    it("should produce a 64-byte signature from sign()", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-id-001" },
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
        { platform: "darwin", certificateId: "test-cert-id-001" },
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
        { platform: "darwin", certificateId: "test-cert-id-001" },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      await expect(signer.sign(testData)).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError if public key extraction fails", async () => {
      const mockProvider = createMockProvider({ throwOnGetPublicKey: true });

      await expect(
        createOsCertSigner({ platform: "darwin", certificateId: "test-cert-id-001" }, mockProvider),
      ).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError for invalid public key length", async () => {
      const mockProvider = createMockProvider({
        publicKeyOverride: new Uint8Array(32), // Wrong length
      });

      await expect(
        createOsCertSigner({ platform: "darwin", certificateId: "test-cert-id-001" }, mockProvider),
      ).rejects.toThrow(CryptoError);
    });

    it("should throw CryptoError for linux platform without provider", async () => {
      await expect(
        createOsCertSigner({
          platform: "linux",
          certificateId: "test-cert-id-001",
        }),
      ).rejects.toThrow(CryptoError);
    });

    it("should work with win32 platform via mock provider", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "win32", certificateId: "test-cert-id-001" },
        mockProvider,
      );

      expect(signer).toBeDefined();
      expect(signer.type).toBe("os-cert");
      expect(signer.algorithm).toBe("P-256");
    });

    it("should not include key material in signer metadata", async () => {
      const mockProvider = createMockProvider();

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-id-001" },
        mockProvider,
      );

      // Metadata should only contain safe-to-display information
      const meta = signer.metadata;
      expect(meta.id).toMatch(/^did:key:/);
      expect(meta.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(meta.algorithm).toBe("P-256");
      expect(meta.type).toBe("os-cert");
      // No private key material anywhere
      expect(JSON.stringify(meta)).not.toContain("privateKey");
      expect(JSON.stringify(meta)).not.toContain("secret");
    });

    it("should reject signatures with wrong length", async () => {
      const mockProvider = createMockProvider({
        signatureOverride: new Uint8Array(48), // Wrong length
      });

      const { signer } = await createOsCertSigner(
        { platform: "darwin", certificateId: "test-cert-id-001" },
        mockProvider,
      );

      const testData = new Uint8Array(64);
      await expect(signer.sign(testData)).rejects.toThrow(CryptoError);
      await expect(signer.sign(testData)).rejects.toThrow(/expected 64 bytes/);
    });
  });
});
