import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  createSign,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { CryptoError } from "@opencred/shared";
import type { SigningKey } from "./types.js";
import { multibaseEncode } from "./data-integrity.js";

/** P-256 multicodec varint prefix (0x1200 in unsigned varint = [0x80, 0x24]). */
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

/**
 * Metadata about a managed signing key.
 */
export interface SigningKeyInfo {
  /** The key identifier (did:key verification method format). */
  id: string;
  /** The ECDSA curve. */
  algorithm: "P-256";
  /** ISO 8601 timestamp when the key was added to the provider. */
  createdAt: string;
  /** Whether this is the currently active signing key. */
  isActive: boolean;
}

/**
 * Public key in JWK format (EC P-256, public components only).
 */
export interface PublicKeyJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

/**
 * Pluggable interface for managing OpenCred's own signing keys.
 *
 * Implementations may store keys locally (dev), in environment variables,
 * or in a cloud KMS (production). This is NOT for issuer keys — issuers
 * never share their private keys with OpenCred.
 */
export interface SigningKeyProvider {
  /** Returns the current active signing key. */
  getActiveKey(): SigningKey;

  /** Returns a specific key by its ID, or undefined if not found. */
  getKeyById(keyId: string): SigningKey | undefined;

  /** Returns metadata for all managed keys (active + rotated). */
  listKeys(): SigningKeyInfo[];

  /** Returns the public key in JWK format for DeDi registration. */
  getPublicKeyJwk(keyId: string): PublicKeyJwk;

  /** Sign data with the specified key (defaults to active key). Returns raw r||s (64 bytes for P-256). */
  sign(data: Uint8Array, keyId?: string): Uint8Array;
}

/**
 * Configuration for the local signing key provider.
 */
export interface LocalSigningKeyProviderOptions {
  /** PEM-encoded ECDSA P-256 private key to load at startup. */
  privateKeyPem?: string;
  /** File path to a PEM-encoded ECDSA P-256 private key. */
  privateKeyPath?: string;
}

/**
 * Internal representation of a managed key with metadata.
 */
interface ManagedKey {
  signingKey: SigningKey;
  createdAt: string;
}

/**
 * Compute the SEC1 compressed public key bytes from a P-256 KeyObject.
 */
function getCompressedPublicKey(publicKey: KeyObject): Uint8Array {
  const jwk = publicKey.export({ format: "jwk" });
  if (!jwk.x || !jwk.y) {
    throw new CryptoError("Failed to export public key coordinates");
  }

  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");

  // SEC1 compressed form: 0x02 if y is even, 0x03 if y is odd
  const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
  const compressed = new Uint8Array(1 + x.length);
  compressed[0] = prefix;
  compressed.set(x, 1);
  return compressed;
}

/**
 * Derive a did:key verification method identifier from a P-256 public key.
 *
 * Format: `did:key:z<multibase>#z<multibase>` where the multibase value is
 * the base58btc encoding of the P-256 multicodec prefix + compressed public key.
 */
function deriveDidKeyId(publicKey: KeyObject): string {
  const compressed = getCompressedPublicKey(publicKey);

  const multicodecKey = new Uint8Array(P256_MULTICODEC_PREFIX.length + compressed.length);
  multicodecKey.set(P256_MULTICODEC_PREFIX, 0);
  multicodecKey.set(compressed, P256_MULTICODEC_PREFIX.length);

  const multibaseKey = multibaseEncode(multicodecKey);
  const did = `did:key:${multibaseKey}`;
  return `${did}#${multibaseKey}`;
}

/**
 * Local implementation of SigningKeyProvider for development and single-server deployments.
 *
 * Generates or loads ECDSA P-256 keys at construction time. Supports key rotation:
 * old keys remain available for verifying previously-issued credentials while the
 * new key is used for all new signing operations.
 *
 * Security:
 * - Private keys are held as KeyObject instances (never serialized or logged).
 * - Key generation uses Node.js CSPRNG via `generateKeyPairSync`.
 * - The `sign()` method produces IEEE P1363 (raw r||s) signatures.
 */
export class LocalSigningKeyProvider implements SigningKeyProvider {
  private readonly keys: Map<string, ManagedKey> = new Map();
  private activeKeyId: string;

  constructor(options?: LocalSigningKeyProviderOptions) {
    let signingKey: SigningKey;

    if (options?.privateKeyPem) {
      signingKey = loadFromPem(options.privateKeyPem);
    } else if (options?.privateKeyPath) {
      const pem = readFileSync(options.privateKeyPath, "utf-8");
      signingKey = loadFromPem(pem);
    } else {
      signingKey = generateSigningKey();
    }

    this.keys.set(signingKey.id, {
      signingKey,
      createdAt: new Date().toISOString(),
    });
    this.activeKeyId = signingKey.id;
  }

  getActiveKey(): SigningKey {
    const managed = this.keys.get(this.activeKeyId);
    if (!managed) {
      throw new CryptoError("No active signing key available");
    }
    return managed.signingKey;
  }

  getKeyById(keyId: string): SigningKey | undefined {
    return this.keys.get(keyId)?.signingKey;
  }

  listKeys(): SigningKeyInfo[] {
    return Array.from(this.keys.entries()).map(([id, managed]) => ({
      id,
      algorithm: "P-256" as const,
      createdAt: managed.createdAt,
      isActive: id === this.activeKeyId,
    }));
  }

  getPublicKeyJwk(keyId: string): PublicKeyJwk {
    const managed = this.keys.get(keyId);
    if (!managed) {
      throw new CryptoError(`Unknown key ID: ${keyId}`);
    }

    const jwk = managed.signingKey.publicKey.export({ format: "jwk" });
    return {
      kty: "EC",
      crv: "P-256",
      x: jwk.x!,
      y: jwk.y!,
    };
  }

  sign(data: Uint8Array, keyId?: string): Uint8Array {
    const id = keyId ?? this.activeKeyId;
    const managed = this.keys.get(id);
    if (!managed) {
      throw new CryptoError(`Unknown key ID: ${id}`);
    }

    const signer = createSign("SHA256");
    signer.update(data);
    const signature = signer.sign({
      key: managed.signingKey.privateKey,
      dsaEncoding: "ieee-p1363",
    });

    return new Uint8Array(signature);
  }

  /**
   * Generate a new key pair and make it the active key.
   * The previously active key remains available for verification of
   * credentials signed before the rotation.
   */
  rotateKey(): SigningKey {
    const newKey = generateSigningKey();

    this.keys.set(newKey.id, {
      signingKey: newKey,
      createdAt: new Date().toISOString(),
    });
    this.activeKeyId = newKey.id;

    return newKey;
  }
}

/**
 * Generate a new ECDSA P-256 signing key pair using CSPRNG.
 */
function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  const id = deriveDidKeyId(publicKey);
  return { id, privateKey, publicKey, algorithm: "P-256" };
}

/**
 * Load a signing key from a PEM-encoded private key string.
 * Only ECDSA P-256 keys are accepted.
 */
function loadFromPem(pem: string): SigningKey {
  try {
    const privateKey = createPrivateKey(pem);
    const publicKey = createPublicKey(privateKey);

    // Verify it's an EC P-256 key
    const jwk = publicKey.export({ format: "jwk" });
    if (jwk.crv !== "P-256") {
      throw new CryptoError(`Unsupported key curve: ${jwk.crv}. Only P-256 is supported.`);
    }

    const id = deriveDidKeyId(publicKey);
    return { id, privateKey, publicKey, algorithm: "P-256" };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to load signing key from PEM: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}
