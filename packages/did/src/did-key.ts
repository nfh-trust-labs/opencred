import { createHash, type KeyObject } from "node:crypto";
import { DIDResolutionError, CryptoError } from "@opencred/shared";
import type { DIDDocument, DIDResolutionResult, VerificationMethod } from "./types.js";
import type { DIDResolver } from "./resolver.js";
import { decodeBase58btc, encodeBase58btc } from "./multibase.js";

/** P-256 multicodec varint prefix: 0x1200 encoded as unsigned varint [0x80, 0x24]. */
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);
/** P-384 multicodec varint prefix: 0x1201 encoded as unsigned varint [0x81, 0x24]. */
const P384_MULTICODEC_PREFIX = new Uint8Array([0x81, 0x24]);
/** Ed25519 multicodec prefix: 0xed01 encoded as unsigned varint [0xed, 0x01]. */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

const P256_COMPRESSED_KEY_LENGTH = 33;
const P384_COMPRESSED_KEY_LENGTH = 49;
const ED25519_PUBLIC_KEY_LENGTH = 32;

/**
 * Compute the SEC1 compressed public key bytes from an EC KeyObject.
 * Works for both P-256 (33 bytes) and P-384 (49 bytes).
 */
export function getCompressedPublicKey(publicKey: KeyObject): Uint8Array {
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
 * Compute a SHA-256 fingerprint of a public key (hex-encoded).
 * Safe to log, display, and transmit over IPC.
 */
export function computeKeyFingerprint(publicKey: KeyObject): string {
  const spki = publicKey.export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki).digest("hex");
}

/**
 * Derive a did:key verification method identifier from an EC public key.
 *
 * Supports P-256 and P-384 curves. Format: `did:key:z<multibase>#z<multibase>`
 * where the multibase value is the base58btc encoding of the multicodec prefix + compressed key.
 *
 * @param publicKey - A Node.js KeyObject for the EC public key.
 * @returns The did:key verification method ID string.
 * @throws {CryptoError} if the key is not a supported EC curve.
 */
export function deriveDidKeyId(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" });

  let prefix: Uint8Array;
  let keyBytes: Uint8Array;

  if (jwk.crv === "Ed25519") {
    // Ed25519: raw 32-byte public key (no SEC1 compression)
    if (!jwk.x) {
      throw new CryptoError("Failed to export Ed25519 public key");
    }
    prefix = ED25519_MULTICODEC_PREFIX;
    keyBytes = new Uint8Array(Buffer.from(jwk.x, "base64url"));
  } else if (jwk.crv === "P-256" || jwk.crv === "P-384") {
    prefix = jwk.crv === "P-256" ? P256_MULTICODEC_PREFIX : P384_MULTICODEC_PREFIX;
    keyBytes = getCompressedPublicKey(publicKey);
  } else {
    throw new CryptoError(`Unsupported curve for did:key: ${String(jwk.crv)}`);
  }

  const multicodecKey = new Uint8Array(prefix.length + keyBytes.length);
  multicodecKey.set(prefix, 0);
  multicodecKey.set(keyBytes, prefix.length);

  const multibaseKey = "z" + encodeBase58btc(multicodecKey);
  const did = `did:key:${multibaseKey}`;
  return `${did}#${multibaseKey}`;
}

/**
 * Derive a did:key verification method identifier from a SEC1 compressed EC public key.
 *
 * @param compressedPublicKey - SEC1 compressed key (33 bytes for P-256, 49 bytes for P-384).
 * @param curve - The EC curve ("P-256" or "P-384").
 * @returns The did:key verification method ID string.
 */
export function deriveDidKeyIdFromCompressedKey(
  compressedPublicKey: Uint8Array,
  curve: "P-256" | "P-384" = "P-256",
): string {
  const expectedLength = curve === "P-256" ? P256_COMPRESSED_KEY_LENGTH : P384_COMPRESSED_KEY_LENGTH;
  if (compressedPublicKey.length !== expectedLength) {
    throw new CryptoError(
      `Invalid compressed public key length: expected ${expectedLength} bytes, got ${compressedPublicKey.length}`,
    );
  }

  const prefix = curve === "P-256" ? P256_MULTICODEC_PREFIX : P384_MULTICODEC_PREFIX;
  const multicodecKey = new Uint8Array(prefix.length + compressedPublicKey.length);
  multicodecKey.set(prefix, 0);
  multicodecKey.set(compressedPublicKey, prefix.length);

  const multibaseKey = "z" + encodeBase58btc(multicodecKey);
  const did = `did:key:${multibaseKey}`;
  return `${did}#${multibaseKey}`;
}

export class DIDKeyResolver implements DIDResolver {
  async resolve(did: string): Promise<DIDResolutionResult> {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }

    const parts = did.split(":");
    if (parts.length !== 3 || parts[0] !== "did") {
      throw new DIDResolutionError(`Invalid DID format: expected did:<method>:<id>`);
    }

    if (parts[1] !== "key") {
      throw new DIDResolutionError(`Unsupported DID method: ${parts[1]}`);
    }

    const multibaseKey = parts[2];
    if (!multibaseKey || !multibaseKey.startsWith("z")) {
      throw new DIDResolutionError("Only base58btc (z prefix) multibase encoding is supported");
    }

    let decoded: Uint8Array;
    try {
      decoded = decodeBase58btc(multibaseKey.slice(1));
    } catch {
      throw new DIDResolutionError("Failed to decode multibase key");
    }

    if (decoded.length < 2) {
      throw new DIDResolutionError("Decoded key too short");
    }

    // Detect curve from multicodec prefix
    let expectedKeyLength: number;
    let isEd25519 = false;
    if (decoded[0] === P256_MULTICODEC_PREFIX[0] && decoded[1] === P256_MULTICODEC_PREFIX[1]) {
      expectedKeyLength = P256_COMPRESSED_KEY_LENGTH;
    } else if (decoded[0] === P384_MULTICODEC_PREFIX[0] && decoded[1] === P384_MULTICODEC_PREFIX[1]) {
      expectedKeyLength = P384_COMPRESSED_KEY_LENGTH;
    } else if (decoded[0] === ED25519_MULTICODEC_PREFIX[0] && decoded[1] === ED25519_MULTICODEC_PREFIX[1]) {
      expectedKeyLength = ED25519_PUBLIC_KEY_LENGTH;
      isEd25519 = true;
    } else {
      throw new DIDResolutionError("Unsupported key type: only P-256, P-384, and Ed25519 keys are supported");
    }

    const publicKeyBytes = decoded.slice(2);
    if (publicKeyBytes.length !== expectedKeyLength) {
      throw new DIDResolutionError(
        `Invalid key length: expected ${expectedKeyLength} bytes, got ${publicKeyBytes.length}`,
      );
    }

    // EC keys (P-256, P-384) must have SEC1 compressed point prefix
    if (!isEd25519 && publicKeyBytes[0] !== 0x02 && publicKeyBytes[0] !== 0x03) {
      throw new DIDResolutionError("Invalid compressed key: must start with 0x02 or 0x03");
    }

    const verificationMethodId = `${did}#${multibaseKey}`;

    const verificationMethod: VerificationMethod = {
      id: verificationMethodId,
      type: "Multikey",
      controller: did,
      publicKeyMultibase: multibaseKey,
    };

    const didDocument: DIDDocument = {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      capabilityInvocation: [verificationMethodId],
      capabilityDelegation: [verificationMethodId],
    };

    return {
      didDocument,
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }
}
