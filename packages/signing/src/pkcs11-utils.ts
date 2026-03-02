/**
 * PKCS#11 key utility functions.
 *
 * Provides helpers for extracting public keys from PKCS#11 objects,
 * deriving did:key verification method IDs, and computing key fingerprints.
 *
 * SECURITY INVARIANTS:
 *  - Only public key material is handled here. Private keys NEVER leave
 *    the hardware token.
 *  - Key fingerprints use SHA-256 of the SPKI encoding.
 *  - No key material is ever logged.
 */

import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { multibaseEncode, derToRaw } from "@opencred/crypto";

/** P-256 multicodec varint prefix (0x1200 in unsigned varint = [0x80, 0x24]). */
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

/**
 * The P-256 uncompressed point length: 1 prefix byte + 32 x bytes + 32 y bytes = 65 bytes.
 */
const P256_UNCOMPRESSED_POINT_LENGTH = 65;

/**
 * The P-256 raw r||s signature length: 32 r bytes + 32 s bytes = 64 bytes.
 */
const P256_RAW_SIGNATURE_LENGTH = 64;

/**
 * Build a Node.js KeyObject from a raw EC P-256 public key point.
 *
 * PKCS#11 returns EC public keys as uncompressed points (04 || x || y).
 * This wraps them in SPKI DER to create a standard KeyObject.
 *
 * @param ecPoint - The uncompressed EC point bytes (65 bytes for P-256).
 * @returns A Node.js KeyObject for the public key.
 * @throws {CryptoError} if the point is not a valid P-256 uncompressed point.
 */
export function publicKeyFromEcPoint(ecPoint: Uint8Array): KeyObject {
  if (ecPoint.length !== P256_UNCOMPRESSED_POINT_LENGTH || ecPoint[0] !== 0x04) {
    throw new CryptoError(
      "Invalid EC point: expected 65-byte uncompressed P-256 point (04 || x || y)",
    );
  }

  // Build SPKI DER wrapper for EC P-256 public key
  // SEQUENCE {
  //   SEQUENCE {
  //     OID ecPublicKey (1.2.840.10045.2.1)
  //     OID prime256v1  (1.2.840.10045.3.1.7)
  //   }
  //   BIT STRING (the uncompressed point)
  // }
  const ecPublicKeyOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const prime256v1Oid = new Uint8Array([
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  ]);

  // Inner SEQUENCE: ecPublicKeyOid + prime256v1Oid
  const innerSeqContent = new Uint8Array(ecPublicKeyOid.length + prime256v1Oid.length);
  innerSeqContent.set(ecPublicKeyOid, 0);
  innerSeqContent.set(prime256v1Oid, ecPublicKeyOid.length);

  const innerSeq = new Uint8Array(2 + innerSeqContent.length);
  innerSeq[0] = 0x30; // SEQUENCE
  innerSeq[1] = innerSeqContent.length;
  innerSeq.set(innerSeqContent, 2);

  // BIT STRING wrapping the EC point: 1 byte for unused bits (0x00) + point
  const bitStringContent = new Uint8Array(1 + ecPoint.length);
  bitStringContent[0] = 0x00; // no unused bits
  bitStringContent.set(ecPoint, 1);

  const bitString = new Uint8Array(2 + bitStringContent.length);
  bitString[0] = 0x03; // BIT STRING
  bitString[1] = bitStringContent.length;
  bitString.set(bitStringContent, 2);

  // Outer SEQUENCE: innerSeq + bitString
  const outerContent = new Uint8Array(innerSeq.length + bitString.length);
  outerContent.set(innerSeq, 0);
  outerContent.set(bitString, innerSeq.length);

  const spki = new Uint8Array(2 + outerContent.length);
  spki[0] = 0x30; // SEQUENCE
  spki[1] = outerContent.length;
  spki.set(outerContent, 2);

  try {
    return createPublicKey({
      key: Buffer.from(spki),
      format: "der",
      type: "spki",
    });
  } catch {
    throw new CryptoError("Failed to construct public key from EC point");
  }
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
 * Format: did:key:z<multibase>#z<multibase> where the multibase value is
 * the base58btc encoding of the P-256 multicodec prefix + compressed public key.
 *
 * @param publicKey - A Node.js KeyObject for the P-256 public key.
 * @returns The did:key verification method ID string.
 */
export function deriveDidKeyIdFromPublicKey(publicKey: KeyObject): string {
  const compressed = getCompressedPublicKey(publicKey);

  const multicodecKey = new Uint8Array(P256_MULTICODEC_PREFIX.length + compressed.length);
  multicodecKey.set(P256_MULTICODEC_PREFIX, 0);
  multicodecKey.set(compressed, P256_MULTICODEC_PREFIX.length);

  const multibaseKey = multibaseEncode(multicodecKey);
  const did = `did:key:${multibaseKey}`;
  return `${did}#${multibaseKey}`;
}

/**
 * Compute a SHA-256 fingerprint of the public key (hex-encoded).
 * This is safe to log, display, and transmit over IPC.
 *
 * @param publicKey - A Node.js KeyObject for the public key.
 * @returns Hex-encoded SHA-256 fingerprint.
 */
export function computeFingerprint(publicKey: KeyObject): string {
  const spki = publicKey.export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki).digest("hex");
}

/**
 * Normalize a PKCS#11 ECDSA signature to raw r||s format (64 bytes for P-256).
 *
 * PKCS#11 CKM_ECDSA mechanism returns raw r||s for P-256 (64 bytes), but some
 * tokens incorrectly return DER-encoded signatures. This function detects the
 * format and normalizes to raw r||s.
 *
 * @param signature - The signature bytes from PKCS#11 C_Sign.
 * @returns Raw r||s signature (64 bytes).
 * @throws {CryptoError} if the signature cannot be interpreted.
 */
export function normalizeSignature(signature: Uint8Array): Uint8Array {
  if (signature.length === P256_RAW_SIGNATURE_LENGTH) {
    // Already raw r||s format
    return signature;
  }

  // Check for DER encoding: starts with 0x30 (SEQUENCE tag)
  if (signature.length > P256_RAW_SIGNATURE_LENGTH && signature[0] === 0x30) {
    try {
      return derToRaw(signature);
    } catch {
      throw new CryptoError("PKCS#11 signature appears to be DER-encoded but could not be parsed");
    }
  }

  throw new CryptoError(
    `Unexpected PKCS#11 signature length: expected 64 bytes (raw) or DER-encoded, got ${signature.length} bytes`,
  );
}
