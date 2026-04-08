/**
 * PKCS#11 key utility functions.
 *
 * Provides helpers for extracting public keys from PKCS#11 objects,
 * deriving did:key / did:jwk verification method IDs, and computing key fingerprints.
 *
 * SECURITY INVARIANTS:
 *  - Only public key material is handled here. Private keys NEVER leave
 *    the hardware token.
 *  - Key fingerprints use SHA-256 of the SPKI encoding.
 *  - No key material is ever logged.
 */

import { createPublicKey, type KeyObject } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { derToRaw } from "@opencred/crypto";
import {
  deriveDidKeyId,
  computeKeyFingerprint,
  encodeDidJwk,
  didJwkVerificationMethodId,
} from "@opencred/did";
import type { SigningAlgorithm } from "@opencred/crypto";

/**
 * The P-256 uncompressed point length: 1 prefix byte + 32 x bytes + 32 y bytes = 65 bytes.
 */
const P256_UNCOMPRESSED_POINT_LENGTH = 65;

/**
 * The P-384 uncompressed point length: 1 prefix byte + 48 x bytes + 48 y bytes = 97 bytes.
 */
const P384_UNCOMPRESSED_POINT_LENGTH = 97;

/**
 * The P-256 raw r||s signature length: 32 r bytes + 32 s bytes = 64 bytes.
 */
const P256_RAW_SIGNATURE_LENGTH = 64;

/**
 * The P-384 raw r||s signature length: 48 r bytes + 48 s bytes = 96 bytes.
 */
const P384_RAW_SIGNATURE_LENGTH = 96;

/**
 * Build a Node.js KeyObject from a raw EC public key point.
 *
 * PKCS#11 returns EC public keys as uncompressed points (04 || x || y).
 * This wraps them in SPKI DER to create a standard KeyObject.
 * Supports both P-256 (65-byte) and P-384 (97-byte) points.
 *
 * @param ecPoint - The uncompressed EC point bytes (65 bytes for P-256, 97 bytes for P-384).
 * @returns A Node.js KeyObject for the public key.
 * @throws {CryptoError} if the point is not a valid uncompressed EC point.
 */
export function publicKeyFromEcPoint(ecPoint: Uint8Array): KeyObject {
  if (ecPoint[0] !== 0x04) {
    throw new CryptoError("Invalid EC point: must start with 0x04 (uncompressed point prefix)");
  }

  if (
    ecPoint.length !== P256_UNCOMPRESSED_POINT_LENGTH &&
    ecPoint.length !== P384_UNCOMPRESSED_POINT_LENGTH
  ) {
    throw new CryptoError(
      `Invalid EC point: expected 65-byte (P-256) or 97-byte (P-384) uncompressed point, got ${ecPoint.length} bytes`,
    );
  }

  const isP384 = ecPoint.length === P384_UNCOMPRESSED_POINT_LENGTH;

  // Build SPKI DER wrapper for EC public key
  // SEQUENCE {
  //   SEQUENCE {
  //     OID ecPublicKey (1.2.840.10045.2.1)
  //     OID curve (prime256v1 or secp384r1)
  //   }
  //   BIT STRING (the uncompressed point)
  // }
  const ecPublicKeyOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const curveOid = isP384
    ? new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]) // secp384r1 (1.3.132.0.34)
    : new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]); // prime256v1

  // Inner SEQUENCE: ecPublicKeyOid + curveOid
  const innerSeqContent = new Uint8Array(ecPublicKeyOid.length + curveOid.length);
  innerSeqContent.set(ecPublicKeyOid, 0);
  innerSeqContent.set(curveOid, ecPublicKeyOid.length);

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
 * Build a Node.js KeyObject from RSA modulus and public exponent bytes.
 *
 * PKCS#11 exposes RSA public key components via CKA_MODULUS and
 * CKA_PUBLIC_EXPONENT attributes. This constructs a standard KeyObject
 * by importing them as a JWK.
 *
 * @param modulus - The RSA modulus bytes (CKA_MODULUS).
 * @param publicExponent - The RSA public exponent bytes (CKA_PUBLIC_EXPONENT).
 * @returns A Node.js KeyObject for the public key.
 * @throws {CryptoError} if the key cannot be constructed.
 */
export function publicKeyFromRsaComponents(
  modulus: Uint8Array,
  publicExponent: Uint8Array,
): KeyObject {
  // Strip leading zero bytes from modulus (PKCS#11 may include a sign byte)
  let trimmedModulus = modulus;
  while (trimmedModulus.length > 0 && trimmedModulus[0] === 0x00) {
    trimmedModulus = trimmedModulus.subarray(1);
  }

  const n = Buffer.from(trimmedModulus).toString("base64url");
  const e = Buffer.from(publicExponent).toString("base64url");

  try {
    return createPublicKey({
      key: { kty: "RSA", n, e },
      format: "jwk",
    });
  } catch {
    throw new CryptoError("Failed to construct RSA public key from modulus and exponent");
  }
}

/**
 * Determine the SigningAlgorithm for an RSA key based on modulus bit length.
 */
export function rsaAlgorithmFromModulusBits(modulusBitLength: number): SigningAlgorithm {
  if (modulusBitLength <= 2048) return "RSA-2048";
  if (modulusBitLength <= 3072) return "RSA-3072";
  return "RSA-4096";
}

/**
 * Derive a did:key verification method identifier from an EC public key.
 * Delegates to the shared implementation in @opencred/did.
 */
export function deriveDidKeyIdFromPublicKey(publicKey: KeyObject): string {
  return deriveDidKeyId(publicKey);
}

/**
 * Derive a did:jwk verification method identifier from an RSA public key.
 *
 * RSA keys use did:jwk rather than did:key because did:key for RSA produces
 * very long identifiers and is only in draft status.
 */
export function deriveDidJwkIdFromPublicKey(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" }) as { kty: string; [key: string]: unknown };
  const did = encodeDidJwk(jwk);
  return didJwkVerificationMethodId(did);
}

/**
 * Compute a SHA-256 fingerprint of the public key (hex-encoded).
 * Delegates to the shared implementation in @opencred/did.
 */
export function computeFingerprint(publicKey: KeyObject): string {
  return computeKeyFingerprint(publicKey);
}

/**
 * Convert a DER-encoded X.509 certificate to PEM format.
 */
export function derCertToPem(derCert: Uint8Array): string {
  const b64 = Buffer.from(derCert).toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.substring(i, i + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Normalize a PKCS#11 signature to the expected raw format.
 *
 * For EC keys (P-256/P-384): normalizes to raw r||s (64/96 bytes).
 * For RSA keys: passes through unchanged (RSA signatures are not r||s).
 *
 * @param signature - The signature bytes from PKCS#11 C_Sign.
 * @param keyType - The key type: "EC" or "RSA". Defaults to "EC" for backward compatibility.
 * @returns Normalized signature bytes.
 * @throws {CryptoError} if an EC signature cannot be interpreted.
 */
export function normalizeSignature(
  signature: Uint8Array,
  keyType: "EC" | "RSA" = "EC",
): Uint8Array {
  // RSA signatures pass through without normalization
  if (keyType === "RSA") {
    return signature;
  }

  // EC: check for raw r||s format (P-256 = 64 bytes, P-384 = 96 bytes)
  if (
    signature.length === P256_RAW_SIGNATURE_LENGTH ||
    signature.length === P384_RAW_SIGNATURE_LENGTH
  ) {
    return signature;
  }

  // Check for DER encoding: starts with 0x30 (SEQUENCE tag)
  if (signature[0] === 0x30) {
    try {
      // Infer component size from DER total length.
      // P-256 DER sigs are ~70 bytes; P-384 DER sigs are ~102 bytes.
      // The component size is 32 for P-256, 48 for P-384.
      const componentSize = signature.length > 80 ? 48 : 32;
      return derToRaw(signature, componentSize);
    } catch {
      throw new CryptoError("PKCS#11 signature appears to be DER-encoded but could not be parsed");
    }
  }

  throw new CryptoError(
    `Unexpected PKCS#11 EC signature length: expected 64 bytes (P-256), 96 bytes (P-384), or DER-encoded, got ${signature.length} bytes`,
  );
}
