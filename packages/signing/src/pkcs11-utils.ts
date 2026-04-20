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
import { derToRaw, publicKeyFromEcBytes } from "@opencred/crypto";
import { encodeDidJwk, didJwkVerificationMethodId } from "@opencred/did";
import type { SigningAlgorithm } from "@opencred/crypto";

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
 * Delegates to the canonical `publicKeyFromEcBytes` in @opencred/crypto.
 * Supports both P-256 (65-byte) and P-384 (97-byte) points.
 *
 * @param ecPoint - The uncompressed EC point bytes (65 bytes for P-256, 97 bytes for P-384).
 * @returns A Node.js KeyObject for the public key.
 * @throws {CryptoError} if the point is not a valid uncompressed EC point.
 */
export function publicKeyFromEcPoint(ecPoint: Uint8Array): KeyObject {
  return publicKeyFromEcBytes(ecPoint);
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
  } catch (err) {
    throw new CryptoError("Failed to construct RSA public key from modulus and exponent", { cause: err });
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
