/**
 * Key algorithm detection utilities.
 *
 * Provides a canonical function for detecting the SigningAlgorithm
 * of a Node.js KeyObject. Centralised here in @opencred/crypto
 * because the SigningAlgorithm type is defined in this package.
 */

import { createPublicKey, type KeyObject } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import type { SigningAlgorithm } from "./types.js";

/**
 * Detect the signing algorithm from a public key's JWK export.
 *
 * Supports EC (P-256, P-384), OKP (Ed25519), and RSA (2048, 3072, 4096).
 *
 * @param publicKey - A Node.js KeyObject (public key).
 * @returns The detected SigningAlgorithm.
 * @throws {CryptoError} if the key type or curve is unsupported.
 */
export function detectKeyAlgorithm(publicKey: KeyObject): SigningAlgorithm {
  const jwk = publicKey.export({ format: "jwk" });

  if (jwk.kty === "EC") {
    if (jwk.crv === "P-256") return "P-256";
    if (jwk.crv === "P-384") return "P-384";
    throw new CryptoError(`Unsupported EC curve: ${String(jwk.crv)}`);
  }

  if (jwk.kty === "OKP") {
    if (jwk.crv === "Ed25519") return "Ed25519";
    throw new CryptoError(`Unsupported OKP curve: ${String(jwk.crv)}`);
  }

  if (jwk.kty === "RSA") {
    const modulusBits = Buffer.from(jwk.n!, "base64url").length * 8;
    if (modulusBits >= 4096) return "RSA-4096";
    if (modulusBits >= 3072) return "RSA-3072";
    if (modulusBits >= 2048) return "RSA-2048";
    throw new CryptoError(`RSA modulus too small: ${modulusBits} bits`);
  }

  throw new CryptoError(`Unsupported algorithm type: ${String(jwk.kty)}`);
}

/**
 * Build a Node.js KeyObject from raw EC public key bytes (compressed or uncompressed).
 *
 * Accepts both:
 *  - Uncompressed points: 04 || x || y (65 bytes for P-256, 97 bytes for P-384)
 *  - Compressed points: 02/03 || x (33 bytes for P-256, 49 bytes for P-384)
 *
 * Wraps the key bytes in SPKI DER to create a standard KeyObject.
 *
 * @param ecBytes - The EC public key bytes (compressed or uncompressed).
 * @returns A Node.js KeyObject for the public key.
 * @throws {CryptoError} if the point format or length is invalid.
 */
export function publicKeyFromEcBytes(ecBytes: Uint8Array): KeyObject {
  const prefix = ecBytes[0];
  const len = ecBytes.length;

  // Validate format
  const isUncompressed = prefix === 0x04;
  const isCompressed = prefix === 0x02 || prefix === 0x03;

  if (!isUncompressed && !isCompressed) {
    throw new CryptoError(
      `Invalid EC point: must start with 0x02, 0x03 (compressed) or 0x04 (uncompressed), got 0x${prefix.toString(16).padStart(2, "0")}`,
    );
  }

  // Determine curve from byte length
  let isP384: boolean;
  if (isUncompressed) {
    if (len === 65) isP384 = false;
    else if (len === 97) isP384 = true;
    else {
      throw new CryptoError(
        `Invalid EC uncompressed point: expected 65 bytes (P-256) or 97 bytes (P-384), got ${len} bytes`,
      );
    }
  } else {
    if (len === 33) isP384 = false;
    else if (len === 49) isP384 = true;
    else {
      throw new CryptoError(
        `Invalid EC compressed point: expected 33 bytes (P-256) or 49 bytes (P-384), got ${len} bytes`,
      );
    }
  }

  // OIDs for SPKI DER wrapper
  const ecPublicKeyOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const curveOid = isP384
    ? new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]) // secp384r1
    : new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]); // prime256v1

  // Inner SEQUENCE: ecPublicKeyOid + curveOid
  const innerSeqContent = new Uint8Array(ecPublicKeyOid.length + curveOid.length);
  innerSeqContent.set(ecPublicKeyOid, 0);
  innerSeqContent.set(curveOid, ecPublicKeyOid.length);

  const innerSeq = new Uint8Array(2 + innerSeqContent.length);
  innerSeq[0] = 0x30; // SEQUENCE
  innerSeq[1] = innerSeqContent.length;
  innerSeq.set(innerSeqContent, 2);

  // BIT STRING wrapping the EC point
  const bitStringContent = new Uint8Array(1 + ecBytes.length);
  bitStringContent[0] = 0x00; // no unused bits
  bitStringContent.set(ecBytes, 1);

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
