import { createPublicKey, type KeyObject } from "node:crypto";
import { multibaseDecode } from "@opencred/crypto";

/**
 * Convert a multibase-encoded public key (from a DID document's
 * publicKeyMultibase field) to a Node.js KeyObject.
 *
 * The multibase value starts with 'z' (base58btc). Decoded bytes carry
 * a multicodec prefix identifying the curve:
 *   Ed25519:  0xed 0x01   → 32-byte raw key
 *   P-256:    0x80 0x24   → 33-byte compressed key
 *   P-384:    0x81 0x24   → 49-byte compressed key
 *
 * VC-DI-ECDSA §3.1 defines the ecdsa-rdfc-2019 cryptosuite over both
 * P-256 and P-384, and did:key issues P-384 identifiers with the
 * 0x81 0x24 prefix. Rejecting P-384 here would break verification of
 * otherwise-conformant credentials.
 */
export function publicKeyFromMultibase(multibaseKey: string): KeyObject | null {
  try {
    const decoded = multibaseDecode(multibaseKey);

    if (decoded.length < 2) {
      return null;
    }

    // Ed25519 multicodec prefix (0xed 0x01)
    if (decoded[0] === 0xed && decoded[1] === 0x01) {
      const rawKey = decoded.slice(2);
      if (rawKey.length !== 32) {
        return null;
      }
      return publicKeyFromRawEd25519(rawKey);
    }

    // P-256 multicodec prefix (varint: 0x80 0x24)
    if (decoded[0] === 0x80 && decoded[1] === 0x24) {
      const compressedKey = decoded.slice(2);
      if (compressedKey.length !== 33) {
        return null;
      }
      return publicKeyFromCompressedP256(compressedKey);
    }

    // P-384 multicodec prefix (varint: 0x81 0x24)
    if (decoded[0] === 0x81 && decoded[1] === 0x24) {
      const compressedKey = decoded.slice(2);
      if (compressedKey.length !== 49) {
        return null;
      }
      return publicKeyFromCompressedP384(compressedKey);
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Convert a raw Ed25519 public key (32 bytes) into a Node.js KeyObject
 * by constructing a DER-encoded SubjectPublicKeyInfo.
 *
 * Ed25519 SPKI DER structure:
 *   SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING { raw key } }
 *   Fixed prefix: 30 2a 30 05 06 03 2b 65 70 03 21 00 (12 bytes)
 */
function publicKeyFromRawEd25519(rawKey: Uint8Array): KeyObject {
  const ed25519SpkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const spki = Buffer.concat([ed25519SpkiPrefix, rawKey]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

/**
 * Convert a compressed P-256 public key (33 bytes) into a Node.js KeyObject
 * by constructing a DER-encoded SubjectPublicKeyInfo.
 */
function publicKeyFromCompressedP256(compressedKey: Uint8Array): KeyObject {
  // SubjectPublicKeyInfo ::= SEQUENCE {
  //   algorithm  AlgorithmIdentifier ::= SEQUENCE { OID ecPublicKey, OID prime256v1 }
  //   subjectPublicKey  BIT STRING (compressed point)
  // }
  const ecPublicKeyOid = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const p256Oid = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

  const algSequence = Buffer.concat([
    Buffer.from([0x30, ecPublicKeyOid.length + p256Oid.length]),
    ecPublicKeyOid,
    p256Oid,
  ]);

  const bitString = Buffer.concat([
    Buffer.from([0x03, compressedKey.length + 1, 0x00]),
    compressedKey,
  ]);

  const spki = Buffer.concat([
    Buffer.from([0x30, algSequence.length + bitString.length]),
    algSequence,
    bitString,
  ]);

  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

/**
 * Convert a compressed P-384 public key (49 bytes) into a Node.js KeyObject
 * by constructing a DER-encoded SubjectPublicKeyInfo.
 *
 * Identical shape to the P-256 helper but with the secp384r1 OID
 * (1.3.132.0.34) in the AlgorithmIdentifier instead of prime256v1.
 */
function publicKeyFromCompressedP384(compressedKey: Uint8Array): KeyObject {
  const ecPublicKeyOid = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  // OID 1.3.132.0.34 = 2B 81 04 00 22, wrapped: 06 05 2B 81 04 00 22
  const p384Oid = Buffer.from([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);

  const algSequence = Buffer.concat([
    Buffer.from([0x30, ecPublicKeyOid.length + p384Oid.length]),
    ecPublicKeyOid,
    p384Oid,
  ]);

  const bitString = Buffer.concat([
    Buffer.from([0x03, compressedKey.length + 1, 0x00]),
    compressedKey,
  ]);

  const spki = Buffer.concat([
    Buffer.from([0x30, algSequence.length + bitString.length]),
    algSequence,
    bitString,
  ]);

  return createPublicKey({ key: spki, format: "der", type: "spki" });
}
