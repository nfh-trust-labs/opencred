import { createPublicKey, type KeyObject } from "node:crypto";
import { multibaseDecode } from "@opencred/crypto";

/**
 * Convert a multibase-encoded P-256 public key (from a DID document's
 * publicKeyMultibase field) to a Node.js KeyObject.
 *
 * The multibase value starts with 'z' (base58btc), decoded bytes have a
 * multicodec prefix (0x80 0x24 for P-256), followed by the 33-byte
 * compressed public key.
 */
export function publicKeyFromMultibase(multibaseKey: string): KeyObject | null {
  try {
    const decoded = multibaseDecode(multibaseKey);

    // Check for P-256 multicodec prefix (varint: 0x80 0x24)
    if (decoded.length < 2 || decoded[0] !== 0x80 || decoded[1] !== 0x24) {
      return null;
    }

    const compressedKey = decoded.slice(2);
    if (compressedKey.length !== 33) {
      return null;
    }

    return publicKeyFromCompressedP256(compressedKey);
  } catch {
    return null;
  }
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
