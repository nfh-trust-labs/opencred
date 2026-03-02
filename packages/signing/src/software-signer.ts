/**
 * Software signer for the OpenCred desktop app.
 *
 * Loads issuer private keys from local files and provides a Signer interface
 * for the local signing flow. Supports PEM, JWK, and PKCS#8 DER formats.
 *
 * SECURITY INVARIANTS:
 *  - The private key NEVER leaves this process.
 *  - Key material is NEVER logged -- only the key ID or fingerprint.
 *  - Only ECDSA P-256 keys are accepted (required by ecdsa-rdfc-2019).
 *  - The KeyObject is held in memory; it is never serialised or transmitted.
 */

import {
  createPrivateKey,
  createPublicKey,
  createSign,
  createHash,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { CryptoError } from "@opencred/shared";
import { multibaseEncode } from "@opencred/crypto";
import type { Signer, SignerMetadata, KeyFormat } from "./types.js";

/** P-256 multicodec varint prefix (0x1200 in unsigned varint = [0x80, 0x24]). */
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

/**
 * Detect the format of a key file's contents.
 *
 * - PEM: starts with "-----BEGIN"
 * - JWK: valid JSON with a "kty" property
 * - PKCS#8 DER: binary data (fallback)
 */
export function detectKeyFormat(content: Buffer): KeyFormat {
  // Check for PEM header
  const textContent = content.toString("utf-8").trim();
  if (textContent.startsWith("-----BEGIN")) {
    return "pem";
  }

  // Check for JWK (JSON with "kty" field)
  try {
    const parsed = JSON.parse(textContent) as Record<string, unknown>;
    if (parsed && typeof parsed === "object" && "kty" in parsed) {
      return "jwk";
    }
  } catch {
    // Not JSON -- fall through to DER
  }

  return "pkcs8-der";
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
 * Compute a SHA-256 fingerprint of the public key (hex-encoded).
 * This is safe to log, display, and transmit over IPC.
 */
function computeFingerprint(publicKey: KeyObject): string {
  const spki = publicKey.export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki).digest("hex");
}

/**
 * Validate that a key is an ECDSA P-256 key.
 * Throws CryptoError if the key is not P-256.
 */
function validateP256Key(publicKey: KeyObject): void {
  const jwk = publicKey.export({ format: "jwk" });
  if (jwk.crv !== "P-256") {
    throw new CryptoError(`Unsupported key curve: ${String(jwk.crv)}. Only P-256 is supported.`);
  }
  if (jwk.kty !== "EC") {
    throw new CryptoError(`Unsupported key type: ${String(jwk.kty)}. Only EC keys are supported.`);
  }
}

/**
 * Load a private key from a PEM string.
 */
function loadFromPem(pem: string): { privateKey: KeyObject; publicKey: KeyObject } {
  const privateKey = createPrivateKey(pem);
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Load a private key from a JWK object.
 */
function loadFromJwk(jwkString: string): { privateKey: KeyObject; publicKey: KeyObject } {
  const jwk = JSON.parse(jwkString) as Record<string, unknown>;
  const privateKey = createPrivateKey({ key: jwk, format: "jwk" });
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Load a private key from PKCS#8 DER binary.
 */
function loadFromPkcs8Der(buffer: Buffer): { privateKey: KeyObject; publicKey: KeyObject } {
  const privateKey = createPrivateKey({ key: buffer, format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Build a Signer from loaded key material.
 *
 * Validates that the key is P-256, derives the did:key identifier,
 * computes the fingerprint, and returns a ready-to-use Signer.
 */
export function buildSigner(privateKey: KeyObject, publicKey: KeyObject, label?: string): Signer {
  validateP256Key(publicKey);

  const id = deriveDidKeyId(publicKey);
  const fingerprint = computeFingerprint(publicKey);

  const metadata: SignerMetadata = {
    id,
    algorithm: "P-256",
    type: "software",
    fingerprint,
    label,
  };

  const signer: Signer = {
    id,
    algorithm: "P-256",
    type: "software",
    metadata,

    async sign(data: Uint8Array): Promise<Uint8Array> {
      try {
        const sig = createSign("SHA256");
        sig.update(data);
        const signature = sig.sign({
          key: privateKey,
          dsaEncoding: "ieee-p1363",
        });

        // ieee-p1363 gives us raw r||s directly (64 bytes for P-256)
        return new Uint8Array(signature);
      } catch {
        throw new CryptoError("Signing operation failed");
      }
    },
  };

  return signer;
}

/**
 * Load key material from a buffer and detect the format.
 */
function loadKeyFromBuffer(
  content: Buffer,
  format: KeyFormat,
): { privateKey: KeyObject; publicKey: KeyObject } {
  switch (format) {
    case "pem": {
      return loadFromPem(content.toString("utf-8"));
    }
    case "jwk": {
      return loadFromJwk(content.toString("utf-8"));
    }
    case "pkcs8-der": {
      return loadFromPkcs8Der(content);
    }
  }
}

/**
 * Create a SoftwareSigner from a file path.
 *
 * Reads the key file, detects the format (PEM, JWK, or PKCS#8 DER),
 * validates it is an ECDSA P-256 key, and returns a Signer instance.
 *
 * The private key stays in memory within this process. It is never
 * logged, serialised, or transmitted.
 *
 * @param filePath - Absolute path to the key file on disk.
 * @param label - Optional user-friendly label for the key.
 * @returns An object containing the Signer and the detected key format.
 * @throws {CryptoError} if the key is invalid, unsupported, or unreadable.
 */
export function createSoftwareSigner(
  filePath: string,
  label?: string,
): { signer: Signer; format: KeyFormat } {
  let content: Buffer;
  try {
    content = readFileSync(filePath);
  } catch {
    throw new CryptoError("Failed to read key file");
  }

  const format = detectKeyFormat(content);

  try {
    const { privateKey, publicKey } = loadKeyFromBuffer(content, format);
    const signer = buildSigner(privateKey, publicKey, label);
    return { signer, format };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to parse key file: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Create a SoftwareSigner directly from key material in memory.
 *
 * This is used internally when the key content is already available
 * (e.g., from the key import IPC handler). The private key is never
 * stored -- only the resulting Signer is kept.
 *
 * @param content - The raw key file content as a Buffer.
 * @param label - Optional user-friendly label.
 * @returns An object containing the Signer and the detected key format.
 */
export function createSoftwareSignerFromBuffer(
  content: Buffer,
  label?: string,
): { signer: Signer; format: KeyFormat } {
  const format = detectKeyFormat(content);

  try {
    const { privateKey, publicKey } = loadKeyFromBuffer(content, format);
    const signer = buildSigner(privateKey, publicKey, label);
    return { signer, format };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to parse key: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}
