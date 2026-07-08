/**
 * Software signer for the OpenCred desktop app.
 *
 * Loads issuer private keys from local files and provides a Signer interface
 * for the local signing flow. Supports PEM, JWK, PKCS#8 DER, and PFX/P12 formats.
 *
 * SECURITY INVARIANTS:
 *  - The private key NEVER leaves this process.
 *  - Key material is NEVER logged -- only the key ID or fingerprint.
 *  - Supported algorithms: P-256, P-384, RSA-2048, RSA-3072, RSA-4096.
 *  - The KeyObject is held in memory; it is never serialised or transmitted.
 */

import {
  constants,
  createPrivateKey,
  createPublicKey,
  createSign,
  sign,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { CryptoError } from "@opencred/shared";
import {
  deriveDidKeyId,
  computeKeyFingerprint,
  encodeDidJwk,
  didJwkVerificationMethodId,
} from "@opencred/did";
import { detectKeyAlgorithm, type SigningAlgorithm } from "@opencred/crypto";
import type { Signer, SignerMetadata, KeyFormat } from "./types.js";
import { parsePfx } from "./pfx-parser.js";

/**
 * Detect the format of a key file's contents.
 *
 * - PEM: starts with "-----BEGIN"
 * - JWK: valid JSON with a "kty" property
 * - PFX: detected via filenameHint (.pfx or .p12 extension)
 * - PKCS#8 DER: binary data (fallback)
 */
export function detectKeyFormat(content: Buffer, filenameHint?: string): KeyFormat {
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
    // Not JSON -- fall through
  }

  // Check for PFX by extension hint
  if (filenameHint) {
    const ext = filenameHint.toLowerCase();
    if (ext.endsWith(".pfx") || ext.endsWith(".p12")) {
      return "pfx";
    }
  }

  return "pkcs8-der";
}

/**
 * Derive the DID-based verification method ID for a given algorithm.
 * EC uses did:key; RSA uses did:jwk.
 */
function deriveVerificationMethodId(publicKey: KeyObject, algorithm: SigningAlgorithm): string {
  if (algorithm === "P-256" || algorithm === "P-384" || algorithm === "Ed25519") {
    return deriveDidKeyId(publicKey);
  }
  const jwk = publicKey.export({ format: "jwk" });
  const did = encodeDidJwk(jwk as import("@opencred/did").JWK);
  return didJwkVerificationMethodId(did);
}

/**
 * Load from a PEM string.
 */
function loadFromPem(pem: string): { privateKey: KeyObject; publicKey: KeyObject } {
  const privateKey = createPrivateKey(pem);
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Load from a JWK object.
 */
function loadFromJwk(jwkString: string): { privateKey: KeyObject; publicKey: KeyObject } {
  const jwk = JSON.parse(jwkString) as Record<string, unknown>;
  const privateKey = createPrivateKey({ key: jwk, format: "jwk" });
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Load from PKCS#8 DER binary.
 */
function loadFromPkcs8Der(buffer: Buffer): { privateKey: KeyObject; publicKey: KeyObject } {
  const privateKey = createPrivateKey({ key: buffer, format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Create an algorithm-dispatched sign function.
 */
function createSignFn(
  privateKey: KeyObject,
  algorithm: SigningAlgorithm,
): (data: Uint8Array) => Promise<Uint8Array> {
  return async (data: Uint8Array): Promise<Uint8Array> => {
    try {
      switch (algorithm) {
        case "P-256": {
          const s = createSign("SHA256");
          s.update(data);
          // ieee-p1363: raw r||s (64 bytes for P-256)
          return new Uint8Array(s.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }));
        }
        case "P-384": {
          const s = createSign("SHA384");
          s.update(data);
          // ieee-p1363: raw r||s (96 bytes for P-384)
          return new Uint8Array(s.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }));
        }
        case "Ed25519": {
          return new Uint8Array(sign(null, data, privateKey));
        }
        case "RSA-2048":
        case "RSA-3072":
        case "RSA-4096": {
          const s = createSign("SHA256");
          s.update(data);
          return new Uint8Array(
            s.sign({
              key: privateKey,
              padding: constants.RSA_PKCS1_PSS_PADDING,
              saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
            }),
          );
        }
      }
    } catch (err) {
      // Preserve the original node-crypto failure so operators
      // troubleshooting "signing failed" can inspect `.cause` (or the
      // stack chain in Node 16.9+) to distinguish padding errors, wrong
      // key type, EVP internal errors, etc. The wire payload from
      // toJSON()/toHttpBody() is still sanitized.
      throw new CryptoError("Signing operation failed", { cause: err });
    }
  };
}

/**
 * Build a Signer from loaded material.
 *
 * Detects the algorithm, derives the appropriate DID identifier,
 * computes the fingerprint, and returns a ready-to-use Signer.
 *
 * `verificationMethodIdOverride` — optional. When set, replaces the
 * derived `did:key:…` / `did:jwk:…` ID with the supplied verification
 * method URL (typically `did:web:<domain>#key-0` produced by callers
 * that have configured `OPENCRED_ISSUER_DID_METHOD=web`). The override
 * is applied to BOTH `signer.id` and `signer.metadata.id` so every
 * downstream consumer (`verificationMethod`, JWT `kid`, span attrs,
 * batch engine, rotate gate) sees the same value. Caller responsible
 * for ensuring the override actually identifies a key bound to this
 * keypair — `buildSigner` does not validate. See issue #632.
 */
export function buildSigner(
  privateKey: KeyObject,
  publicKey: KeyObject,
  label?: string,
  certificateChain?: string[],
  verificationMethodIdOverride?: string,
): Signer {
  const algorithm = detectKeyAlgorithm(publicKey);
  const derivedId = deriveVerificationMethodId(publicKey, algorithm);
  const id = verificationMethodIdOverride ?? derivedId;
  const fingerprint = computeKeyFingerprint(publicKey);

  // Export public key JWK once at signer-build time. Used by callers that
  // need to assemble a DID Document (e.g. did:web auto-publish at startup).
  // `KeyObject.export({ format: "jwk" })` returns ONLY public parameters for
  // a public KeyObject (`kty`, `crv`, `x`, `y` for EC; `kty`, `n`, `e` for
  // RSA) — never `d`/`p`/`q`. Safe to surface via SignerMetadata.
  const publicKeyJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;

  const metadata: SignerMetadata = {
    id,
    algorithm,
    type: "software",
    fingerprint,
    label,
    publicKeyJwk,
  };
  if (certificateChain && certificateChain.length > 0) {
    metadata.certificateChain = certificateChain;
  }

  const signer: Signer = {
    id,
    algorithm,
    type: "software",
    metadata,
    sign: createSignFn(privateKey, algorithm),
  };

  return signer;
}

/**
 * Build a Signer from a PFX/P12 buffer.
 *
 * Parses the PFX, extracts material and certificate chain,
 * and returns a signer with the chain included in metadata.
 *
 * `verificationMethodIdOverride` is forwarded to `buildSigner` —
 * see its docstring for semantics.
 */
export function buildSignerFromPfx(
  buffer: Buffer,
  password: string,
  label?: string,
  verificationMethodIdOverride?: string,
): Signer {
  const pfx = parsePfx(buffer, password);
  return buildSigner(
    pfx.privateKey,
    pfx.publicKey,
    label,
    pfx.certificateChain,
    verificationMethodIdOverride,
  );
}

/**
 * Load material from a buffer and detect the format.
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
    case "pfx": {
      throw new CryptoError("PFX import requires a password — use buildSignerFromPfx() directly");
    }
  }
}

/**
 * Create a SoftwareSigner from a file path.
 *
 * Reads the file, detects the format, validates the data, and
 * returns a Signer instance. For PFX files, a password is required.
 *
 * Material stays in memory within this process. It is never
 * logged, serialised, or transmitted.
 *
 * @param filePath - Absolute path to the file on disk.
 * @param label - Optional user-friendly label.
 * @param password - Password for PFX files (required if format is PFX).
 * @returns An object containing the Signer and the detected format.
 * @throws {CryptoError} if the data is invalid, unsupported, or unreadable.
 */
export function createSoftwareSigner(
  filePath: string,
  label?: string,
  password?: string,
  verificationMethodIdOverride?: string,
): { signer: Signer; format: KeyFormat } {
  let content: Buffer;
  try {
    content = readFileSync(filePath);
  } catch (err) {
    throw new CryptoError("Failed to read key file", { cause: err });
  }

  const format = detectKeyFormat(content, filePath);

  if (format === "pfx") {
    if (!password) {
      throw new CryptoError("PFX import requires a password");
    }
    const signer = buildSignerFromPfx(content, password, label, verificationMethodIdOverride);
    return { signer, format };
  }

  try {
    const { privateKey, publicKey } = loadKeyFromBuffer(content, format);
    const signer = buildSigner(
      privateKey,
      publicKey,
      label,
      undefined,
      verificationMethodIdOverride,
    );
    return { signer, format };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to parse key file: ${error instanceof Error ? error.message : "unknown error"}`,
      { cause: error },
    );
  }
}

/**
 * Create a SoftwareSigner directly from material in memory.
 *
 * This is used internally when the content is already available
 * (e.g., from the import IPC handler). The data is never
 * stored -- only the resulting Signer is kept.
 *
 * @param content - The raw file content as a Buffer.
 * @param label - Optional user-friendly label.
 * @param password - Password for PFX files (required if format is PFX).
 * @param filenameHint - Optional filename to help detect PFX format.
 * @returns An object containing the Signer and the detected format.
 */
export function createSoftwareSignerFromBuffer(
  content: Buffer,
  label?: string,
  password?: string,
  filenameHint?: string,
  verificationMethodIdOverride?: string,
): { signer: Signer; format: KeyFormat } {
  const format = detectKeyFormat(content, filenameHint);

  if (format === "pfx") {
    if (!password) {
      throw new CryptoError("PFX import requires a password");
    }
    const signer = buildSignerFromPfx(content, password, label, verificationMethodIdOverride);
    return { signer, format };
  }

  try {
    const { privateKey, publicKey } = loadKeyFromBuffer(content, format);
    const signer = buildSigner(
      privateKey,
      publicKey,
      label,
      undefined,
      verificationMethodIdOverride,
    );
    return { signer, format };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to parse key: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}
