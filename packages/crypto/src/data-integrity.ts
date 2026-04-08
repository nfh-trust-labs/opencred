import { createSign, createVerify, type KeyObject } from "node:crypto";
import * as _jsonldNs from "jsonld";

// jsonld is a CJS package; when loaded via ESM loaders (e.g. tsx) the namespace
// import may wrap the real module under `.default`.  Resolve once at load time.
const jsonld: typeof _jsonldNs =
  (_jsonldNs as unknown as { default?: typeof _jsonldNs }).default ?? _jsonldNs;
import { CryptoError } from "@opencred/shared";
import { createDocumentLoader } from "@opencred/vc-core";
import type { UnsignedCredential, VerifiableCredential, Proof } from "@opencred/vc-core";
import { sha256, sha384 } from "./hash.js";
import type {
  SigningAlgorithm,
  ProofOptions,
  PreparedProof,
  SigningKey,
  VerificationResult,
  VerifyOptions,
  ProofConfig,
} from "./types.js";

const CRYPTOSUITE = "ecdsa-rdfc-2019" as const;
const PROOF_TYPE = "DataIntegrityProof" as const;

/**
 * Adapt the bundled vc-core document loader for use with the jsonld library.
 * The jsonld library at runtime accepts a simple async loader, but @types/jsonld
 * declares an older callback-based signature. We cast to satisfy the types.
 */
function createJsonLdDocumentLoader(): _jsonldNs.Options.DocLoader["documentLoader"] {
  const bundledLoader = createDocumentLoader();
  const loader = async (url: string) => {
    const result = bundledLoader(url);
    return {
      contextUrl: result.contextUrl ?? undefined,
      documentUrl: result.documentUrl,
      document: result.document,
    };
  };
  // The jsonld runtime accepts Promise-based loaders; the @types are imprecise
  return loader as unknown as _jsonldNs.Options.DocLoader["documentLoader"];
}

/**
 * Canonicalize a JSON-LD document using RDFC-1.0 (URDNA2015).
 *
 * Strict (safe) mode is **enabled by default**.  This is a hard security
 * requirement: when canonicalizing a credential for signing, any field that
 * is not defined in the loaded JSON-LD contexts is silently dropped from the
 * canonical N-Quads form, never gets hashed, and therefore never gets covered
 * by the resulting signature.  An attacker who can modify the credential post
 * facto could change those undefined fields and the signature would still
 * verify — a critical signature-coverage gap.  Enabling `safe: true` causes
 * `jsonld.canonize` to *throw* on any undefined term, forcing every claim to
 * be properly typed in a context before it can be signed.
 *
 * Callers must explicitly pass `{ strict: false }` to opt out.  Do **not** opt
 * out for issuance or verification of Verifiable Credentials — the only
 * legitimate use cases are debugging, tooling that intentionally inspects
 * non-conforming JSON-LD, or one-off canonicalization of documents whose
 * vocabularies are known to be partial.  Opting out re-introduces the
 * silent-field-drop attack surface described above.
 */
export async function canonicalize(
  document: Record<string, unknown>,
  options?: { strict?: boolean },
): Promise<string> {
  // Cast to JsonLdDocument since our documents are valid JSON-LD NodeObjects.
  // The `safe` option is supported by jsonld 8.x at runtime but not yet in
  // @types/jsonld, so we cast the options to include it.  Strict mode is
  // ON by default (`safe: true`); see the JSDoc above for the rationale.
  const result = await jsonld.canonize(
    document as _jsonldNs.JsonLdDocument,
    {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader: createJsonLdDocumentLoader(),
      safe: options?.strict ?? true,
    } as _jsonldNs.Options.Normalize & { safe: boolean },
  );
  return result as string;
}

/**
 * Build a proof configuration object from proof options and the document's @context.
 */
function buildProofConfig(
  unsignedVC: UnsignedCredential,
  options: ProofOptions,
  cryptosuite: string = CRYPTOSUITE,
): ProofConfig {
  const config: ProofConfig = {
    "@context": unsignedVC["@context"] as (string | Record<string, unknown>)[],
    type: PROOF_TYPE,
    cryptosuite,
    created: options.created ?? new Date().toISOString(),
    verificationMethod: options.verificationMethod,
    proofPurpose: options.proofPurpose,
  };
  if (options.domain) {
    config.domain = options.domain;
  }
  if (options.challenge) {
    config.challenge = options.challenge;
  }
  return config;
}

/**
 * Compute the data to sign for an ecdsa-rdfc-2019 proof.
 *
 * Per the W3C ecdsa-rdfc-2019 spec:
 * - P-256: SHA-256(canonicalized proofConfig) || SHA-256(canonicalized document)
 * - P-384: SHA-384(canonicalized proofConfig) || SHA-384(canonicalized document)
 *
 * `strict` defaults to `true` and is forwarded to both `canonicalize()` calls
 * (proof config and document).  See `canonicalize()` for the security rationale
 * — leaving this `true` is the only safe choice for credential issuance and
 * verification.
 */
export async function computeSigningInput(
  document: Record<string, unknown>,
  proofConfig: ProofConfig,
  hashAlgorithm: "sha256" | "sha384" = "sha256",
  strict: boolean = true,
): Promise<Uint8Array> {
  const hash = hashAlgorithm === "sha384" ? sha384 : sha256;

  // Canonicalize the proof config (without @context for the canonical form, spec says include it)
  const canonicalProofConfig = await canonicalize(
    proofConfig as unknown as Record<string, unknown>,
    { strict },
  );
  const proofConfigHash = hash(canonicalProofConfig);

  // Canonicalize the document (without proof)
  const canonicalDocument = await canonicalize(document, { strict });
  const documentHash = hash(canonicalDocument);

  // Concatenate: hash(proofConfig) || hash(document)
  const result = new Uint8Array(proofConfigHash.length + documentHash.length);
  result.set(proofConfigHash, 0);
  result.set(documentHash, proofConfigHash.length);
  return result;
}

/**
 * Encode bytes as multibase base58btc (prefix 'z').
 */
function multibaseEncode(bytes: Uint8Array): string {
  // base58btc encode
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt(0);
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  let encoded = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    encoded = ALPHABET[remainder] + encoded;
  }

  // Preserve leading zeros
  for (const byte of bytes) {
    if (byte === 0) {
      encoded = "1" + encoded;
    } else {
      break;
    }
  }

  return "z" + encoded;
}

/**
 * Decode a multibase base58btc string (prefix 'z').
 */
function multibaseDecode(encoded: string): Uint8Array {
  if (!encoded.startsWith("z")) {
    throw new CryptoError("Invalid multibase encoding: expected base58btc prefix 'z'");
  }
  const base58str = encoded.slice(1);
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let num = BigInt(0);
  for (const char of base58str) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) {
      throw new CryptoError("Invalid base58btc character");
    }
    num = num * 58n + BigInt(index);
  }

  // Convert to bytes
  const hex = num.toString(16);
  const paddedHex = hex.length % 2 ? "0" + hex : hex;
  const bytes: number[] = [];
  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
  }

  // Preserve leading zeros
  let leadingZeros = 0;
  for (const char of base58str) {
    if (char === "1") {
      leadingZeros++;
    } else {
      break;
    }
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  // Leading zeros are already zero in Uint8Array
  result.set(bytes, leadingZeros);
  return result;
}

/**
 * Convert an ECDSA DER signature to raw r||s format.
 * P-256: 64 bytes (32 + 32), P-384: 96 bytes (48 + 48).
 *
 * @param derSig - DER-encoded ECDSA signature.
 * @param componentSize - Size of each r/s component: 32 for P-256, 48 for P-384. Defaults to 32.
 */
function derToRaw(derSig: Uint8Array, componentSize: number = 32): Uint8Array {
  // DER: 0x30 <totalLen> 0x02 <rLen> <r> 0x02 <sLen> <s>
  let offset = 2; // skip 0x30 and totalLen
  if (derSig[0] !== 0x30) {
    throw new CryptoError("Invalid DER signature");
  }

  // Parse r
  if (derSig[offset] !== 0x02) {
    throw new CryptoError("Invalid DER signature: expected integer tag for r");
  }
  offset++;
  const rLen = derSig[offset];
  offset++;
  let r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  // Parse s
  if (derSig[offset] !== 0x02) {
    throw new CryptoError("Invalid DER signature: expected integer tag for s");
  }
  offset++;
  const sLen = derSig[offset];
  offset++;
  let s = derSig.slice(offset, offset + sLen);

  // Remove leading zero padding (DER uses signed integers)
  while (r.length > componentSize && r[0] === 0) r = r.slice(1);
  while (s.length > componentSize && s[0] === 0) s = s.slice(1);

  // Pad to componentSize bytes each
  const totalSize = componentSize * 2;
  const raw = new Uint8Array(totalSize);
  raw.set(r, componentSize - r.length);
  raw.set(s, totalSize - s.length);
  return raw;
}

/**
 * Convert a raw r||s signature to DER format.
 * Accepts 64 bytes (P-256) or 96 bytes (P-384).
 */
function rawToDer(rawSig: Uint8Array): Uint8Array {
  if (rawSig.length !== 64 && rawSig.length !== 96) {
    throw new CryptoError("Raw signature must be 64 bytes (P-256) or 96 bytes (P-384)");
  }
  const componentSize = rawSig.length / 2;
  let r = rawSig.slice(0, componentSize);
  let s = rawSig.slice(componentSize);

  // Add leading zero if high bit is set (DER signed integer)
  if (r[0] & 0x80) {
    const padded = new Uint8Array(componentSize + 1);
    padded.set(r, 1);
    r = padded;
  }
  if (s[0] & 0x80) {
    const padded = new Uint8Array(componentSize + 1);
    padded.set(s, 1);
    s = padded;
  }

  // Strip leading zeros (but keep at least one byte, and keep the zero if high bit would be set)
  while (r.length > 1 && r[0] === 0 && !(r[1] & 0x80)) {
    r = r.slice(1);
  }
  while (s.length > 1 && s[0] === 0 && !(s[1] & 0x80)) {
    s = s.slice(1);
  }

  const totalLen = 2 + r.length + 2 + s.length;
  const der = new Uint8Array(2 + totalLen);
  let offset = 0;
  der[offset++] = 0x30; // SEQUENCE
  der[offset++] = totalLen;
  der[offset++] = 0x02; // INTEGER
  der[offset++] = r.length;
  der.set(r, offset);
  offset += r.length;
  der[offset++] = 0x02; // INTEGER
  der[offset++] = s.length;
  der.set(s, offset);
  return der;
}

/**
 * Prepare a Data Integrity proof for external (Interface) signing.
 *
 * This is phase 1 of the two-phase signing flow. It computes the data that
 * needs to be signed and returns it along with the proof configuration.
 * The caller signs the data externally (e.g., in a browser using SubtleCrypto)
 * and then calls `completeProof()` to assemble the final credential.
 *
 * @param unsignedVC — The unsigned credential to prepare a proof for.
 * @param options — Proof options (verificationMethod, proofPurpose, etc.).
 * @returns PreparedProof containing dataToSign bytes and proofConfig.
 * @throws {CryptoError} if canonicalization or hashing fails.
 */
export async function prepareProof(
  unsignedVC: UnsignedCredential,
  options: ProofOptions,
  algorithm: SigningAlgorithm = "P-256",
): Promise<PreparedProof> {
  if (!options.verificationMethod) {
    throw new CryptoError("verificationMethod is required");
  }
  if (!options.proofPurpose) {
    throw new CryptoError("proofPurpose is required");
  }

  const hashAlg = algorithm === "P-384" ? "sha384" : "sha256";

  try {
    const proofConfig = buildProofConfig(unsignedVC, options);
    const document = unsignedVC as unknown as Record<string, unknown>;
    const dataToSign = await computeSigningInput(document, proofConfig, hashAlg);

    return { dataToSign, proofConfig };
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Failed to prepare proof: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Complete a Data Integrity proof with an externally-produced signature.
 *
 * This is phase 2 of the two-phase signing flow. It takes the signature
 * bytes produced by the external signer and assembles the final VerifiableCredential.
 *
 * @param credential — The unsigned credential.
 * @param proofConfig — The proof configuration from `prepareProof()`.
 * @param signatureBytes — The raw ECDSA signature bytes (r || s, 64 bytes for P-256).
 * @returns VerifiableCredential with the attached Data Integrity proof.
 * @throws {CryptoError} if the signature is malformed.
 */
export function completeProof(
  credential: UnsignedCredential,
  proofConfig: ProofConfig,
  signatureBytes: Uint8Array,
): VerifiableCredential {
  if (signatureBytes.length !== 64 && signatureBytes.length !== 96) {
    throw new CryptoError("Signature must be 64 bytes (P-256) or 96 bytes (P-384) raw r||s ECDSA");
  }

  const proofValue = multibaseEncode(signatureBytes);

  const proof: Proof = {
    type: proofConfig.type,
    cryptosuite: proofConfig.cryptosuite,
    created: proofConfig.created,
    verificationMethod: proofConfig.verificationMethod,
    proofPurpose: proofConfig.proofPurpose,
    proofValue,
  };

  if (proofConfig.domain) {
    proof.domain = proofConfig.domain;
  }
  if (proofConfig.challenge) {
    proof.challenge = proofConfig.challenge;
  }

  return { ...credential, proof };
}

/**
 * Sign a credential with a Data Integrity proof (Delegated Signing).
 *
 * This is the full signing path where the private key is available server-side.
 * The key stays within the OpenCred process and is never transmitted.
 *
 * @param unsignedVC — The unsigned credential to sign.
 * @param signingKey — The signing key (OpenCred-managed).
 * @param options — Proof options.
 * @returns VerifiableCredential with the attached Data Integrity proof.
 * @throws {CryptoError} if signing fails.
 */
export async function signCredential(
  unsignedVC: UnsignedCredential,
  signingKey: SigningKey,
  options: ProofOptions,
): Promise<VerifiableCredential> {
  const { signAlg } = ecdsaParams(signingKey.algorithm);

  const { dataToSign, proofConfig } = await prepareProof(
    unsignedVC,
    {
      ...options,
      verificationMethod: options.verificationMethod || signingKey.id,
    },
    signingKey.algorithm,
  );

  try {
    const signer = createSign(signAlg);
    signer.update(dataToSign);
    const rawSignature = signer.sign({
      key: signingKey.privateKey,
      dsaEncoding: "ieee-p1363",
    });

    return completeProof(unsignedVC, proofConfig, new Uint8Array(rawSignature));
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Signing failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Get ECDSA hash and signing algorithm parameters for a given key algorithm.
 */
function ecdsaParams(algorithm: SigningAlgorithm): {
  hashAlg: "sha256" | "sha384";
  signAlg: string;
} {
  switch (algorithm) {
    case "P-256":
      return { hashAlg: "sha256", signAlg: "SHA256" };
    case "P-384":
      return { hashAlg: "sha384", signAlg: "SHA384" };
    default:
      throw new CryptoError(
        `Algorithm ${algorithm} is not supported for Data Integrity proofs. Use JWS for RSA keys.`,
      );
  }
}

/**
 * Verify a Data Integrity proof on a VerifiableCredential.
 *
 * @param credential — The credential with proof to verify.
 * @param options — Verification options (e.g., a pre-resolved public key).
 * @returns VerificationResult indicating success or failure with error detail.
 */
export async function verifyProof(
  credential: VerifiableCredential,
  options?: VerifyOptions,
): Promise<VerificationResult> {
  try {
    const { proof } = credential;
    if (!proof) {
      return { verified: false, error: "Credential has no proof" };
    }
    if (proof.type !== PROOF_TYPE) {
      return {
        verified: false,
        error: `Unsupported proof type: ${proof.type}`,
      };
    }
    if (proof.cryptosuite !== CRYPTOSUITE) {
      return {
        verified: false,
        error: `Unsupported cryptosuite: ${proof.cryptosuite}`,
      };
    }
    if (!proof.proofValue) {
      return { verified: false, error: "Proof has no proofValue" };
    }

    // Decode signature from proofValue
    const signatureBytes = multibaseDecode(proof.proofValue);
    if (signatureBytes.length !== 64 && signatureBytes.length !== 96) {
      return {
        verified: false,
        error: "Invalid signature length: expected 64 (P-256) or 96 (P-384) bytes",
      };
    }

    // Detect curve from signature length
    const isP384 = signatureBytes.length === 96;
    const hashAlg: "sha256" | "sha384" = isP384 ? "sha384" : "sha256";
    const signAlg = isP384 ? "SHA384" : "SHA256";

    // Resolve public key
    const publicKey = resolvePublicKey(credential, options);
    if (!publicKey) {
      return {
        verified: false,
        error: "Unable to resolve public key from verificationMethod",
      };
    }

    // Reconstruct the proof config
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { proof: _proof, ...unsignedDoc } = credential;
    const proofConfig: ProofConfig = {
      "@context": credential["@context"] as (string | Record<string, unknown>)[],
      type: proof.type as "DataIntegrityProof",
      cryptosuite: proof.cryptosuite as string,
      created: proof.created,
      verificationMethod: proof.verificationMethod,
      proofPurpose: proof.proofPurpose,
    };
    if (proof.domain) {
      proofConfig.domain = proof.domain as string;
    }
    if (proof.challenge) {
      proofConfig.challenge = proof.challenge as string;
    }

    // Compute the signing input with correct hash algorithm
    const dataToVerify = await computeSigningInput(
      unsignedDoc as Record<string, unknown>,
      proofConfig,
      hashAlg,
    );

    // Verify ECDSA signature
    const verifier = createVerify(signAlg);
    verifier.update(dataToVerify);
    const verified = verifier.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, signatureBytes);

    return verified
      ? { verified: true }
      : { verified: false, error: "Signature verification failed" };
  } catch (error) {
    // Re-throw programming bugs so they surface
    // instead of being silently swallowed as verification failures.
    if (
      error instanceof TypeError ||
      error instanceof ReferenceError ||
      error instanceof SyntaxError ||
      error instanceof RangeError
    ) {
      throw error;
    }
    return {
      verified: false,
      error: `Verification error: ${error instanceof Error ? error.message : "unknown error"}`,
    };
  }
}

/**
 * Resolve a public key for verification.
 * Currently supports: direct key via options, did:key resolution.
 */
function resolvePublicKey(
  _credential: VerifiableCredential,
  options?: VerifyOptions,
): KeyObject | undefined {
  if (options?.publicKey) {
    return options.publicKey;
  }
  // Future: resolve from did:key, did:web, etc.
  return undefined;
}

// Export the encoding helpers for testing and for use by other packages
export { multibaseEncode, multibaseDecode, derToRaw, rawToDer, buildProofConfig };
