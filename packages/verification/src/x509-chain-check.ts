/**
 * X.509 certificate chain verification.
 *
 * Validates the x5c certificate chain embedded in a credential's proof,
 * linking the signing key back to a DSC (Digital Signature Certificate)
 * and to a configured CSCA (Country Signing Certificate Authority) trust
 * anchor.
 *
 * The x5c field follows JOSE conventions (RFC 7517 §4.7): an array of
 * base64-encoded DER certificates, leaf (DSC) first.
 *
 * Checks performed when `x5c` is present:
 *  1. The leaf certificate's public key matches the credential's signing key
 *     (resolved via the DID document of `proof.verificationMethod`).
 *  2. Each certificate in the chain was signed by the next (chain-of-trust).
 *  3. The chain terminates in (or chains to) one of the configured trust
 *     anchors. If no trust anchors are configured the check fails closed.
 *  4. No certificate in the chain is expired at the credential's
 *     proof.created time.
 *
 * SECURITY: This check fails CLOSED. If `x5c` is present but the DID public
 * key cannot be resolved, the trust anchor list is empty, or the chain does
 * not terminate at a trusted root, the check returns `passed: false` with a
 * detail explaining which check failed. Silently passing on incomplete trust
 * data was the bug fixed in nfh-trust-labs/opencred#316.
 */

import { readdir, readFile } from "node:fs/promises";
import { createHash, createPublicKey, type KeyObject, X509Certificate } from "node:crypto";
import path from "node:path";
import type { DIDResolver, JWK } from "@opencred/did";
import { publicKeyFromMultibase } from "./key-utils.js";
import type { VerificationCheck } from "./types.js";

/**
 * Options for X.509 chain verification.
 */
export interface X509ChainCheckOptions {
  /**
   * DID resolver used to fetch the credential issuer's published verification
   * method, so the leaf certificate's public key can be bound to the DID.
   */
  didResolver?: DIDResolver;

  /**
   * PEM-encoded trust anchor certificates (e.g. CSCA roots). Required when a
   * credential carries an `x5c` chain — the check fails closed if no trust
   * anchors are supplied.
   */
  trustAnchors?: string[];
}

/**
 * Options for `loadCscaTrustStore`.
 */
export interface LoadCscaTrustStoreOptions {
  /**
   * Called when a trust-store entry is skipped — either because the whole
   * directory is unreadable, a candidate file can't be read, or a candidate
   * file contains no PEM certificate blocks. Callers should wire this to
   * their own logger (e.g. `pino.warn`) so operators can detect a misconfigured
   * or partially corrupt trust store instead of silently running with fewer
   * anchors than expected. Not called for non-candidate extensions (e.g.
   * `README.md`), only for entries the loader actively tried to load.
   */
  onSkipped?: (info: { path: string; reason: string }) => void;
}

/**
 * Load all PEM-encoded certificates from a directory.
 *
 * Used to populate the trust anchor list from a `CSCA_TRUST_STORE_PATH`
 * directory containing one or more `.pem` / `.crt` / `.cer` files. Returns
 * an empty array if the directory does not exist or contains no PEM files.
 *
 * Each returned string is a complete PEM block (single certificate); files
 * containing multiple concatenated certificates are split.
 *
 * Files that are skipped (unreadable, non-PEM content, or a missing
 * directory) are surfaced via the optional `onSkipped` callback. This
 * package does not import a logger — pass a callback that forwards to your
 * application's logger so a partial or misconfigured trust store never
 * loads silently. The downstream chain check still fails closed if the
 * trust store is empty, but an operator-visible warning is the difference
 * between "DSC verification mysteriously rejects everything" and "warn
 * surfaced 'CSCA_TRUST_STORE_PATH directory not found'".
 */
export async function loadCscaTrustStore(
  directory: string,
  options?: LoadCscaTrustStoreOptions,
): Promise<string[]> {
  const onSkipped = options?.onSkipped;
  let entries: string[];
  try {
    entries = await readdir(directory);
  } catch (err) {
    onSkipped?.({
      path: directory,
      reason: `unable to read trust store directory: ${err instanceof Error ? err.message : "unknown error"}`,
    });
    return [];
  }

  const pems: string[] = [];
  for (const entry of entries) {
    const lower = entry.toLowerCase();
    if (!lower.endsWith(".pem") && !lower.endsWith(".crt") && !lower.endsWith(".cer")) {
      continue;
    }
    const fullPath = path.join(directory, entry);
    let content: string;
    try {
      content = await readFile(fullPath, "utf8");
    } catch (err) {
      onSkipped?.({
        path: fullPath,
        reason: `read failed: ${err instanceof Error ? err.message : "unknown error"}`,
      });
      continue;
    }
    const blocks = splitPemBlocks(content);
    if (blocks.length === 0) {
      onSkipped?.({
        path: fullPath,
        reason: "no PEM certificate blocks found",
      });
      continue;
    }
    for (const block of blocks) {
      pems.push(block);
    }
  }
  return pems;
}

/**
 * Split a PEM string that may contain multiple concatenated certificates
 * into individual single-certificate PEM blocks. Lines outside CERTIFICATE
 * blocks are ignored. Each returned block ends with a trailing newline.
 */
function splitPemBlocks(input: string): string[] {
  const blocks: string[] = [];
  const lines = input.split(/\r?\n/);
  let inBlock = false;
  let buffer: string[] = [];
  for (const line of lines) {
    if (line.includes("-----BEGIN CERTIFICATE-----")) {
      inBlock = true;
      buffer = [line];
      continue;
    }
    if (inBlock) {
      buffer.push(line);
      if (line.includes("-----END CERTIFICATE-----")) {
        blocks.push(buffer.join("\n") + "\n");
        inBlock = false;
        buffer = [];
      }
    }
  }
  return blocks;
}

/**
 * Compute a SHA-256 fingerprint over a public key's SPKI DER encoding.
 *
 * This is the canonical way to compare two public keys without depending on
 * key-type-specific JWK fields. Two keys produce the same fingerprint iff
 * they encode the same public key material.
 */
function spkiFingerprint(key: KeyObject): string {
  const der = key.export({ format: "der", type: "spki" });
  return createHash("sha256").update(der).digest("hex");
}

/**
 * Extract the public key (as a KeyObject) from a DID's verification method.
 * Returns `null` if the DID cannot be resolved, the verification method id
 * does not match, or the VM does not contain a recognised key encoding.
 *
 * SECURITY: The lookup is strict — the verification method `id` published in
 * the DID document must match the credential's `verificationMethod` exactly
 * (or the bare fragment must match a relative-id verification method). The
 * URL fragment is NEVER decoded as key material. See
 * nfh-trust-labs/opencred#311.
 */
async function resolveDidPublicKey(
  verificationMethod: string,
  resolver?: DIDResolver,
): Promise<KeyObject | null> {
  if (!resolver || typeof verificationMethod !== "string" || verificationMethod.length === 0) {
    return null;
  }

  const did = verificationMethod.split("#")[0];
  if (!did) {
    return null;
  }

  let result;
  try {
    result = await resolver.resolve(did);
  } catch {
    return null;
  }

  const doc = result.didDocument;
  if (!doc || !doc.verificationMethod || doc.verificationMethod.length === 0) {
    return null;
  }

  const fragmentId = verificationMethod.includes("#")
    ? `#${verificationMethod.split("#").slice(1).join("#")}`
    : undefined;

  const vm = doc.verificationMethod.find(
    (v) => v.id === verificationMethod || (fragmentId !== undefined && v.id === fragmentId),
  );

  if (!vm) {
    return null;
  }

  if (vm.publicKeyMultibase) {
    return publicKeyFromMultibase(vm.publicKeyMultibase) ?? null;
  }

  if (vm.publicKeyJwk) {
    try {
      return createPublicKey({ key: vm.publicKeyJwk as JWK, format: "jwk" });
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Parse a base64-encoded DER certificate into an X509Certificate.
 */
function parseX5cCert(base64Der: string): X509Certificate {
  const pem = `-----BEGIN CERTIFICATE-----\n${base64Der}\n-----END CERTIFICATE-----`;
  return new X509Certificate(pem);
}

/**
 * Check whether the leaf certificate's public key matches the DID's public key.
 *
 * Comparison is done over the SPKI fingerprint, which works uniformly for
 * EC and RSA keys.
 */
function checkKeyBinding(leafCert: X509Certificate, didPublicKey: KeyObject): boolean {
  try {
    return spkiFingerprint(leafCert.publicKey) === spkiFingerprint(didPublicKey);
  } catch {
    return false;
  }
}

/**
 * Validate the certificate chain's temporal bounds at a specific point in time.
 * Each certificate must be valid (not before / not after) at the given time.
 */
function checkChainTemporal(certs: X509Certificate[], proofTime: Date): string | null {
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const notBefore = new Date(cert.validFrom);
    const notAfter = new Date(cert.validTo);
    const label = i === 0 ? "Leaf (DSC)" : `Chain certificate [${i}]`;

    if (proofTime < notBefore) {
      return `${label} was not yet valid at credential signing time (notBefore: ${cert.validFrom})`;
    }
    if (proofTime > notAfter) {
      return `${label} had expired at credential signing time (notAfter: ${cert.validTo})`;
    }
  }
  return null;
}

/**
 * Validate that each certificate in the chain was signed by the next.
 * cert[0] should be signed by cert[1], cert[1] by cert[2], etc.
 */
function checkChainSignatures(certs: X509Certificate[]): string | null {
  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const parent = certs[i + 1];

    if (!child.checkIssued(parent)) {
      return `Certificate [${i}] was not issued by certificate [${i + 1}] (issuer/subject mismatch)`;
    }

    try {
      if (!child.verify(parent.publicKey)) {
        return `Certificate [${i}] signature does not verify against certificate [${i + 1}]`;
      }
    } catch {
      return `Certificate [${i}] signature verification failed against certificate [${i + 1}]`;
    }
  }
  return null;
}

/**
 * Verify that the chain terminates at one of the configured trust anchors.
 *
 * Walks from the top of the supplied chain outward and looks for a trust
 * anchor that either (a) IS the top-of-chain certificate (matching by SPKI
 * fingerprint via `checkIssued` against itself) or (b) signed the
 * top-of-chain certificate. Returns the matching anchor's subject string when
 * found, or `null` when no anchor accepts the chain.
 */
function findAnchor(
  chain: X509Certificate[],
  trustAnchors: X509Certificate[],
): X509Certificate | null {
  if (chain.length === 0 || trustAnchors.length === 0) {
    return null;
  }
  const topOfChain = chain[chain.length - 1];

  // Case 1: the top-of-chain certificate IS one of the trust anchors.
  // Match by issuer/subject identity AND signature self-verification.
  for (const anchor of trustAnchors) {
    if (
      anchor.subject === topOfChain.subject &&
      anchor.fingerprint256 === topOfChain.fingerprint256
    ) {
      return anchor;
    }
  }

  // Case 2: the top-of-chain certificate was issued by one of the trust
  // anchors. The anchor itself is not in the x5c.
  for (const anchor of trustAnchors) {
    try {
      if (topOfChain.checkIssued(anchor) && topOfChain.verify(anchor.publicKey)) {
        return anchor;
      }
    } catch {
      // Try next anchor.
    }
  }

  return null;
}

/**
 * Check the X.509 certificate chain embedded in a credential's proof.
 *
 * If the credential has no x5c field, this check is skipped (returns passed) —
 * the credential is not DSC-backed and trust comes from elsewhere (e.g. did:web
 * + TLS PKI).
 *
 * When x5c is present, the chain is validated end-to-end:
 *  1. Parse all certificates.
 *  2. Verify the leaf cert's public key matches the signing DID. Fails closed
 *     if the DID cannot be resolved or has no matching verification method.
 *  3. Verify chain-of-trust signatures.
 *  4. Verify the chain terminates at a configured trust anchor. Fails closed
 *     if no trust anchors are configured.
 *  5. Verify all certificates were valid at proof.created time.
 */
export async function checkX509Chain(
  credential: Record<string, unknown>,
  options: X509ChainCheckOptions = {},
): Promise<VerificationCheck> {
  const proof = credential["proof"] as Record<string, unknown> | undefined;
  if (!proof) {
    return { name: "x509-chain", passed: true, detail: "No proof — X.509 chain check skipped" };
  }

  const x5c = proof["x5c"] as string[] | undefined;
  if (!x5c || !Array.isArray(x5c) || x5c.length === 0) {
    return {
      name: "x509-chain",
      passed: true,
      detail: "No x5c certificate chain — not a DSC-backed credential",
    };
  }

  // x5c IS present — every check below must fail closed if it cannot be
  // satisfied.

  // Parse all certificates first; without parseable certs nothing else can be
  // checked.
  let certs: X509Certificate[];
  try {
    certs = x5c.map(parseX5cCert);
  } catch (err) {
    return {
      name: "x509-chain",
      passed: false,
      detail: `Failed to parse x5c certificates: ${err instanceof Error ? err.message : "unknown error"}`,
    };
  }

  if (certs.length === 0) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "x5c chain is empty",
    };
  }

  // Check 1: Bind leaf certificate to the credential's signing DID. The DID
  // resolution MUST succeed and yield a public key matching the leaf — silent
  // skipping (the previous behaviour) is the bug fixed by #316.
  const verificationMethod = proof["verificationMethod"] as string | undefined;
  if (!verificationMethod) {
    return {
      name: "x509-chain",
      passed: false,
      detail:
        "Credential has x5c but no proof.verificationMethod — cannot bind certificate to issuer",
    };
  }

  const didPubKey = await resolveDidPublicKey(verificationMethod, options.didResolver);
  if (!didPubKey) {
    return {
      name: "x509-chain",
      passed: false,
      detail:
        "Unable to confirm leaf certificate matches credential issuer (DID could not be resolved or has no matching verification method)",
    };
  }
  if (!checkKeyBinding(certs[0], didPubKey)) {
    return {
      name: "x509-chain",
      passed: false,
      detail:
        "X.509 chain invalid: leaf certificate public key does not match the signing DID's public key",
    };
  }

  // Check 2: Chain-of-trust signatures (if more than one cert).
  if (certs.length > 1) {
    const chainError = checkChainSignatures(certs);
    if (chainError) {
      return {
        name: "x509-chain",
        passed: false,
        detail: `X.509 chain invalid: ${chainError}`,
      };
    }
  }

  // Check 3: Chain MUST terminate at a configured trust anchor. The previous
  // behaviour ("self-signed or root not included") silently accepted any chain
  // — exactly the false-sense-of-security flaw reported in #316. Fail closed
  // when no trust anchors are configured or the chain doesn't reach one.
  const trustAnchorPems = options.trustAnchors ?? [];
  if (trustAnchorPems.length === 0) {
    return {
      name: "x509-chain",
      passed: false,
      detail:
        "X.509 chain check requires a configured trust anchor (set CSCA_TRUST_STORE_PATH or pass trustAnchors to the verifier)",
    };
  }

  let trustAnchorCerts: X509Certificate[];
  try {
    trustAnchorCerts = trustAnchorPems.map((pem) => new X509Certificate(pem));
  } catch (err) {
    return {
      name: "x509-chain",
      passed: false,
      detail: `Failed to parse configured trust anchors: ${err instanceof Error ? err.message : "unknown error"}`,
    };
  }

  const anchor = findAnchor(certs, trustAnchorCerts);
  if (!anchor) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "X.509 chain invalid: chain does not terminate at a configured trust anchor",
    };
  }

  // Check 4: Temporal validity at proof.created time. Validate the
  // presented chain AND the resolved trust anchor (a recently-expired CA must
  // not be honoured).
  const proofCreated = proof["created"] as string | undefined;
  if (proofCreated) {
    const proofTime = new Date(proofCreated);
    if (!isNaN(proofTime.getTime())) {
      const temporalError = checkChainTemporal([...certs, anchor], proofTime);
      if (temporalError) {
        return {
          name: "x509-chain",
          passed: false,
          detail: `X.509 chain invalid: ${temporalError}`,
        };
      }
    }
  }

  const leaf = certs[0];
  return {
    name: "x509-chain",
    passed: true,
    detail: `DSC verified (${leaf.subject}), chain depth: ${certs.length}, anchored to ${anchor.subject}`,
  };
}
