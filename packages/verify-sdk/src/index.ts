/**
 * @opencred/verify — public SDK for verifying OpenCred-issued credentials.
 *
 * This is a curated, single-install facade over the internal verification
 * engine (`@opencred/verification`) that powers the OpenCred Docker image
 * and Desktop Client. It exposes a minimal, ergonomic API for use in
 * third-party verifier services without exposing the internal package
 * structure or workspace deps.
 *
 * Usage:
 *
 * ```ts
 * import { createVerifier } from "@opencred/verify";
 *
 * const verify = createVerifier({
 *   // Optional: DeDi config for revocation checks + did:web fallback.
 *   // Omit to verify did:key / did:jwk credentials with zero infra.
 *   dedi: {
 *     baseUrl: "https://your-dedi-instance.example.org",
 *     namespace: "your-namespace",
 *     auth: { type: "api-key", apiKey: process.env.DEDI_API_KEY! },
 *   },
 *
 *   // Optional: PEM-encoded CSCA roots, for verifying DSC-signed credentials.
 *   trustAnchors: [process.env.CSCA_PEM!],
 * });
 *
 * const result = await verify(jwtCompactStringOrJsonLdVcObject);
 * if (result.verified) {
 *   // proceed
 * } else {
 *   console.log(result.code, result.checks);
 * }
 * ```
 *
 * For PDF inputs, use the `verifyPdf` helper:
 *
 * ```ts
 * import { createVerifier } from "@opencred/verify";
 * const verify = createVerifier();
 * const result = await verify.pdf(uint8ArrayOfPdfBytes);
 * ```
 */

import {
  verifyCredential as _verifyCredential,
  verifyPdf as _verifyPdf,
  detectFormat as _detectFormat,
  type CredentialVerificationResult,
  type VerificationCheck,
  type VerificationInput,
  type CredentialFormat,
  type VerificationResultCode,
  type VerifierConfig,
} from "@opencred/verification";

import {
  DIDKeyResolver,
  DIDJwkResolver,
  DIDWebResolver,
  CompositeDIDResolver,
  type DIDResolver,
} from "@opencred/did";

import { DeDiClient, createDeDiDIDWebFallback, type DeDiClientConfig } from "@opencred/dedi-client";

// -----------------------------------------------------------------------------
// Re-exports — types
// -----------------------------------------------------------------------------

export type {
  /** The full result returned by every verification call. */
  CredentialVerificationResult,
  /** One row in `result.checks`. */
  VerificationCheck,
  /** The credential or token being verified. */
  VerificationInput,
  /** The detected wire format. */
  CredentialFormat,
  /** The stable top-level result enum. */
  VerificationResultCode,
};

// -----------------------------------------------------------------------------
// Configuration shape — public API
// -----------------------------------------------------------------------------

/**
 * Configuration passed to {@link createVerifier}. Every field is optional —
 * with no config, the SDK verifies any `did:key` / `did:jwk` credential
 * fully offline.
 */
export interface VerifySdkOptions {
  /**
   * DeDi (Decentralized Directory) configuration. When present:
   *
   *  - The verifier checks revocation status for credentials with
   *    `credentialStatus` by querying the `vc-revocation-registry` registry.
   *  - The verifier checks each signing key's status (active / rotated /
   *    revoked) in the `opencred-key-registry`; a revoked key rejects the
   *    credential (`REVOKED`).
   *  - `did:web` resolution falls back to DeDi's `did-documents` registry
   *    when canonical HTTPS resolution fails.
   *
   * Omit for a pure offline verifier. Note that without DeDi, revocation
   * cannot be checked — credentials carrying a `credentialStatus` block
   * will verify as VALID even if they've been revoked, because there's no
   * way to query the registry. The skip is surfaced in `result.checks` as
   * a non-failing `revocation` row whose detail says the check was NOT
   * performed; strict relying parties can treat that row as a policy
   * failure.
   */
  dedi?: DeDiClientConfig;

  /**
   * PEM-encoded CSCA root certificates as an array of strings, used to
   * validate DSC chains (the `x5c` chain attached to credentials signed
   * by a Document Signer Certificate). Omit if you don't expect to
   * verify DSC-signed credentials.
   */
  trustAnchors?: string[];

  /**
   * Custom DID resolver. By default the SDK builds a CompositeDIDResolver
   * with `did:key`, `did:jwk`, and `did:web` (HTTPS, plus DeDi fallback if
   * `dedi` is configured). Override only if you need an exotic DID method
   * or want to disable HTTPS network access entirely.
   */
  didResolver?: DIDResolver;

  /**
   * Logger sink for DeDi operations (circuit-breaker events, retry warnings,
   * etc.). Defaults to a no-op.
   */
  logger?: {
    debug: (msg: string, ctx?: Record<string, unknown>) => void;
    info: (msg: string, ctx?: Record<string, unknown>) => void;
    warn: (msg: string, ctx?: Record<string, unknown>) => void;
    error: (msg: string, ctx?: Record<string, unknown>) => void;
  };
}

const noopLogger: NonNullable<VerifySdkOptions["logger"]> = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

// -----------------------------------------------------------------------------
// Public API — createVerifier factory
// -----------------------------------------------------------------------------

/**
 * The verifier function returned by {@link createVerifier}.
 *
 * Calling it with a JWT compact string, JSON-LD VC object, sd-jwt-vc string,
 * or bare PixelPass QR data string returns a `CredentialVerificationResult`.
 *
 * Use the `.pdf` method for binary PDF input.
 */
export interface Verifier {
  (input: VerificationInput): Promise<CredentialVerificationResult>;
  /**
   * Verify a credential embedded in an OpenCred-issued PDF. The credential
   * is read from the PDF's info-dictionary under the `OpenCredCredential`
   * key and verified end-to-end.
   */
  pdf(pdfBytes: Uint8Array): Promise<CredentialVerificationResult>;
}

/**
 * Build a verifier with the given configuration. The returned function and
 * its `.pdf` method are safe to call concurrently and can be reused across
 * many verifications.
 *
 * @example Zero-config verifier (handles did:key / did:jwk fully offline)
 * ```ts
 * const verify = createVerifier();
 * const result = await verify(jwt);
 * ```
 *
 * @example DeDi-backed verifier (revocation + did:web fallback)
 * ```ts
 * const verify = createVerifier({
 *   dedi: {
 *     baseUrl: "https://your-dedi.example.org",
 *     namespace: "your-namespace",
 *     auth: { type: "api-key", apiKey: process.env.DEDI_API_KEY! },
 *   },
 * });
 * ```
 */
export function createVerifier(options: VerifySdkOptions = {}): Verifier {
  const logger = options.logger ?? noopLogger;

  // Build the DeDi client first (if configured) — needed both for
  // revocation checks and for did:web resolution fallback.
  const dediClient = options.dedi ? new DeDiClient({ ...options.dedi, logger }) : null;

  // Build the DID resolver. Default: did:key + did:jwk + did:web (with
  // DeDi fallback if available). Consumer can override entirely.
  const didResolver: DIDResolver =
    options.didResolver ??
    new CompositeDIDResolver(
      new Map<string, DIDResolver>([
        ["key", new DIDKeyResolver()],
        ["jwk", new DIDJwkResolver()],
        ["web", new DIDWebResolver(dediClient ? createDeDiDIDWebFallback(dediClient) : undefined)],
      ]),
    );

  const verifierConfig: VerifierConfig = {
    didResolver,
    trustAnchors: options.trustAnchors,
    dediClient: dediClient ?? undefined,
  };

  // The public SDK contract is "always returns a CredentialVerificationResult"
  // — verifier services feed it untrusted input (QR scans, uploads), so an
  // undetectable format or an oversized token must come back as a structured
  // INVALID, not an exception. The internal engine throws typed errors for
  // these (the Docker image maps them to HTTP 400s); the facade is where
  // that contract changes.
  const toInvalidResult = (err: unknown): CredentialVerificationResult => ({
    code: "INVALID",
    verified: false,
    checks: [
      {
        name: "input",
        passed: false,
        detail: err instanceof Error ? err.message : "Input is not a verifiable credential",
      },
    ],
  });

  const fn = async (input: VerificationInput): Promise<CredentialVerificationResult> => {
    try {
      return await _verifyCredential(input, verifierConfig);
    } catch (err) {
      return toInvalidResult(err);
    }
  };

  (fn as Verifier).pdf = async (pdfBytes: Uint8Array) => {
    try {
      return await _verifyPdf(pdfBytes, verifierConfig);
    } catch (err) {
      return toInvalidResult(err);
    }
  };

  return fn as Verifier;
}

// -----------------------------------------------------------------------------
// Direct functional API — for callers that want to manage their own resolver
// -----------------------------------------------------------------------------

/**
 * One-shot verification helper. Equivalent to
 * `createVerifier(options)(input)`, but discards the verifier after the
 * call. Use {@link createVerifier} instead when verifying many credentials
 * — it avoids rebuilding the DID resolver and DeDi client every time.
 */
export async function verifyCredential(
  input: VerificationInput,
  options: VerifySdkOptions = {},
): Promise<CredentialVerificationResult> {
  return createVerifier(options)(input);
}

/**
 * One-shot PDF verification helper. Equivalent to
 * `createVerifier(options).pdf(pdfBytes)`.
 */
export async function verifyPdf(
  pdfBytes: Uint8Array,
  options: VerifySdkOptions = {},
): Promise<CredentialVerificationResult> {
  return createVerifier(options).pdf(pdfBytes);
}

/**
 * Inspect the wire format of an input string without verifying it.
 * Useful when you want to route by format (e.g. show different UI for a
 * JWT vs. a PDF reference) before calling the verifier.
 */
export function detectFormat(input: VerificationInput): CredentialFormat {
  return _detectFormat(input);
}
