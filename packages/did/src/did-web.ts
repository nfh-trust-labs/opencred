/**
 * did:web resolution — resolves DIDs hosted at HTTPS well-known endpoints.
 *
 * Used for the Self-Published Keys workflow where issuers publish their
 * public key at `.well-known/did.json` on their domain.
 *
 * Spec: https://w3c-ccg.github.io/did-method-web/
 */

import { promises as dns } from "node:dns";
import { DIDResolutionError, isPrivateIP } from "@opencred/shared";
import type { DIDDocument, DIDResolutionResult, JWK, VerificationMethod } from "./types.js";
import type { DIDResolver } from "./resolver.js";

/** Timeout for DID document fetch requests (milliseconds). */
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Encode a domain (and optional path segments) as a did:web identifier.
 *
 * Follows the did:web spec encoding rules:
 * - Colons in the domain (e.g., port numbers) are percent-encoded as `%3A`
 * - Path segments are separated by colons
 *
 * @example
 * encodeDidWeb("example.com") // "did:web:example.com"
 * encodeDidWeb("example.com:3000") // "did:web:example.com%3A3000"
 * encodeDidWeb("example.com", ["path", "to"]) // "did:web:example.com:path:to"
 *
 * @param domain - The domain name, optionally including a port (e.g., "example.com:3000").
 * @param path - Optional path segments beneath the domain.
 * @returns The did:web DID string.
 */
export function encodeDidWeb(domain: string, path?: string[]): string {
  // Percent-encode colons in the domain (port separator)
  const encodedDomain = domain.replace(/:/g, "%3A");

  if (path && path.length > 0) {
    return `did:web:${encodedDomain}:${path.join(":")}`;
  }
  return `did:web:${encodedDomain}`;
}

/**
 * Get the verification method ID for a did:web DID.
 * Uses the convention `#key-0` for the primary key.
 */
export function didWebVerificationMethodId(did: string): string {
  return `${did}#key-0`;
}

/**
 * Build a DID document suitable for publishing at `.well-known/did.json`.
 *
 * @param did - The did:web DID (e.g., "did:web:example.com").
 * @param publicKeyJwk - The public key JWK to include in the document.
 * @returns A W3C DID document with the key as a JsonWebKey verification method.
 */
export function generateDidWebDocument(did: string, publicKeyJwk: JWK): DIDDocument {
  const verificationMethodId = `${did}#key-0`;

  const verificationMethod: VerificationMethod = {
    id: verificationMethodId,
    type: "JsonWebKey",
    controller: did,
    publicKeyJwk,
  };

  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
    capabilityInvocation: [verificationMethodId],
    capabilityDelegation: [verificationMethodId],
  };
}

/**
 * Convert a did:web DID to the HTTPS URL where the DID document is hosted.
 *
 * Follows the did:web spec:
 * - `did:web:example.com` → `https://example.com/.well-known/did.json`
 * - `did:web:example.com:path:to` → `https://example.com/path/to/did.json`
 * - `did:web:example.com%3A3000` → `https://example.com:3000/.well-known/did.json`
 *
 * @param did - The did:web DID string.
 * @returns The HTTPS URL for the DID document.
 * @throws {DIDResolutionError} If the DID format is invalid.
 */
export function didWebToUrl(did: string): string {
  if (!did || typeof did !== "string") {
    throw new DIDResolutionError("DID must be a non-empty string");
  }

  const parts = did.split(":");
  if (parts.length < 3 || parts[0] !== "did" || parts[1] !== "web") {
    throw new DIDResolutionError("Invalid did:web format");
  }

  // Decode percent-encoded colons in the domain (port numbers)
  const domain = parts[2].replace(/%3A/gi, ":");

  // Remaining parts are path segments
  const pathSegments = parts.slice(3);

  if (pathSegments.length > 0) {
    return `https://${domain}/${pathSegments.join("/")}/did.json`;
  }
  return `https://${domain}/.well-known/did.json`;
}

/**
 * Optional fallback resolver function for DeDi-backed resolution.
 * When standard did:web HTTP resolution fails, the fallback is tried
 * if provided. This allows DeDi to serve as an alternative DID document
 * host without creating a hard dependency from packages/did to packages/dedi-client.
 */
export type DIDWebFallbackResolver = (did: string) => Promise<DIDResolutionResult | null>;

/**
 * DID resolver that fetches did:web documents over HTTPS.
 *
 * Security measures:
 * - HTTPS only (enforced by did:web spec)
 * - No redirects followed
 * - 10-second fetch timeout
 * - SSRF prevention via DNS resolution + private IP check
 *
 * Optionally accepts a fallback resolver (e.g., DeDi) that is tried
 * when standard HTTP resolution fails.
 */
export class DIDWebResolver implements DIDResolver {
  private readonly fallback?: DIDWebFallbackResolver;

  constructor(fallback?: DIDWebFallbackResolver) {
    this.fallback = fallback;
  }

  async resolve(did: string): Promise<DIDResolutionResult> {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }

    const parts = did.split(":");
    if (parts.length < 3 || parts[0] !== "did") {
      throw new DIDResolutionError("Invalid DID format: expected did:<method>:<id>");
    }

    if (parts[1] !== "web") {
      throw new DIDResolutionError(`Unsupported DID method: ${parts[1]}`);
    }

    const url = didWebToUrl(did);

    // Try standard HTTPS resolution first
    try {
      return await this.resolveViaHttps(did, url);
    } catch (httpError) {
      // Never fall back on SSRF violations — these are security boundaries
      const isSsrf =
        httpError instanceof DIDResolutionError && httpError.message.includes("SSRF protection");
      if (isSsrf || !this.fallback) {
        throw httpError;
      }
      // Try DeDi fallback; if it also fails, throw the original HTTP error
      try {
        const fallbackResult = await this.fallback(did);
        if (fallbackResult) return fallbackResult;
      } catch {
        // Fallback failed — throw the original, more meaningful error
      }
      throw httpError;
    }
  }

  private async resolveViaHttps(did: string, url: string): Promise<DIDResolutionResult> {
    // Extract hostname for SSRF check
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;

    // DNS resolution + SSRF check: resolve the hostname and verify
    // all returned IPs (IPv4 + IPv6) are public before making the HTTP request.
    const [v4Result, v6Result] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
    ]);
    const addresses = [
      ...(v4Result.status === "fulfilled" ? v4Result.value : []),
      ...(v6Result.status === "fulfilled" ? v6Result.value : []),
    ];

    if (addresses.length === 0) {
      throw new DIDResolutionError(`Failed to resolve hostname: ${hostname}`);
    }

    for (const ip of addresses) {
      if (isPrivateIP(ip)) {
        throw new DIDResolutionError("SSRF protection: DID document host resolves to a private IP");
      }
    }

    // Fetch with timeout and no redirects
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetch(url, {
        signal: controller.signal,
        redirect: "error",
        headers: {
          Accept: "application/did+ld+json, application/json",
        },
      });
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new DIDResolutionError(`Timeout fetching DID document from: ${url}`);
      }
      throw new DIDResolutionError(`Failed to fetch DID document from: ${url}`);
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new DIDResolutionError(
        `HTTP ${String(response.status)} fetching DID document from: ${url}`,
      );
    }

    let didDocument: DIDDocument;
    try {
      didDocument = (await response.json()) as DIDDocument;
    } catch {
      throw new DIDResolutionError("Failed to parse DID document as JSON");
    }

    // Validate that the document ID matches the DID
    if (didDocument.id !== did) {
      throw new DIDResolutionError(
        `DID document ID mismatch: expected ${did}, got ${String(didDocument.id)}`,
      );
    }

    return {
      didDocument,
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }
}

/**
 * Structured result from {@link verifyDidWeb}.
 *
 * The fields are split so callers can distinguish "the DID couldn't be
 * resolved at all" from "it resolved but the published key doesn't match
 * what we expected" — these have different remediation paths.
 */
export interface DidWebVerificationResult {
  /** Whether the DID document was successfully resolved (HTTP fetch + validation). */
  accessible: boolean;
  /**
   * Whether the resolved document references the expected public key.
   * Only populated when `expectedPublicKey` was supplied; `undefined` otherwise.
   */
  keyMatches?: boolean;
  /** The resolved DID document, if accessible. */
  didDocument?: DIDDocument;
  /** Human-readable error message when verification fails. */
  error?: string;
}

export interface VerifyDidWebOptions {
  /**
   * If provided, the helper additionally checks that one of the DID document's
   * verification methods publishes this exact public key. Used by:
   * - Desktop wizard: after the user hosts `did.json`, confirm it references their key
   * - apps/server boot: ensure the configured `did:web` is consistent with the loaded signer
   */
  expectedPublicKey?: JWK;
  /** Optional DeDi fallback resolver, when the user has chosen DeDi-hosted did:web. */
  fallback?: DIDWebFallbackResolver;
}

/**
 * Verify that a `did:web` is published and (optionally) references the expected public key.
 *
 * Wraps {@link DIDWebResolver} to return a structured result instead of throwing,
 * which is the shape both the desktop wizard verify step and the server boot
 * validation need. The validation step is intentionally hosting-agnostic — it
 * doesn't care whether the operator hosts `did.json` themselves or whether DeDi
 * is serving it via the optional `fallback` resolver.
 *
 * @param did - The full did:web DID (e.g., `did:web:example.com`).
 * @param options - Optional expected key + DeDi fallback.
 * @returns Structured verification result.
 */
export async function verifyDidWeb(
  did: string,
  options: VerifyDidWebOptions = {},
): Promise<DidWebVerificationResult> {
  const resolver = new DIDWebResolver(options.fallback);
  let didDocument: DIDDocument;
  try {
    const result = await resolver.resolve(did);
    if (!result.didDocument) {
      return { accessible: false, error: "DID document was empty" };
    }
    didDocument = result.didDocument;
  } catch (err) {
    return {
      accessible: false,
      error: err instanceof Error ? err.message : "did:web verification failed",
    };
  }

  if (!options.expectedPublicKey) {
    return { accessible: true, didDocument };
  }

  const keyMatches = documentReferencesKey(didDocument, options.expectedPublicKey);
  return {
    accessible: true,
    keyMatches,
    didDocument,
    error: keyMatches ? undefined : "DID document does not reference the expected public key",
  };
}

/**
 * Check whether any verificationMethod in the DID document publishes the expected JWK.
 *
 * Comparison is on the public-material fields of the JWK only (kty/crv/x/y/n/e),
 * not on optional metadata like `kid` or `use`. The private `d` field is
 * never compared (it shouldn't be present in either side, but be defensive).
 */
function documentReferencesKey(doc: DIDDocument, expected: JWK): boolean {
  if (!doc.verificationMethod) return false;
  for (const vm of doc.verificationMethod) {
    if (!vm.publicKeyJwk) continue;
    if (jwkPublicMaterialEquals(vm.publicKeyJwk, expected)) return true;
  }
  return false;
}

function jwkPublicMaterialEquals(a: JWK, b: JWK): boolean {
  if (a.kty !== b.kty) return false;
  switch (a.kty) {
    case "EC":
      return a.crv === b.crv && a.x === b.x && a.y === b.y;
    case "OKP":
      return a.crv === b.crv && a.x === b.x;
    case "RSA":
      return a["n"] === b["n"] && a["e"] === b["e"];
    default:
      return false;
  }
}
