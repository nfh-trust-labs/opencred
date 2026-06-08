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
 * Build the verification-method id for the Nth key of a did:web DID, using the
 * sequential `#key-<n>` convention (`did:web:acme.com#key-0`, `…#key-1`, …).
 *
 * The fragment is the stable join key across three places that MUST agree for a
 * credential to verify: the credential's `proof.verificationMethod` (or JWT
 * `kid`), the `verificationMethod[]` entry in the issuer's did.json, and the
 * record name in the `opencred-key-registry`. Sequential indices keep the
 * fragment human-readable AND enumerable, which is what lets a stateless issuer
 * compute "the next key in line" from the current did.json.
 *
 * @param did - The did:web DID (e.g., "did:web:example.com").
 * @param index - The zero-based key index. Must be a non-negative integer.
 * @throws {DIDResolutionError} If `index` is not a non-negative integer.
 */
export function didWebVerificationMethodIdForIndex(did: string, index: number): string {
  if (!Number.isInteger(index) || index < 0) {
    throw new DIDResolutionError(
      `did:web key index must be a non-negative integer, got ${String(index)}`,
    );
  }
  return `${did}#key-${index}`;
}

/**
 * Get the verification method ID for the primary key of a did:web DID.
 * Uses the convention `#key-0`. Thin wrapper over
 * {@link didWebVerificationMethodIdForIndex} preserved for callers that only
 * deal with the first key.
 */
export function didWebVerificationMethodId(did: string): string {
  return didWebVerificationMethodIdForIndex(did, 0);
}

/**
 * Extract the sequential key index from a `#key-<n>` verification-method id.
 *
 * Accepts a full verification method (`did:web:acme.com#key-3`) or a bare
 * fragment (`#key-3` / `key-3`). Returns the integer `n`, or `null` when the
 * fragment is not in the canonical `key-<n>` form (e.g. a did:key fragment or a
 * thumbprint id) — callers treat `null` as "not a sequential did:web key".
 *
 * @param verificationMethod - The verification method id or fragment.
 */
export function keyIndexFromVerificationMethod(verificationMethod: string): number | null {
  if (typeof verificationMethod !== "string") return null;
  const fragment = verificationMethod.includes("#")
    ? verificationMethod.slice(verificationMethod.indexOf("#") + 1)
    : verificationMethod;
  const match = /^key-(\d+)$/.exec(fragment);
  if (!match) return null;
  const index = Number(match[1]);
  return Number.isSafeInteger(index) ? index : null;
}

/**
 * A single signing key to publish in a did:web document.
 *
 * `id` is the full verification-method id (`did:web:acme.com#key-0`, or a
 * `did:key:...#z...` fragment for cross-method cases). `publicKeyJwk` is the
 * public key material — never a private `d` member.
 *
 * `revoked` (default `false`) controls relationship membership. A revoked key
 * stays in `verificationMethod[]` so previously-issued signatures still
 * resolve (yielding a precise `REVOKED` verdict rather than "unresolvable"),
 * but it is dropped from every verification relationship (`assertionMethod`,
 * `authentication`, …). This matches W3C DID Core §5.3 — "the DID document
 * does not express revoked keys using a verification relationship" — while
 * keeping the key dereferenceable. Active and cleanly-rotated keys keep
 * `revoked` falsy and remain in all relationships.
 */
export interface DidWebKeyInput {
  id: string;
  publicKeyJwk: JWK;
  revoked?: boolean;
}

/**
 * Build a multi-key DID document suitable for publishing at
 * `.well-known/did.json` (or in DeDi's `did-documents` registry).
 *
 * Every key in `keys` becomes one `verificationMethod` entry. Non-revoked keys
 * (active + cleanly-rotated) are additionally referenced from all verification
 * relationships (`assertionMethod`, `authentication`, `capabilityInvocation`,
 * `capabilityDelegation`) so credentials they signed still verify. A `revoked`
 * key is kept in `verificationMethod[]` (so its signatures still resolve and
 * the verifier can report `REVOKED`) but is excluded from every relationship,
 * per W3C DID Core §5.3.
 *
 * @param did - The did:web DID (e.g., "did:web:example.com").
 * @param keys - The full key set (active, rotated, and revoked). Must be
 *   non-empty and contain at least one non-revoked key — a document whose only
 *   keys are revoked has no usable signing identity.
 * @returns A W3C DID document listing every key.
 * @throws {DIDResolutionError} If `keys` is empty or has no non-revoked key.
 */
export function generateDidWebDocumentMultiKey(did: string, keys: DidWebKeyInput[]): DIDDocument {
  if (!keys || keys.length === 0) {
    throw new DIDResolutionError("generateDidWebDocumentMultiKey requires at least one key");
  }
  const activeIds = keys.filter((key) => !key.revoked).map((key) => key.id);
  if (activeIds.length === 0) {
    throw new DIDResolutionError(
      "generateDidWebDocumentMultiKey requires at least one non-revoked key",
    );
  }

  const verificationMethod: VerificationMethod[] = keys.map((key) => ({
    id: key.id,
    type: "JsonWebKey",
    controller: did,
    publicKeyJwk: key.publicKeyJwk,
  }));

  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    verificationMethod,
    authentication: activeIds,
    assertionMethod: activeIds,
    capabilityInvocation: activeIds,
    capabilityDelegation: activeIds,
  };
}

/**
 * Build a single-key DID document suitable for publishing at
 * `.well-known/did.json`. Thin wrapper over
 * {@link generateDidWebDocumentMultiKey} using the conventional `#key-0`
 * fragment — preserved for callers that issue under one key.
 *
 * @param did - The did:web DID (e.g., "did:web:example.com").
 * @param publicKeyJwk - The public key JWK to include in the document.
 * @returns A W3C DID document with the key as a JsonWebKey verification method.
 */
export function generateDidWebDocument(did: string, publicKeyJwk: JWK): DIDDocument {
  return generateDidWebDocumentMultiKey(did, [{ id: `${did}#key-0`, publicKeyJwk }]);
}

/**
 * A single key extracted from an existing did:web document by
 * {@link importDidWebDocument}. Superset of {@link DidWebKeyInput} — it can be
 * fed straight back into {@link generateDidWebDocumentMultiKey} to carry the
 * key forward into a regenerated document.
 */
export interface ImportedDidWebKey extends DidWebKeyInput {
  /**
   * The sequential index parsed from a `#key-<n>` fragment, or `null` when the
   * verification method does not use the canonical sequential form.
   */
  index: number | null;
  /** Always `false` for active/rotated keys; `true` when the key is revoked. */
  revoked: boolean;
}

/**
 * The structured, stateless view of an existing did:web document, returned by
 * {@link importDidWebDocument}.
 */
export interface ImportedDidWebDocument {
  /** The document's `id` (the did:web DID). */
  did: string;
  /**
   * Every verification method that carries `publicKeyJwk`, in document order,
   * with its parsed index and revoked status. Directly reusable as
   * `DidWebKeyInput[]`.
   */
  keys: ImportedDidWebKey[];
  /** The highest `#key-<n>` index present, or `-1` when there are none. */
  maxKeyIndex: number;
  /** Every `#key-<n>` index already taken (sorted ascending). */
  usedIndices: number[];
}

/** Normalize a verification-relationship entry (string ref or embedded VM) to its id string. */
function relationshipEntryId(entry: unknown): string | undefined {
  if (typeof entry === "string") return entry;
  if (entry && typeof entry === "object" && typeof (entry as { id?: unknown }).id === "string") {
    return (entry as { id: string }).id;
  }
  return undefined;
}

/** The verification relationships a signing key can appear in. */
const VERIFICATION_RELATIONSHIPS = [
  "assertionMethod",
  "authentication",
  "capabilityInvocation",
  "capabilityDelegation",
  "keyAgreement",
] as const;

/** Collect every id referenced by any verification relationship in the document. */
function collectRelationshipIds(doc: Record<string, unknown>): Set<string> {
  const ids = new Set<string>();
  for (const rel of VERIFICATION_RELATIONSHIPS) {
    const entries = doc[rel];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const id = relationshipEntryId(entry);
      if (id) ids.add(id);
    }
  }
  return ids;
}

/**
 * Import an existing did:web document as a whole and return a stateless,
 * structured view of its key set.
 *
 * This is the input a stateless issuer needs to rotate or revoke a key without
 * tracking any local history: the operator hands OpenCred the current did.json
 * (fetched from their domain or DeDi's `did-documents` registry), and this
 * function reports the full key set, which `#key-<n>` indices are taken, and
 * each key's revoked status — everything required to (a) validate the operator's
 * chosen next index and (b) carry every existing key forward into the
 * regenerated document.
 *
 * A key is reported as `revoked: true` when it appears in `verificationMethod[]`
 * but is referenced by NO verification relationship — exactly how
 * {@link generateDidWebDocumentMultiKey} encodes a revoked key.
 *
 * @param document - The DID document (parsed JSON object).
 * @returns The structured key set, taken indices, and max index.
 * @throws {DIDResolutionError} If the input is not a did:web DID document.
 */
export function importDidWebDocument(document: unknown): ImportedDidWebDocument {
  if (!document || typeof document !== "object") {
    throw new DIDResolutionError("importDidWebDocument: document must be a JSON object");
  }
  const doc = document as Record<string, unknown>;
  const did = doc["id"];
  if (typeof did !== "string" || !did.startsWith("did:web:")) {
    throw new DIDResolutionError("importDidWebDocument: document.id must be a did:web DID");
  }

  const relationshipIds = collectRelationshipIds(doc);
  const isInRelationship = (id: string): boolean => {
    if (relationshipIds.has(id)) return true;
    // A document may reference keys by bare fragment (`#key-2`) instead of the
    // full id (`did:web:acme.com#key-2`); treat either as a match.
    if (id.includes("#")) {
      const fragment = `#${id.slice(id.indexOf("#") + 1)}`;
      if (relationshipIds.has(fragment)) return true;
    }
    return false;
  };

  const vms = Array.isArray(doc["verificationMethod"]) ? doc["verificationMethod"] : [];
  const keys: ImportedDidWebKey[] = [];
  for (const vm of vms) {
    if (!vm || typeof vm !== "object") continue;
    const id = (vm as { id?: unknown }).id;
    const publicKeyJwk = (vm as { publicKeyJwk?: unknown }).publicKeyJwk;
    if (typeof id !== "string" || !publicKeyJwk || typeof publicKeyJwk !== "object") continue;
    keys.push({
      id,
      publicKeyJwk: publicKeyJwk as JWK,
      index: keyIndexFromVerificationMethod(id),
      revoked: !isInRelationship(id),
    });
  }

  const usedIndices = keys
    .map((key) => key.index)
    .filter((index): index is number => index !== null)
    .sort((a, b) => a - b);

  return {
    did,
    keys,
    maxKeyIndex: usedIndices.length > 0 ? usedIndices[usedIndices.length - 1]! : -1,
    usedIndices,
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
