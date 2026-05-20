/**
 * Cache-control + ETag helpers (Tier 3 #9 of nfh-trust-labs/opencred#446).
 *
 * The "verify-split" recommendation from issue #446 calls for putting the
 * read-only, idempotent surface of the OpenCred API behind a CDN or a
 * dedicated read tier. `POST /credentials/verify` itself is not GET-cacheable
 * (the credential body is in the request, not the URL), but the expensive
 * dependencies it pulls in — DID documents, CSCA trust-store entries, JSON
 * Schema documents, JSON-LD contexts — ARE cacheable. This module produces
 * the response headers that let any sane CDN, service-worker, or reverse
 * proxy cache those dependencies between calls.
 *
 * SECURITY (CLAUDE.md):
 *  - ETag input MUST be deterministic. The helper never folds wall-clock
 *    time, randomness, or per-request identifiers into the digest — only
 *    the canonical body bytes a client would otherwise re-fetch.
 *  - ETag value is `W/"<sha256-hex>"`. The "W/" prefix marks it as a weak
 *    validator (RFC 7232 §2.3) — semantically equivalent representations
 *    may share an ETag even if their byte-for-byte serialization differs.
 *    This is the right shape for JSON responses, where key ordering can
 *    vary across replicas without affecting client semantics.
 *  - The hash never includes secrets. Inputs are public-by-construction
 *    (DID documents, schema bodies, etc.).
 */

import { createHash } from "node:crypto";
import type { Context } from "hono";

/**
 * Cache-Control directives for read-tier responses. The exposed objects are
 * frozen at module load so per-route handlers cannot accidentally mutate a
 * shared value (and so the shapes can be passed through `c.header()` with no
 * defensive copies).
 *
 * The numeric ages are derived from how often each shape changes in the
 * field. DID documents are the most volatile (key rotation, did:web edits);
 * schemas + contexts are functionally immutable once published in the v1
 * catalogue.
 */
export const CACHE_PRESETS = Object.freeze({
  /**
   * DID resolution responses (`/keys/resolve`). Five-minute fresh window with
   * a one-minute stale-while-revalidate (RFC 5861) cushion so a CDN keeps
   * serving the previous value while it refreshes in the background.
   */
  didDocument: "public, max-age=300, stale-while-revalidate=60",
  /**
   * Schema + context responses. Schemas in the bundled catalogue are
   * versioned in the id (`functional-identity/v1`), so a published schema
   * body never changes; an hour-long max-age is conservative. Five-minute
   * stale-while-revalidate covers the edge case where the operator pulls in
   * a schema-update manifest mid-flight.
   */
  schemaOrContext: "public, max-age=3600, stale-while-revalidate=300",
  /**
   * Verify responses. POST replies can be marked `private, max-age=N` so a
   * client-side cache (service-worker, in-process LRU) can dedupe rapid
   * re-verifications of the SAME credential without violating HTTP caching
   * semantics — `private` keeps a shared CDN from latching onto a per-caller
   * answer. Sixty seconds matches the longest verification path latency
   * we've measured for did:web resolution at p99.
   */
  verifyPrivate: "private, max-age=60",
} as const);

/**
 * Stable JSON serializer used to compute the ETag input. Recursively sorts
 * object keys so two responses that differ only in key order produce the
 * same hash. `null`, primitives, and arrays are emitted verbatim — array
 * order is semantically significant in every endpoint we cache here, so we
 * never reorder it.
 *
 * Exported for test coverage; do not import from elsewhere in the server.
 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const entries = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`,
  );
  return `{${entries.join(",")}}`;
}

/**
 * Compute a deterministic ETag for a JSON body. Returns the strong-looking
 * `W/"<sha256-hex>"` weak-validator form.
 */
export function computeETag(body: unknown): string {
  const digest = createHash("sha256").update(stableStringify(body), "utf8").digest("hex");
  return `W/"${digest}"`;
}

/**
 * Apply cache headers to the current Hono context and short-circuit with
 * `304 Not Modified` when the client supplied a matching `If-None-Match`.
 *
 * Returns either:
 *  - a 304 Response (caller MUST return it as-is), OR
 *  - `undefined` — the caller proceeds with its normal JSON response.
 *
 * The 304 path strips the body (per RFC 7232) and preserves the validator
 * headers so the cache can refresh its freshness window without re-reading
 * the payload.
 */
export function applyCacheHeaders(
  c: Context,
  body: unknown,
  cacheControl: string,
  opts?: { vary?: string },
): Response | undefined {
  const etag = computeETag(body);
  const ifNoneMatch = c.req.header("if-none-match");
  if (ifNoneMatch && etagMatches(ifNoneMatch, etag)) {
    // RFC 7232 §4.1: 304 response MUST include the validators (ETag,
    // Cache-Control, Vary) so the cache can update its freshness state.
    const headers = new Headers();
    headers.set("ETag", etag);
    headers.set("Cache-Control", cacheControl);
    if (opts?.vary) headers.set("Vary", opts.vary);
    return new Response(null, { status: 304, headers });
  }
  c.header("ETag", etag);
  c.header("Cache-Control", cacheControl);
  if (opts?.vary) c.header("Vary", opts.vary);
  return undefined;
}

/**
 * Compare an `If-None-Match` header against a server-computed ETag.
 *
 * RFC 7232 §3.2 permits a comma-separated list of validators or the wildcard
 * `*`. Per §2.3.2 weak comparison ignores the `W/` prefix on either side —
 * we therefore strip it from both before comparing. Anything else is treated
 * as no-match.
 *
 * Exported for direct unit testing.
 */
export function etagMatches(headerValue: string, serverEtag: string): boolean {
  const trimmed = headerValue.trim();
  if (trimmed === "*") return true;
  const normalize = (v: string): string => v.trim().replace(/^W\//, "");
  const serverNorm = normalize(serverEtag);
  for (const candidate of trimmed.split(",")) {
    if (normalize(candidate) === serverNorm) return true;
  }
  return false;
}
