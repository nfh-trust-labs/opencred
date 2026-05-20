/**
 * DeDi adapter instrumentation — wraps a {@link DeDiClient} so every
 * lookup / publish / update operation emits a span.
 *
 * Spans emitted:
 *   - `dedi.lookup_record` — resolveDID / resolveSchema / resolveContext /
 *     queryRevocationHash
 *   - `dedi.publish_record` — publishDID / publishSchema / publishContext /
 *     publishRevocationHash / ensureRegistries
 *   - `dedi.update_record` — markDIDRotated (DeDi `update-record`)
 *
 * SECURITY (CLAUDE.md):
 *   - The DeDi base URL is decomposed: we record only the *host* in
 *     `dedi.host`. Paths (which carry record names that may map to
 *     credential identifiers) are NOT placed on the span.
 *   - Bearer tokens / API keys are owned by the underlying api-client
 *     and never reach this layer. No auth header is read here.
 *   - The `registry` attribute identifies which DeDi registry is being
 *     touched (public_key_registry, vc-revocation-registry, etc.) —
 *     useful for ops dashboards, no PII.
 */

import type { DeDiClient } from "@opencred/dedi-client";

import { runInSpan } from "./span-helpers.js";

/**
 * Extract just the host (with port if non-standard) from a base URL.
 * Strips path, credentials, and query — anything that could carry a
 * record name or token. Returns `"unknown"` for malformed input rather
 * than throwing, because a span attribute must never be the failure
 * mode that breaks an otherwise-working request.
 */
function safeHost(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    return u.host;
  } catch {
    return "unknown";
  }
}

/**
 * Wrap a {@link DeDiClient} so its lookup/publish/update methods emit
 * spans. Returns a new object that delegates to the original — the
 * underlying client is not mutated. Only the methods OpenCred's
 * critical paths actually call are wrapped; unwrapped methods (e.g.
 * `apiClient` low-level access used by tests) pass through.
 */
export function wrapDeDiClientWithTracing(client: DeDiClient, baseUrl: string): DeDiClient {
  const host = safeHost(baseUrl);

  // We deliberately construct a proxy-like object rather than mutate
  // the original. This keeps tests that hold the raw client reference
  // ungated by tracing and lets the dedi-singleton swap the wrapped
  // instance in without leaking observability into the dedi-client
  // package itself.
  const wrapped = Object.create(Object.getPrototypeOf(client)) as DeDiClient;

  // Copy non-method properties (apiClient getter, logger, etc.) by
  // delegating through.
  Object.defineProperty(wrapped, "apiClient", {
    get: () => client.apiClient,
    configurable: true,
  });
  Object.defineProperty(wrapped, "logger", {
    get: () => client.logger,
    configurable: true,
  });

  // ── Revocation registry ─────────────────────────────────────────

  wrapped.publishRevocationHash = (hash, namespace, reason) =>
    runInSpan(
      "dedi.publish_record",
      { "dedi.host": host, "dedi.registry": "vc-revocation-registry" },
      () => client.publishRevocationHash(hash, namespace, reason),
    );

  wrapped.queryRevocationHash = (hash, namespace) =>
    runInSpan(
      "dedi.lookup_record",
      { "dedi.host": host, "dedi.registry": "vc-revocation-registry" },
      () => client.queryRevocationHash(hash, namespace),
    );

  // ── DID / public-key registry ───────────────────────────────────

  wrapped.publishDID = (did, document, namespace) =>
    runInSpan(
      "dedi.publish_record",
      { "dedi.host": host, "dedi.registry": "public_key_registry" },
      () => client.publishDID(did, document, namespace),
    );

  wrapped.resolveDID = (did, namespace) =>
    runInSpan(
      "dedi.lookup_record",
      { "dedi.host": host, "dedi.registry": "public_key_registry" },
      () => client.resolveDID(did, namespace),
    );

  wrapped.markDIDRotated = (did, namespace) =>
    runInSpan(
      "dedi.update_record",
      { "dedi.host": host, "dedi.registry": "public_key_registry" },
      () => client.markDIDRotated(did, namespace),
    );

  // ── Schema registry ─────────────────────────────────────────────

  wrapped.publishSchema = (schema, namespace) =>
    runInSpan(
      "dedi.publish_record",
      { "dedi.host": host, "dedi.registry": "schema_registry" },
      () => client.publishSchema(schema, namespace),
    );

  wrapped.resolveSchema = (schemaId, version, namespace) =>
    runInSpan(
      "dedi.lookup_record",
      { "dedi.host": host, "dedi.registry": "schema_registry" },
      () => client.resolveSchema(schemaId, version, namespace),
    );

  // ── Context registry ────────────────────────────────────────────

  wrapped.publishContext = (record, namespace) =>
    runInSpan(
      "dedi.publish_record",
      { "dedi.host": host, "dedi.registry": "context_registry" },
      () => client.publishContext(record, namespace),
    );

  wrapped.resolveContext = (schemaId, version, namespace) =>
    runInSpan(
      "dedi.lookup_record",
      { "dedi.host": host, "dedi.registry": "context_registry" },
      () => client.resolveContext(schemaId, version, namespace),
    );

  // ── Namespace bootstrap ─────────────────────────────────────────

  wrapped.ensureRegistries = (namespace) =>
    runInSpan(
      "dedi.publish_record",
      { "dedi.host": host, "dedi.operation": "ensure_registries" },
      () => client.ensureRegistries(namespace),
    );

  return wrapped;
}
