/**
 * DeDi adapter instrumentation — wraps a {@link DeDiClient} so every
 * lookup / publish / update operation emits a span.
 *
 * Spans emitted:
 *   - `dedi.lookup_record` — resolveKey / resolveDidWebDocument / resolveSchema /
 *     resolveContext / queryRevocationHash
 *   - `dedi.publish_record` — publishKey / publishSchema /
 *     publishContext / publishRevocationHash / ensureRegistries
 *   - `dedi.update_record` — setKeyStatus (DeDi `update-record`)
 *
 * SECURITY (CLAUDE.md):
 *   - The DeDi base URL is decomposed: we record only the *host* in
 *     `dedi.host`. Paths (which carry record names that may map to
 *     credential identifiers) are NOT placed on the span.
 *   - Bearer tokens / API keys are owned by the underlying api-client
 *     and never reach this layer. No auth header is read here.
 *   - The `registry` attribute identifies which DeDi registry is being
 *     touched (opencred-key-registry, vc-revocation-registry, etc.) —
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
 * underlying client is not mutated.
 *
 * IMPORTANT: every method OpenCred calls on the wrapped client MUST be
 * explicitly assigned below. The wrapper is a bare object over the
 * prototype; it does NOT carry the real client's private instance fields
 * (`api`, `defaultNamespace`, …). A method left unwrapped runs on this
 * bare object and throws (e.g. `resolveNamespace` can't find
 * `defaultNamespace`). The explicit assignments delegate to `client`, which
 * does have those fields. Only genuinely test-only accessors (`apiClient`,
 * `logger`, copied via defineProperty) are exempt.
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

  // ── Per-key registry ────────────────────────────────────────────

  wrapped.publishKey = (key, namespace) =>
    runInSpan(
      "dedi.publish_record",
      { "dedi.host": host, "dedi.registry": "opencred-key-registry" },
      () => client.publishKey(key, namespace),
    );

  wrapped.resolveKey = (verificationMethod, namespace) =>
    runInSpan(
      "dedi.lookup_record",
      { "dedi.host": host, "dedi.registry": "opencred-key-registry" },
      () => client.resolveKey(verificationMethod, namespace),
    );

  wrapped.setKeyStatus = (verificationMethod, status, namespace) =>
    runInSpan(
      "dedi.update_record",
      { "dedi.host": host, "dedi.registry": "opencred-key-registry" },
      () => client.setKeyStatus(verificationMethod, status, namespace),
    );

  wrapped.setKeyDocument = (verificationMethod, document, namespace) =>
    runInSpan(
      "dedi.update_record",
      { "dedi.host": host, "dedi.registry": "opencred-key-registry" },
      () => client.setKeyDocument(verificationMethod, document, namespace),
    );

  // did:web fallback resolution — projects the did.json from the per-key
  // registry snapshots (the separate did-documents registry was removed). It
  // reads `opencred-key-registry`, so the span carries that registry label.
  wrapped.resolveDidWebDocument = (did, namespace) =>
    runInSpan(
      "dedi.lookup_record",
      { "dedi.host": host, "dedi.registry": "opencred-key-registry" },
      () => client.resolveDidWebDocument(did, namespace),
    );

  // ── Schema registry ─────────────────────────────────────────────

  wrapped.publishSchema = (schema, namespace) =>
    runInSpan(
      "dedi.publish_record",
      { "dedi.host": host, "dedi.registry": "schema_registry" },
      () => client.publishSchema(schema, namespace),
    );

  wrapped.resolveSchema = (schemaId, version, namespace) =>
    runInSpan("dedi.lookup_record", { "dedi.host": host, "dedi.registry": "schema_registry" }, () =>
      client.resolveSchema(schemaId, version, namespace),
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
