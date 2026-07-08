/**
 * Span helpers — small wrappers over the OpenTelemetry API that the
 * critical-path instrumentation reaches for.
 *
 * Goals:
 *   - Centralise the "record exception + set status + end" boilerplate so
 *     individual call sites stay readable.
 *   - Make the no-op path cheap: when tracing isn't initialised,
 *     `getTracer()` returns OTel's built-in no-op tracer and these
 *     helpers add roughly a function call's worth of overhead.
 *   - NEVER serialise key material or signing buffers into attributes.
 *     Callers pass `Record<string, AttributeValue>` and are responsible
 *     for shape — but this module documents the contract.
 *
 * SECURITY (CLAUDE.md):
 *   - Span attributes are visible to observability backends. Use OPAQUE
 *     identifiers (job ids, fingerprints) — never user data, signing
 *     buffers, or PII.
 */

import { SpanKind, SpanStatusCode, type Attributes, type Span } from "@opentelemetry/api";

import { getTracer } from "../tracing.js";

export { SpanKind, SpanStatusCode } from "@opentelemetry/api";
export type { Attributes, Span } from "@opentelemetry/api";

/**
 * Run an async function inside a span. Records exceptions, sets
 * status, and ends the span — even when the inner function throws.
 *
 * The inner function receives the span so it can decorate it with
 * dynamic attributes (e.g. signature byte length, row status). The
 * caller does NOT need to call `span.end()` manually; doing so is
 * harmless because OTel's API is idempotent on `end()`.
 */
export async function runInSpan<T>(
  name: string,
  attributes: Attributes,
  fn: (span: Span) => Promise<T>,
  options?: { kind?: SpanKind },
): Promise<T> {
  const tracer = getTracer();
  return tracer.startActiveSpan(
    name,
    { kind: options?.kind ?? SpanKind.INTERNAL, attributes },
    async (span) => {
      try {
        const result = await fn(span);
        // We only flip to OK explicitly when the caller hasn't already
        // set a status (e.g. via setSpanStatusFromVerdict). The OTel
        // contract treats UNSET as OK on export, so leave it alone.
        return result;
      } catch (err) {
        span.recordException(err as Error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: err instanceof Error ? err.message : String(err),
        });
        throw err;
      } finally {
        span.end();
      }
    },
  );
}

/**
 * Synchronous variant of {@link runInSpan}. Same exception-recording
 * contract; useful for pure compute (e.g. canonicalisation hashes)
 * where awaiting would be a downgrade.
 */
export function runInSpanSync<T>(
  name: string,
  attributes: Attributes,
  fn: (span: Span) => T,
  options?: { kind?: SpanKind },
): T {
  const tracer = getTracer();
  return tracer.startActiveSpan(
    name,
    { kind: options?.kind ?? SpanKind.INTERNAL, attributes },
    (span) => {
      try {
        return fn(span);
      } catch (err) {
        span.recordException(err as Error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: err instanceof Error ? err.message : String(err),
        });
        throw err;
      } finally {
        span.end();
      }
    },
  );
}
