/**
 * OpenTelemetry tracing bootstrap — Tier 3 #10 of nfh-trust-labs/opencred#446.
 *
 * Provides:
 *
 *  - A no-overhead path when `OPENCRED_OTEL_ENABLED` is unset/false.
 *    `initTracing()` returns `null` and downstream `getTracer()` calls
 *    resolve to OpenTelemetry's built-in no-op tracer (zero allocations
 *    per span).
 *
 *  - A production path when `OPENCRED_OTEL_ENABLED=true`. A
 *    `NodeTracerProvider` is registered with a `BatchSpanProcessor`
 *    + `OTLPTraceExporter`. Standard OTel env vars apply:
 *      `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`,
 *      `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`.
 *
 *  - A test path via {@link setInMemoryExporter}. Vitest installs an
 *    `InMemorySpanExporter` with a `SimpleSpanProcessor` so finished
 *    spans are flushed synchronously and asserted on directly. Test
 *    code never touches the real OTLP exporter.
 *
 * SECURITY (CLAUDE.md):
 *  - Spans MUST NOT contain key material, signing buffers, or credential
 *    subject PII. The instrumentation helpers in `src/observability/`
 *    enforce this contract — see `signer-span.ts`.
 *  - No environment variable read here is logged.
 */

import { trace, type Tracer } from "@opentelemetry/api";
import {
  NodeTracerProvider,
  BatchSpanProcessor,
  SimpleSpanProcessor,
  ParentBasedSampler,
  TraceIdRatioBasedSampler,
  AlwaysOnSampler,
  AlwaysOffSampler,
  type SpanProcessor,
  type SpanExporter,
  type Sampler,
} from "@opentelemetry/sdk-trace-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { Resource } from "@opentelemetry/resources";
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from "@opentelemetry/semantic-conventions";

/**
 * Tracer name used by every helper that calls `getTracer()`. Kept as a
 * constant so a future scoped-tracer split (per-package) reuses the same
 * resource. Today every span lives under the same `opencred-server`
 * instrumentation library.
 */
export const TRACER_NAME = "opencred-server";

let activeProvider: NodeTracerProvider | null = null;

/**
 * Resolve the sampler from standard OTel env vars.
 *
 * Recognised values:
 *   - `always_on` (default), `always_off`
 *   - `traceidratio` + `OTEL_TRACES_SAMPLER_ARG` (e.g. `0.1`)
 *   - `parentbased_always_on`, `parentbased_always_off`
 *   - `parentbased_traceidratio` + `OTEL_TRACES_SAMPLER_ARG`
 *
 * Falls back to `always_on` for any unrecognised value. We don't log a
 * warning because the SDK itself surfaces this via diagnostics if the
 * caller wires up DiagLogLevel.
 */
function resolveSampler(): Sampler {
  const name = (process.env.OTEL_TRACES_SAMPLER ?? "parentbased_always_on").toLowerCase();
  const argRaw = process.env.OTEL_TRACES_SAMPLER_ARG;
  const arg = argRaw !== undefined ? Number.parseFloat(argRaw) : 1.0;
  const ratio = Number.isFinite(arg) ? Math.min(Math.max(arg, 0), 1) : 1.0;

  switch (name) {
    case "always_on":
      return new AlwaysOnSampler();
    case "always_off":
      return new AlwaysOffSampler();
    case "traceidratio":
      return new TraceIdRatioBasedSampler(ratio);
    case "parentbased_always_on":
      return new ParentBasedSampler({ root: new AlwaysOnSampler() });
    case "parentbased_always_off":
      return new ParentBasedSampler({ root: new AlwaysOffSampler() });
    case "parentbased_traceidratio":
      return new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(ratio) });
    default:
      return new ParentBasedSampler({ root: new AlwaysOnSampler() });
  }
}

export interface TracerHandle {
  /** Flush any pending span batches and shut the provider down. */
  shutdown: () => Promise<void>;
}

/**
 * Initialise tracing.
 *
 * Returns `null` when `OPENCRED_OTEL_ENABLED` is not set to a truthy
 * value — this is the back-compat default. Otherwise installs a
 * `NodeTracerProvider` globally and returns a handle that the caller
 * (typically `index.ts`) can use to shut the provider down on SIGTERM.
 *
 * When `OTEL_EXPORTER_OTLP_ENDPOINT` is unset the provider is
 * installed without an exporter — spans are still created (so
 * `getTracer().startSpan(...)` returns a real span you can attach
 * attributes to) but they are not transmitted anywhere. This is the
 * "tracing on, collector down" mode that an operator might hit when
 * Tempo/Jaeger is restarting; the server keeps running.
 */
export function initTracing(): TracerHandle | null {
  const enabledRaw = (process.env.OPENCRED_OTEL_ENABLED ?? "").trim().toLowerCase();
  const enabled = enabledRaw === "true" || enabledRaw === "1" || enabledRaw === "yes";
  if (!enabled) return null;

  const serviceName = process.env.OTEL_SERVICE_NAME ?? "opencred-server";
  const resource = new Resource({
    [ATTR_SERVICE_NAME]: serviceName,
    [ATTR_SERVICE_VERSION]: "0.1.0",
  });

  const sampler = resolveSampler();
  const provider = new NodeTracerProvider({ resource, sampler });

  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (endpoint) {
    // OTLP/HTTP — endpoint should be the collector base; we append the
    // standard /v1/traces path the OTLP/HTTP spec defines.
    const url = endpoint.endsWith("/v1/traces") ? endpoint : `${endpoint.replace(/\/$/, "")}/v1/traces`;
    const exporter = new OTLPTraceExporter({ url });
    provider.addSpanProcessor(new BatchSpanProcessor(exporter));
  }
  // No endpoint → no processor. The provider still serves a real Tracer;
  // spans are dropped at end() without crossing a network boundary.

  provider.register();
  activeProvider = provider;

  return {
    async shutdown() {
      await provider.shutdown();
      activeProvider = null;
    },
  };
}

/**
 * Get the singleton Tracer used by all OpenCred server instrumentation.
 *
 * Safe to call regardless of whether `initTracing()` ran. When the SDK
 * hasn't been initialised, returns OpenTelemetry's built-in no-op
 * tracer (every `startActiveSpan` becomes a synchronous passthrough).
 */
export function getTracer(): Tracer {
  return trace.getTracer(TRACER_NAME);
}

// ---------------------------------------------------------------------------
// Test hook — in-memory exporter
// ---------------------------------------------------------------------------

/**
 * Install an in-memory span exporter for tests.
 *
 * Test code wires up an `InMemorySpanExporter`, hands it to this helper,
 * and asserts on the collected spans after exercising whatever code path
 * is under test. Uses `SimpleSpanProcessor` so finished spans are
 * available without an explicit `forceFlush()`.
 *
 * The previously installed provider (if any) is shut down and the global
 * tracer registration is reset, so spans don't leak across test cases.
 * Without the `trace.disable()` call, OpenTelemetry's `registerGlobal`
 * refuses a second registration and silently no-ops the `setDelegate`
 * step — meaning subsequent `getTracer()` calls would still resolve to
 * the previous provider (or the no-op proxy). This makes the helper
 * idempotent across `beforeEach` invocations.
 */
export async function setInMemoryExporter(exporter: SpanExporter): Promise<TracerHandle> {
  if (activeProvider) {
    await activeProvider.shutdown();
    activeProvider = null;
  }
  // Forcibly clear the global registration so the new provider's
  // `register()` succeeds. Without this the second test would still
  // see spans flow into the previously-installed provider (or the
  // no-op proxy when no provider was ever installed via initTracing).
  trace.disable();

  const resource = new Resource({
    [ATTR_SERVICE_NAME]: process.env.OTEL_SERVICE_NAME ?? "opencred-server",
    [ATTR_SERVICE_VERSION]: "0.1.0-test",
  });

  const provider = new NodeTracerProvider({
    resource,
    sampler: new AlwaysOnSampler(),
  });
  const processor: SpanProcessor = new SimpleSpanProcessor(exporter);
  provider.addSpanProcessor(processor);
  provider.register();
  activeProvider = provider;

  return {
    async shutdown() {
      await provider.shutdown();
      activeProvider = null;
      trace.disable();
    },
  };
}

/**
 * Reset the active provider — for tests that need to flush completely
 * between cases. No-op if no provider is installed.
 */
export async function resetTracingForTesting(): Promise<void> {
  if (activeProvider) {
    await activeProvider.shutdown();
    activeProvider = null;
  }
  trace.disable();
}
