/**
 * Tracing module tests.
 *
 * Covers the opt-in / opt-out contract for OpenTelemetry bootstrap.
 * Full span-content assertions live in `tracing-spans.test.ts` — that
 * suite installs an `InMemorySpanExporter` and exercises the
 * critical-path instrumentation via test routes.
 */

import { describe, it, expect, afterEach } from "vitest";
import { initTracing, resetTracingForTesting } from "../tracing.js";

afterEach(async () => {
  delete process.env.OPENCRED_OTEL_ENABLED;
  delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  await resetTracingForTesting();
});

describe("initTracing", () => {
  it("returns null when OPENCRED_OTEL_ENABLED is unset", () => {
    delete process.env.OPENCRED_OTEL_ENABLED;
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    const result = initTracing();
    expect(result).toBeNull();
  });

  it("returns null when OPENCRED_OTEL_ENABLED=false", () => {
    process.env.OPENCRED_OTEL_ENABLED = "false";
    const result = initTracing();
    expect(result).toBeNull();
  });

  it("ignores OTEL_EXPORTER_OTLP_ENDPOINT alone when not OPENCRED_OTEL_ENABLED", () => {
    // Critical back-compat invariant — every deployment before #581
    // ran without tracing. Setting OTEL_EXPORTER_OTLP_ENDPOINT alone
    // MUST NOT enable tracing.
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318";
    const result = initTracing();
    expect(result).toBeNull();
  });

  it("returns a shutdown handle when OPENCRED_OTEL_ENABLED=true (no endpoint)", async () => {
    process.env.OPENCRED_OTEL_ENABLED = "true";
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    const result = initTracing();
    expect(result).not.toBeNull();
    expect(typeof result!.shutdown).toBe("function");
    await result!.shutdown();
  });

  it("returns a shutdown handle when OPENCRED_OTEL_ENABLED=true and OTLP endpoint is set", async () => {
    process.env.OPENCRED_OTEL_ENABLED = "true";
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318";
    const result = initTracing();
    expect(result).not.toBeNull();
    expect(typeof result!.shutdown).toBe("function");
    await result!.shutdown();
  });
});
