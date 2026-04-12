/**
 * Tracing module tests.
 */

import { describe, it, expect, afterEach } from "vitest";
import { initTracing } from "../tracing.js";

afterEach(() => {
  delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
});

describe("initTracing", () => {
  it("returns null when OTEL_EXPORTER_OTLP_ENDPOINT is not set", () => {
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    const result = initTracing();
    expect(result).toBeNull();
  });

  it("returns shutdown function when OTEL_EXPORTER_OTLP_ENDPOINT is set", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318";
    const result = initTracing();
    expect(result).not.toBeNull();
    expect(result).toHaveProperty("shutdown");
    expect(typeof result!.shutdown).toBe("function");

    // Clean up the provider
    await result!.shutdown();
  });
});
