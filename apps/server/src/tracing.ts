/**
 * OpenTelemetry tracing — opt-in via OTEL_EXPORTER_OTLP_ENDPOINT.
 *
 * When the env var is not set, this module returns null and adds zero
 * overhead. When set, it initialises a NodeTracerProvider that exports
 * spans via OTLP/HTTP to the configured collector.
 */

import { NodeTracerProvider, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { Resource } from "@opentelemetry/resources";
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from "@opentelemetry/semantic-conventions";

export function initTracing(): { shutdown: () => Promise<void> } | null {
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint) return null;

  const resource = new Resource({
    [ATTR_SERVICE_NAME]: "opencred-server",
    [ATTR_SERVICE_VERSION]: "0.1.0",
  });

  const exporter = new OTLPTraceExporter({ url: `${endpoint}/v1/traces` });
  const provider = new NodeTracerProvider({ resource });
  provider.addSpanProcessor(new SimpleSpanProcessor(exporter));
  provider.register();

  return {
    async shutdown() {
      await provider.shutdown();
    },
  };
}
