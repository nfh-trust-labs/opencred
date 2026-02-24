import { serve } from "@hono/node-server";
import { DeDiClient } from "@opencred/dedi-client";
import { loadConfig } from "@opencred/shared";
import { createApp } from "./app.js";

const config = loadConfig();

const dediClient = config.DEDI_API_URL
  ? new DeDiClient({
      baseUrl: config.DEDI_API_URL,
      timeoutMs: config.DEDI_API_TIMEOUT_MS,
      maxRetries: 3,
      circuitBreakerThreshold: 5,
    })
  : undefined;

const { app, logger } = createApp({ config, dediClient });

const server = serve(
  {
    fetch: app.fetch,
    port: config.PORT,
  },
  (info) => {
    logger.info({ port: info.port, env: config.NODE_ENV }, "OpenCred API server started");
  },
);

// Graceful shutdown: drain connections on SIGTERM/SIGINT (container orchestration)
function shutdown(signal: string) {
  logger.info({ signal }, "Shutdown signal received, draining connections");
  server.close(() => {
    logger.info("Server closed, exiting");
    process.exit(0);
  });
  // Force exit after 10s if connections don't drain
  setTimeout(() => {
    logger.warn("Forced shutdown after timeout");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
