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

serve(
  {
    fetch: app.fetch,
    port: config.PORT,
  },
  (info) => {
    logger.info({ port: info.port, env: config.NODE_ENV }, "OpenCred API server started");
  },
);
