import { serve } from "@hono/node-server";
import { loadConfig } from "@opencred/shared";
import { createApp } from "./app.js";

const config = loadConfig();
const { app, logger } = createApp({ config });

serve(
  {
    fetch: app.fetch,
    port: config.PORT,
  },
  (info) => {
    logger.info({ port: info.port, env: config.NODE_ENV }, "OpenCred API server started");
  },
);
