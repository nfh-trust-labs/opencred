import { Hono } from "hono";
import { cors } from "hono/cors";
import type { EnvConfig } from "@opencred/shared";
import { createLogger, type Logger } from "./logger.js";
import { errorHandler, requestLogger, rateLimitMiddleware } from "./middleware/index.js";
import { health } from "./routes/health.js";

export interface AppDependencies {
  config: EnvConfig;
  logger?: Logger;
}

export function createApp(deps: AppDependencies) {
  const { config } = deps;
  const logger = deps.logger ?? createLogger(config);
  const app = new Hono();

  // CORS — locked to configured origin
  app.use(
    "/*",
    cors({
      origin: config.CORS_ORIGIN,
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization"],
      exposeHeaders: ["X-Request-Id", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
      maxAge: 86400,
      credentials: true,
    }),
  );

  // Request logger
  app.use("/*", requestLogger(logger));

  // Global rate limit
  app.use("/*", rateLimitMiddleware({
    windowMs: 60_000,
    maxRequests: 100,
  }));

  // Health check (before auth — unauthenticated)
  app.route("/", health);

  // Error handler
  app.onError(errorHandler(logger));

  return { app, logger };
}
