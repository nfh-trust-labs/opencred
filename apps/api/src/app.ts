import { Hono } from "hono";
import { cors } from "hono/cors";
import type { DeDiClient } from "@opencred/dedi-client";
import type { EnvConfig } from "@opencred/shared";
import { TTLStore } from "@opencred/state";
import { createLogger, type Logger } from "./logger.js";
import { authMiddleware, errorHandler, requestLogger, rateLimitMiddleware } from "./middleware/index.js";
import { health } from "./routes/health.js";
import { createRevokeRoute } from "./routes/revoke.js";
import { createSigningRoutes, type SigningSession } from "./routes/signing.js";

export interface AppDependencies {
  config: EnvConfig;
  logger?: Logger;
  dediClient?: DeDiClient;
  signingSessionStore?: TTLStore<SigningSession>;
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
      exposeHeaders: [
        "X-Request-Id",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
      ],
      maxAge: 86400,
      credentials: true,
    }),
  );

  // Request logger
  app.use("/*", requestLogger(logger));

  // Global rate limit
  app.use(
    "/*",
    rateLimitMiddleware({
      windowMs: 60_000,
      maxRequests: 100,
    }),
  );

  // Health check (before auth — unauthenticated)
  app.route("/", health);

  // Authenticated routes — require capability token
  if (config.JWT_SECRET) {
    const authKey = new TextEncoder().encode(config.JWT_SECRET);

    // Interface Signing — build + package (requires credentials:write scope)
    const sessionStore = deps.signingSessionStore ?? new TTLStore<SigningSession>(
      config.SESSION_TTL_MS,
      config.SESSION_SWEEP_INTERVAL_MS,
    );
    app.use(
      "/credentials/build",
      authMiddleware({ verificationKey: authKey, issuer: config.JWT_ISSUER }, "credentials:write"),
    );
    app.use(
      "/credentials/package",
      authMiddleware({ verificationKey: authKey, issuer: config.JWT_ISSUER }, "credentials:write"),
    );
    app.route("/credentials", createSigningRoutes({ sessionStore }));

    // Credential revocation (requires credentials:revoke scope)
    if (deps.dediClient) {
      app.use(
        "/credentials/revoke",
        authMiddleware({ verificationKey: authKey, issuer: config.JWT_ISSUER }, "credentials:revoke"),
      );
      app.route("/", createRevokeRoute(deps.dediClient));
    }
  }

  // Error handler
  app.onError(errorHandler(logger));

  return { app, logger };
}
