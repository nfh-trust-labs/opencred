import { Hono } from "hono";
import { cors } from "hono/cors";
import type { DeDiClient } from "@opencred/dedi-client";
import type { SigningKeyProvider } from "@opencred/crypto";
import type { EnvConfig } from "@opencred/shared";
import { createLogger, type Logger } from "./logger.js";
import {
  authMiddleware,
  errorHandler,
  requestLogger,
  rateLimitMiddleware,
} from "./middleware/index.js";
import type { AuthMiddlewareOptions } from "./middleware/index.js";
import { health } from "./routes/health.js";
import { createRevokeRoute } from "./routes/revoke.js";
import { createVerifyRoutes } from "./routes/verify.js";
import { createCredentialsRoute } from "./routes/credentials.js";
import { createOnboardingRoutes } from "./routes/onboarding.js";
import { TrustStore } from "./dsc-chain.js";

export interface AppDependencies {
  config: EnvConfig;
  logger?: Logger;
  trustStore?: TrustStore;
  dediClient?: DeDiClient;
  authOptions?: AuthMiddlewareOptions;
  signingKeyProvider?: SigningKeyProvider;
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

  // Load CSCA trust store if configured
  const trustStore =
    deps.trustStore ??
    (config.CSCA_TRUST_STORE_PATH
      ? TrustStore.load(config.CSCA_TRUST_STORE_PATH, logger)
      : undefined);

  // Health check (before auth — unauthenticated)
  app.route("/", health);

  // Public verification endpoint (no auth required)
  app.route("/verify", createVerifyRoutes({ trustStore, dediClient: deps.dediClient }));

  // Type A DSC onboarding (unauthenticated — this IS the auth issuance endpoint)
  if (config.JWT_SECRET && trustStore) {
    const onboardingKey = new TextEncoder().encode(config.JWT_SECRET);
    app.route(
      "/onboarding",
      createOnboardingRoutes({
        trustStore,
        jwtSigningKey: onboardingKey,
        jwtIssuer: config.JWT_ISSUER,
        jwtExpirySeconds: config.JWT_EXPIRY_SECONDS,
      }),
    );
  }

  // Interface Signing + Delegated Signing endpoints (authenticated)
  if (deps.authOptions) {
    const { credentials } = createCredentialsRoute({
      config,
      authOptions: deps.authOptions,
      signingKeyProvider: deps.signingKeyProvider,
      dediClient: deps.dediClient,
    });
    app.route("/credentials", credentials);
  }

  // Authenticated routes — require capability token
  if (config.JWT_SECRET) {
    const authKey = new TextEncoder().encode(config.JWT_SECRET);

    // Credential revocation (requires credentials:revoke scope)
    if (deps.dediClient) {
      app.use(
        "/credentials/revoke",
        authMiddleware(
          { verificationKey: authKey, issuer: config.JWT_ISSUER },
          "credentials:revoke",
        ),
      );
      app.route("/", createRevokeRoute(deps.dediClient));
    }
  }

  // Error handler
  app.onError(errorHandler(logger));

  return { app, logger };
}
