import { Hono } from "hono";
import { cors } from "hono/cors";
import type { DeDiClient } from "@opencred/dedi-client";
import type { SigningKeyProvider } from "@opencred/crypto";
import type { VerifierConfig } from "@opencred/verification";
import type { EnvConfig } from "@opencred/shared";
import { createLogger, type Logger } from "./logger.js";
import {
  authMiddleware,
  bodyLimitMiddleware,
  errorHandler,
  requestLogger,
  rateLimitMiddleware,
} from "./middleware/index.js";
import type { AuthMiddlewareOptions, RateLimitStore } from "./middleware/index.js";
import { namespaceRateLimitKey } from "./middleware/rate-limit-keys.js";
import { createHealthRoutes } from "./routes/health.js";
import { createRevokeRoute } from "./routes/revoke.js";
import { createVerifyRoutes } from "./routes/verify.js";
import { createCredentialsRoute } from "./routes/credentials.js";
import { createBatchRoute, createBatchRevokeRoute } from "./routes/batch.js";
import { createOnboardingRoutes, createBusinessVcOnboardingRoutes } from "./routes/onboarding.js";
import { createCaRequestRoutes, type CertificateAuthorityAdapter } from "./routes/ca-request.js";
import {
  createDomainVerificationRoutes,
  createTypeBOnboardingRoutes,
  type DomainVerificationDeps,
  type TypeBOnboardingDeps,
} from "./routes/domain-verification.js";
import {
  createSchemaStubRoutes,
  createDelegationStubRoutes,
  createRevocationStatusStubRoutes,
} from "./routes/stubs.js";
import { TrustStore } from "./dsc-chain.js";

export interface AppDependencies {
  config: EnvConfig;
  logger?: Logger;
  trustStore?: TrustStore;
  dediClient?: DeDiClient;
  authOptions?: AuthMiddlewareOptions;
  signingKeyProvider?: SigningKeyProvider;
  opencredSigningKeyDid?: string;
  verifierConfig?: VerifierConfig;
  /** Optional CA adapter for Type C onboarding. When undefined, the endpoint returns 501. */
  caAdapter?: CertificateAuthorityAdapter;
  domainVerificationDeps?: DomainVerificationDeps;
  typeBOnboardingDeps?: TypeBOnboardingDeps;
  /** Pluggable rate-limit store (e.g. Redis-backed) for multi-instance deployments. */
  rateLimitStore?: RateLimitStore;
  /**
   * Number of trusted reverse-proxy hops.  Controls how X-Forwarded-For is
   * interpreted for rate limiting.  Default `0` ignores the header entirely.
   */
  trustedProxyHops?: number;
}

export function createApp(deps: AppDependencies) {
  const { config } = deps;
  const logger = deps.logger ?? createLogger(config);
  const app = new Hono();

  // CORS — locked to configured origin.
  // Only allow HTTP methods that the API actually defines routes for (#144).
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

  // Request body size limit — reject oversized payloads early (#174).
  // 1 MiB for general endpoints; batch CSV upload routes may need their own
  // higher limit applied at the route level.
  app.use("/*", bodyLimitMiddleware({ maxSize: 1024 * 1024 }));

  // Shared rate-limit config
  const trustedProxyHops = deps.trustedProxyHops ?? 0;

  // Global rate limit — applies to all endpoints.
  // Uses trusted proxy configuration to prevent IP spoofing (#125, #175).
  app.use(
    "/*",
    rateLimitMiddleware({
      windowMs: 60_000,
      maxRequests: 100,
      store: deps.rateLimitStore,
      trustedProxyHops,
    }),
  );

  // Per-namespace rate limit for credential endpoints (#145).
  // This is keyed on the issuer namespace extracted from the JWT subject
  // claim, falling back to the client IP for unauthenticated requests.
  app.use(
    "/credentials/*",
    rateLimitMiddleware({
      windowMs: 60_000,
      maxRequests: 50,
      store: deps.rateLimitStore,
      keyFn: namespaceRateLimitKey,
    }),
  );

  // Load CSCA trust store if configured
  const trustStore =
    deps.trustStore ??
    (config.CSCA_TRUST_STORE_PATH
      ? TrustStore.load(config.CSCA_TRUST_STORE_PATH, logger)
      : undefined);

  // Health check (before auth — unauthenticated)
  // Liveness at /health, readiness (with dependency checks) at /health/ready
  app.route("/", createHealthRoutes({ dediClient: deps.dediClient }));

  // Public verification endpoint (no auth required)
  app.route("/verify", createVerifyRoutes({ trustStore, dediClient: deps.dediClient }));

  // Onboarding endpoints (unauthenticated — these ARE auth issuance endpoints)
  if (config.JWT_SECRET) {
    const onboardingKey = new TextEncoder().encode(config.JWT_SECRET);

    // Type A DSC onboarding
    if (trustStore) {
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

    // Type D business-VC onboarding
    app.route(
      "/onboarding",
      createBusinessVcOnboardingRoutes({
        jwtSigningKey: onboardingKey,
        jwtIssuer: config.JWT_ISSUER,
        jwtExpirySeconds: config.JWT_EXPIRY_SECONDS,
        verifierConfig: deps.verifierConfig,
        dediClient: deps.dediClient,
        opencredSigningKeyDid: deps.opencredSigningKeyDid,
      }),
    );

    // Type B onboarding — domain-verified SSL-based onboarding
    if (deps.domainVerificationDeps) {
      app.route(
        "/onboarding",
        createTypeBOnboardingRoutes({
          ...deps.domainVerificationDeps,
          capabilityTokenKey: onboardingKey,
          tokenIssuer: config.JWT_ISSUER,
          tokenExpirySeconds: config.JWT_EXPIRY_SECONDS,
          dediClient: deps.dediClient,
          opencredSigningKeyDid: deps.opencredSigningKeyDid,
        }),
      );
    }
  }

  // Type B domain ownership verification (unauthenticated — initiates verification flow)
  app.route("/onboarding", createDomainVerificationRoutes(deps.domainVerificationDeps));

  // Type C — CA API adapter (extension point; returns 501 when no adapter registered)
  app.route("/onboarding", createCaRequestRoutes({ caAdapter: deps.caAdapter }));

  // Interface Signing + Delegated Signing endpoints (authenticated)
  if (deps.authOptions) {
    const { credentials } = createCredentialsRoute({
      config,
      authOptions: deps.authOptions,
      signingKeyProvider: deps.signingKeyProvider,
      dediClient: deps.dediClient,
    });
    app.route("/credentials", credentials);

    // Batch issuance endpoints
    const { batch } = createBatchRoute({
      config,
      authOptions: deps.authOptions,
      signingKeyProvider: deps.signingKeyProvider,
      dediClient: deps.dediClient,
    });
    app.route("/credentials/batch", batch);
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
      app.use(
        "/credentials/revoke/batch",
        authMiddleware(
          { verificationKey: authKey, issuer: config.JWT_ISSUER },
          "credentials:revoke",
        ),
      );
      app.route("/", createRevokeRoute(deps.dediClient));
      app.route("/", createBatchRevokeRoute(deps.dediClient));
    }
  }

  // PRD-specified stub endpoints (#132) — 501 Not Implemented placeholders
  app.route("/schemas", createSchemaStubRoutes());
  app.route("/delegations", createDelegationStubRoutes());
  app.route("/revocation-status", createRevocationStatusStubRoutes());

  // Error handler
  app.onError(errorHandler(logger));

  return { app, logger };
}
