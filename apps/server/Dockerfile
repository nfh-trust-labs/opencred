# =============================================================================
# OpenCred Server — multi-stage Docker build (Phase 6)
# =============================================================================
# Builds the @opencred/server workspace package and all its workspace
# dependencies, then copies only the production output into a minimal
# runtime image.
#
# Build from the repo root:
#   docker build -f apps/server/Dockerfile -t opencred/server:dev .
#
# Run:
#   docker run --rm -p 3100:3100 \
#     -e OPENCRED_KEY_PATH=/run/secrets/issuer.pem \
#     -v /local/path/issuer.pem:/run/secrets/issuer.pem:ro \
#     opencred/server:dev
#
# REQUIRED ENV VARS
#   OPENCRED_KEY_PATH        Absolute path inside the container to a PEM/JWK/
#                            PKCS#8/PFX private key file. Mount as a read-only
#                            volume — never bake key material into the image.
#
# OPTIONAL ENV VARS
#   OPENCRED_PORT            HTTP listen port (default 3100)
#   OPENCRED_LOG_LEVEL       fatal|error|warn|info|debug|trace (default info)
#   OPENCRED_API_KEY         If set, all routes except /health require a
#                            matching Bearer token in the Authorization header.
#   OPENCRED_KEY_LABEL       Display label shown in /v1/keys responses
#   OPENCRED_KEY_PASSWORD    Password for PFX/P12 key files (only when needed)
#   OPENCRED_SESSION_TTL     Ephemeral session TTL in seconds (default 14400)
#
# OPTIONAL CLOUD HSM (TODO #301 follow-up — full integration)
#   OPENCRED_KMS_PROVIDER       aws | azure | gcp | none
#   OPENCRED_KMS_KEY_ARN        AWS KMS key ARN
#   OPENCRED_AZURE_KEY_VAULT_URL  Azure Key Vault base URL
#   OPENCRED_AZURE_KEY_NAME       Azure Key Vault key name
#   OPENCRED_GCP_KMS_KEY_NAME     GCP KMS key resource name
#
# SECURITY
#   - Runs as the non-root `node` user (built into the alpine image).
#   - No secrets are baked into image layers — inject via env vars or volumes
#     at runtime.
#   - The HEALTHCHECK probes /v1/health which never exposes key material.
#   - JSON-LD contexts are bundled in the @opencred/vc-core package — the
#     container never makes outbound HTTP calls to fetch contexts.
#   - Read-only filesystem recommended (see docker-compose.yml `read_only: true`).
#   - All Linux capabilities dropped except NET_BIND_SERVICE (see compose
#     `cap_drop: [ALL]` / `cap_add: [NET_BIND_SERVICE]`).
#   - `no-new-privileges:true` recommended to block privilege escalation
#     (see docker-compose.yml `security_opt`).
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder — install deps + compile TypeScript
# -----------------------------------------------------------------------------
# Pin base image digest for reproducible builds.
# Periodically update: docker pull node:20-alpine && docker inspect --format='{{index .RepoDigests 0}}' node:20-alpine
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c AS builder

# Install pnpm via corepack (matches the pinned version in package.json).
RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /build

# Copy lockfile + workspace manifest first so the install step can be cached
# across source changes that don't touch dependencies.
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./

# Copy every workspace package's package.json so pnpm can resolve them as
# workspace:* dependencies. Listing each one explicitly keeps the layer
# cache stable when unrelated package.json files change.
COPY apps/server/package.json apps/server/package.json
COPY apps/desktop/package.json apps/desktop/package.json
COPY packages/ca-adapter/package.json packages/ca-adapter/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/dedi-client/package.json packages/dedi-client/package.json
COPY packages/did/package.json packages/did/package.json
COPY packages/schema-engine/package.json packages/schema-engine/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/signing/package.json packages/signing/package.json
COPY packages/templates/package.json packages/templates/package.json
COPY packages/vc-core/package.json packages/vc-core/package.json
COPY packages/verification/package.json packages/verification/package.json

# Install only the dependencies needed by the server (and its workspace
# transitive deps) — this skips desktop-specific deps like Electron, which
# would otherwise add hundreds of MB to the image.
RUN pnpm install --frozen-lockfile --filter @opencred/server...

# Copy source for the server and every workspace package it depends on.
COPY tsconfig.base.json tsconfig.base.json
COPY packages/ packages/
COPY apps/server/ apps/server/

# Build the server and every transitive workspace dependency.
RUN pnpm --filter @opencred/server... build

# Strip dev dependencies from the install to shrink the runtime image.
RUN pnpm prune --prod

# -----------------------------------------------------------------------------
# Stage 2: runtime — minimal image with only production artifacts
# -----------------------------------------------------------------------------
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c AS runtime

# Run as the non-root `node` user that ships with the alpine image.
USER node

WORKDIR /app

# Copy the built server, its production node_modules, and every workspace
# package's compiled output. We deliberately copy package.json files too so
# that workspace:* symlinks resolve at runtime.
COPY --from=builder --chown=node:node /build/node_modules ./node_modules
COPY --from=builder --chown=node:node /build/apps/server/dist ./apps/server/dist
COPY --from=builder --chown=node:node /build/apps/server/package.json ./apps/server/package.json
COPY --from=builder --chown=node:node /build/packages ./packages
COPY --from=builder --chown=node:node /build/package.json ./package.json
COPY --from=builder --chown=node:node /build/pnpm-workspace.yaml ./pnpm-workspace.yaml

EXPOSE 3100

# Health check — alpine ships wget but not curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:${OPENCRED_PORT:-3100}/v1/health || exit 1

CMD ["node", "apps/server/dist/index.js"]
