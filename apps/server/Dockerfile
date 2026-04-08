# ==============================================================================
# OpenCred Server — Multi-stage Docker Build
# ==============================================================================
# Builds the @opencred/server package and all workspace dependencies,
# then copies only the production output into a minimal runtime image.
#
# Build from the repo root:
#   docker build -f apps/server/Dockerfile .
#
# SECURITY:
#   - Non-root user (node) — container never runs as root
#   - No secrets baked into image layers — inject via env vars at runtime
#   - Read-only filesystem recommended (see docker-compose.yml)
#   - All capabilities dropped except NET_BIND_SERVICE (see compose)
# ==============================================================================

# Pin base image digest for reproducible builds.
# Periodically update: docker pull node:20-alpine && docker inspect --format='{{index .RepoDigests 0}}' node:20-alpine
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c AS builder

# Install pnpm
RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /build

# Copy dependency manifests first for layer caching
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/server/package.json apps/server/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/did/package.json packages/did/package.json
COPY packages/key-attestation/package.json packages/key-attestation/package.json
COPY packages/schema-engine/package.json packages/schema-engine/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/signing/package.json packages/signing/package.json
COPY packages/vc-core/package.json packages/vc-core/package.json
COPY packages/verification/package.json packages/verification/package.json
COPY packages/templates/package.json packages/templates/package.json
COPY packages/domain-verification/package.json packages/domain-verification/package.json
COPY packages/ca-adapter/package.json packages/ca-adapter/package.json

# Install all dependencies (including dev for building)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY packages/ packages/
COPY apps/server/ apps/server/

# Build server and all workspace dependencies it needs
RUN pnpm --filter @opencred/server... build

# Prune dev dependencies for a leaner production image
RUN pnpm prune --prod

# ==============================================================================
# Runtime stage — minimal image with only production artifacts
# ==============================================================================
FROM node:20-alpine@sha256:f598378b5240225e6beab68fa9f356db1fb8efe55173e6d4d8153113bb8f333c

# Security: run as non-root user (node user is built into node:alpine)
USER node

WORKDIR /app

# Copy built output and production node_modules
COPY --from=builder --chown=node:node /build/node_modules ./node_modules
COPY --from=builder --chown=node:node /build/apps/server/dist ./apps/server/dist
COPY --from=builder --chown=node:node /build/apps/server/package.json ./apps/server/package.json
COPY --from=builder --chown=node:node /build/packages ./packages
COPY --from=builder --chown=node:node /build/package.json ./package.json
COPY --from=builder --chown=node:node /build/pnpm-workspace.yaml ./pnpm-workspace.yaml

EXPOSE 3100

# Health check — alpine has wget but not curl
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3100/health || exit 1

CMD ["node", "apps/server/dist/index.js"]
