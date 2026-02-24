# ==============================================================================
# OpenCred API — Multi-stage Docker Build
# ==============================================================================
# Stage 1: Build the monorepo (all packages + API)
# Stage 2: Minimal runtime image with only production artifacts
# ==============================================================================

# --------------- Stage 1: Build ---------------
FROM node:20-alpine AS build

# Install pnpm
RUN corepack enable && corepack prepare pnpm@10.30.1 --activate

WORKDIR /app

# Copy workspace configuration first (better layer caching)
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./

# Copy all package.json files for dependency resolution
COPY packages/shared/package.json packages/shared/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/did/package.json packages/did/package.json
COPY packages/vc-core/package.json packages/vc-core/package.json
COPY packages/verification/package.json packages/verification/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/state/package.json packages/state/package.json
COPY packages/delegation/package.json packages/delegation/package.json
COPY packages/dedi-client/package.json packages/dedi-client/package.json
COPY packages/schema-engine/package.json packages/schema-engine/package.json
COPY apps/api/package.json apps/api/package.json

# Install dependencies (frozen lockfile for reproducibility)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY packages/ packages/
COPY apps/api/ apps/api/

# Build all packages and the API
RUN pnpm -r run build

# Prune dev dependencies for a leaner production copy
RUN pnpm prune --prod

# --------------- Stage 2: Runtime ---------------
FROM node:20-alpine AS runtime

# Security: run as non-root user
RUN addgroup -g 1001 -S opencred && \
    adduser -S opencred -u 1001 -G opencred

WORKDIR /app

# Copy built output and production dependencies from build stage
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/package.json
COPY --from=build /app/packages/crypto/dist ./packages/crypto/dist
COPY --from=build /app/packages/crypto/package.json ./packages/crypto/package.json
COPY --from=build /app/packages/crypto/node_modules ./packages/crypto/node_modules
COPY --from=build /app/packages/did/dist ./packages/did/dist
COPY --from=build /app/packages/did/package.json ./packages/did/package.json
COPY --from=build /app/packages/vc-core/dist ./packages/vc-core/dist
COPY --from=build /app/packages/vc-core/package.json ./packages/vc-core/package.json
COPY --from=build /app/packages/vc-core/node_modules ./packages/vc-core/node_modules
COPY --from=build /app/packages/verification/dist ./packages/verification/dist
COPY --from=build /app/packages/verification/package.json ./packages/verification/package.json
COPY --from=build /app/packages/verification/node_modules ./packages/verification/node_modules
COPY --from=build /app/packages/auth/dist ./packages/auth/dist
COPY --from=build /app/packages/auth/package.json ./packages/auth/package.json
COPY --from=build /app/packages/state/dist ./packages/state/dist
COPY --from=build /app/packages/state/package.json ./packages/state/package.json
COPY --from=build /app/packages/delegation/dist ./packages/delegation/dist
COPY --from=build /app/packages/delegation/package.json ./packages/delegation/package.json
COPY --from=build /app/packages/delegation/node_modules ./packages/delegation/node_modules
COPY --from=build /app/packages/dedi-client/dist ./packages/dedi-client/dist
COPY --from=build /app/packages/dedi-client/package.json ./packages/dedi-client/package.json
COPY --from=build /app/packages/schema-engine/dist ./packages/schema-engine/dist
COPY --from=build /app/packages/schema-engine/package.json ./packages/schema-engine/package.json
COPY --from=build /app/packages/schema-engine/node_modules ./packages/schema-engine/node_modules
COPY --from=build /app/apps/api/dist ./apps/api/dist
COPY --from=build /app/apps/api/package.json ./apps/api/package.json

# Copy workspace root files needed for pnpm resolution
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/pnpm-workspace.yaml ./pnpm-workspace.yaml

# JSON-LD contexts are bundled in packages/vc-core/dist/contexts/ (built via cp in vc-core build)
# No additional copy needed — they're included in the vc-core/dist copy above

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

USER opencred

CMD ["node", "apps/api/dist/index.js"]
