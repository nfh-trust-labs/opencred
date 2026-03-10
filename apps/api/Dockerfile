# ==============================================================================
# OpenCred API — Multi-stage Docker Build
# ==============================================================================
# Stage 1 (build):     Full install + compile TypeScript
# Stage 2 (prod-deps): Clean production-only dependency install
# Stage 3 (runtime):   Minimal image with built output + prod deps
# ==============================================================================

# --------------- Stage 1: Build ---------------
FROM node:20-alpine AS build

RUN corepack enable && corepack prepare pnpm@10.30.1 --activate

WORKDIR /app

# Copy workspace config first (better layer caching)
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./

# Copy all package.json files for dependency resolution
COPY packages/shared/package.json packages/shared/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/did/package.json packages/did/package.json
COPY packages/vc-core/package.json packages/vc-core/package.json
COPY packages/verification/package.json packages/verification/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/state/package.json packages/state/package.json
COPY packages/key-attestation/package.json packages/key-attestation/package.json
COPY packages/templates/package.json packages/templates/package.json
COPY packages/dedi-client/package.json packages/dedi-client/package.json
COPY packages/schema-engine/package.json packages/schema-engine/package.json
COPY apps/api/package.json apps/api/package.json

# Install all dependencies (including dev — needed for build)
RUN pnpm install --frozen-lockfile

# Copy source code (only packages the API needs — exclude signing/desktop-only packages)
COPY packages/shared/ packages/shared/
COPY packages/crypto/ packages/crypto/
COPY packages/did/ packages/did/
COPY packages/vc-core/ packages/vc-core/
COPY packages/verification/ packages/verification/
COPY packages/auth/ packages/auth/
COPY packages/state/ packages/state/
COPY packages/key-attestation/ packages/key-attestation/
COPY packages/templates/ packages/templates/
COPY packages/dedi-client/ packages/dedi-client/
COPY packages/schema-engine/ packages/schema-engine/
COPY apps/api/ apps/api/

# Build all packages and the API
RUN pnpm -r run build

# --------------- Stage 2: Production Dependencies ---------------
FROM node:20-alpine AS prod-deps

RUN corepack enable && corepack prepare pnpm@10.30.1 --activate

WORKDIR /app

# Copy workspace config + lockfile
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./

# Copy all package.json files
COPY packages/shared/package.json packages/shared/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/did/package.json packages/did/package.json
COPY packages/vc-core/package.json packages/vc-core/package.json
COPY packages/verification/package.json packages/verification/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/state/package.json packages/state/package.json
COPY packages/key-attestation/package.json packages/key-attestation/package.json
COPY packages/templates/package.json packages/templates/package.json
COPY packages/dedi-client/package.json packages/dedi-client/package.json
COPY packages/schema-engine/package.json packages/schema-engine/package.json
COPY apps/api/package.json apps/api/package.json

# Install production dependencies only
RUN pnpm install --frozen-lockfile --prod

# --------------- Stage 3: Runtime ---------------
FROM node:20-alpine AS runtime

# Security: run as non-root user
RUN addgroup -g 1001 -S opencred && \
    adduser -S opencred -u 1001 -G opencred

WORKDIR /app

# Copy production node_modules from prod-deps stage
# pnpm uses per-package node_modules with symlinks to the root virtual store.
# We must copy both the root store AND each package's node_modules directory.
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=prod-deps /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=prod-deps /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=prod-deps /app/packages/crypto/node_modules ./packages/crypto/node_modules
COPY --from=prod-deps /app/packages/did/node_modules ./packages/did/node_modules
COPY --from=prod-deps /app/packages/vc-core/node_modules ./packages/vc-core/node_modules
COPY --from=prod-deps /app/packages/verification/node_modules ./packages/verification/node_modules
COPY --from=prod-deps /app/packages/auth/node_modules ./packages/auth/node_modules
COPY --from=prod-deps /app/packages/state/node_modules ./packages/state/node_modules
COPY --from=prod-deps /app/packages/key-attestation/node_modules ./packages/key-attestation/node_modules
COPY --from=prod-deps /app/packages/templates/node_modules ./packages/templates/node_modules
COPY --from=prod-deps /app/packages/dedi-client/node_modules ./packages/dedi-client/node_modules
COPY --from=prod-deps /app/packages/schema-engine/node_modules ./packages/schema-engine/node_modules

# Copy built output from build stage
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/package.json
COPY --from=build /app/packages/crypto/dist ./packages/crypto/dist
COPY --from=build /app/packages/crypto/package.json ./packages/crypto/package.json
COPY --from=build /app/packages/did/dist ./packages/did/dist
COPY --from=build /app/packages/did/package.json ./packages/did/package.json
COPY --from=build /app/packages/vc-core/dist ./packages/vc-core/dist
COPY --from=build /app/packages/vc-core/package.json ./packages/vc-core/package.json
COPY --from=build /app/packages/verification/dist ./packages/verification/dist
COPY --from=build /app/packages/verification/package.json ./packages/verification/package.json
COPY --from=build /app/packages/auth/dist ./packages/auth/dist
COPY --from=build /app/packages/auth/package.json ./packages/auth/package.json
COPY --from=build /app/packages/state/dist ./packages/state/dist
COPY --from=build /app/packages/state/package.json ./packages/state/package.json
COPY --from=build /app/packages/key-attestation/dist ./packages/key-attestation/dist
COPY --from=build /app/packages/key-attestation/package.json ./packages/key-attestation/package.json
COPY --from=build /app/packages/templates/dist ./packages/templates/dist
COPY --from=build /app/packages/templates/package.json ./packages/templates/package.json
COPY --from=build /app/packages/dedi-client/dist ./packages/dedi-client/dist
COPY --from=build /app/packages/dedi-client/package.json ./packages/dedi-client/package.json
COPY --from=build /app/packages/schema-engine/dist ./packages/schema-engine/dist
COPY --from=build /app/packages/schema-engine/package.json ./packages/schema-engine/package.json
COPY --from=build /app/apps/api/dist ./apps/api/dist
COPY --from=build /app/apps/api/package.json ./apps/api/package.json

# Copy workspace root files needed for pnpm module resolution
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/pnpm-workspace.yaml ./pnpm-workspace.yaml

# JSON-LD contexts are bundled in packages/vc-core/dist/contexts/ (built via cp in vc-core build)

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Health check (wget available in alpine, curl is not)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

USER opencred

CMD ["node", "apps/api/dist/index.js"]
