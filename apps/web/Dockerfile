# ==============================================================================
# OpenCred Web UI — Multi-stage Docker Build
# ==============================================================================
# Stage 1: Build the Vite SPA
# Stage 2: Serve static files with Nginx
# ==============================================================================

# --------------- Stage 1: Build ---------------
FROM node:20-alpine AS build

# Install pnpm
RUN corepack enable && corepack prepare pnpm@10.30.1 --activate

WORKDIR /app

# Copy workspace configuration first (better layer caching)
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./

# Copy package.json files needed for install
COPY apps/web/package.json apps/web/package.json
# Include packages that web may reference during build
COPY packages/shared/package.json packages/shared/package.json

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build-time arg for API URL (baked into the SPA JS bundle)
ARG VITE_API_URL=/api

# Copy source code
COPY packages/shared/ packages/shared/
COPY apps/web/ apps/web/

# Build the web app (VITE_API_URL is picked up by Vite at build time)
ENV VITE_API_URL=${VITE_API_URL}
RUN pnpm --filter @opencred/shared run build && \
    pnpm --filter @opencred/web run build

# --------------- Stage 2: Nginx Runtime ---------------
FROM nginx:alpine AS runtime

# Remove default nginx config and static files
RUN rm /etc/nginx/conf.d/default.conf && \
    rm -rf /usr/share/nginx/html/*

# Copy custom nginx config
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf

# Copy built static files from build stage
COPY --from=build /app/apps/web/dist /usr/share/nginx/html

# Security: run entirely as non-root nginx user (unprivileged port 8080)
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid && \
    # Remove default nginx.conf 'user' directive so nginx runs as current user
    sed -i 's/^user  nginx;/# user  nginx;/' /etc/nginx/nginx.conf

EXPOSE 8080

# Default API backend URL — overridable at runtime via env var
ENV API_BACKEND_URL=http://api:3000/

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

USER nginx

# Substitute env vars in nginx config at startup, then run nginx.
# NGINX_RESOLVER is extracted from the container's /etc/resolv.conf so DNS
# resolution works on both Docker Compose (127.0.0.11) and Railway.
CMD ["/bin/sh", "-c", "envsubst '${API_BACKEND_URL}' < /etc/nginx/conf.d/default.conf > /tmp/default.conf && mv /tmp/default.conf /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]
