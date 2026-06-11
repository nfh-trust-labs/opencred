#\!/usr/bin/env bash
# E2E smoke test against containerized OpenCred stack.
# Runs: health check, basic API probes.
# Exit 0 = all passed, non-zero = failure.

set -euo pipefail

COMPOSE_FILE="${1:-docker-compose.yml}"
API_URL="http://localhost:3000"
WEB_URL="http://localhost:8080"
TIMEOUT=60

cleanup() {
  echo "==> Tearing down..."
  docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Starting OpenCred stack..."

# Create minimal .env for test
mkdir -p apps/api
cat > apps/api/.env <<ENVFILE
NODE_ENV=production
PORT=3000
LOG_LEVEL=info
CORS_ORIGIN=http://localhost:8080
ENVFILE

docker compose -f "$COMPOSE_FILE" up -d

# Wait for API health
echo "==> Waiting for API health..."
elapsed=0
until curl -sf "$API_URL/health" > /dev/null 2>&1; do
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "FAIL: API did not become healthy within ${TIMEOUT}s"
    docker compose -f "$COMPOSE_FILE" logs api
    exit 1
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
echo "OK: API is healthy"
curl -s "$API_URL/health" | python3 -m json.tool 2>/dev/null || curl -s "$API_URL/health"

# Wait for Web UI
echo "==> Waiting for Web UI..."
elapsed=0
until curl -sf "$WEB_URL/" > /dev/null 2>&1; do
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "FAIL: Web UI did not respond within ${TIMEOUT}s"
    docker compose -f "$COMPOSE_FILE" logs web
    exit 1
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
echo "OK: Web UI is serving"

# Verify security headers
echo "==> Checking security headers..."
HEADERS=$(curl -sI "$WEB_URL/")

check_header() {
  local header="$1"
  if echo "$HEADERS" | grep -qi "$header"; then
    echo "OK: $header present"
  else
    echo "FAIL: $header missing"
    exit 1
  fi
}

check_header "X-Frame-Options"
check_header "X-Content-Type-Options"
check_header "Content-Security-Policy"
check_header "Strict-Transport-Security"

# Verify non-root execution
echo "==> Verifying non-root execution..."
API_USER=$(docker exec opencred-api id -un 2>/dev/null || echo "unknown")
if [ "$API_USER" = "root" ]; then
  echo "FAIL: API container running as root"
  exit 1
fi
echo "OK: API running as $API_USER"

# Verify read-only filesystem (if configured)
echo "==> Checking container security..."
if docker exec opencred-api touch /app/test-write 2>/dev/null; then
  docker exec opencred-api rm -f /app/test-write 2>/dev/null
  echo "WARN: API filesystem is writable (read-only not enforced at this level)"
else
  echo "OK: API filesystem is read-only"
fi

# Verify no secrets in image layers
echo "==> Checking image layers for secrets..."
for img in opencred-api opencred-web; do
  if docker history "$img" 2>/dev/null | grep -iE "(JWT_SECRET|PRIVATE_KEY|password)" > /dev/null 2>&1; then
    echo "FAIL: Secrets found in $img image layers"
    exit 1
  fi
  echo "OK: No secrets in $img layers"
done

echo ""
echo "========================================="
echo "  All smoke tests passed\!"
echo "========================================="
