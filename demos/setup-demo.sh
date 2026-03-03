#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────
# OpenCred PoC Demo — Automated Setup
#
# Usage:
#   ./demos/setup-demo.sh
#
# Idempotent: safe to run multiple times. Skips steps that
# are already complete.
# ────────────────────────────────────────────────────────────
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
DIM="\033[2m"
RESET="\033[0m"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEMOS_DIR="$ROOT_DIR/demos"

header() { printf "\n${BOLD}${CYAN}=== %s ===${RESET}\n\n" "$1"; }
ok()     { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
skip()   { printf "  ${YELLOW}○${RESET} %s ${DIM}(skipped)${RESET}\n" "$1"; }
fail()   { printf "  ${RED}✗${RESET} %s\n" "$1"; }
info()   { printf "  ${DIM}%s${RESET}\n" "$1"; }

cd "$ROOT_DIR"

# ── 1. Install & Build ─────────────────────────────────────
header "Step 1: Install dependencies & build"

if command -v pnpm &>/dev/null; then
  pnpm install --frozen-lockfile 2>/dev/null || pnpm install
  ok "Dependencies installed"
else
  fail "pnpm not found — install it: npm i -g pnpm"
  exit 1
fi

pnpm build
ok "All packages built"

# ── 2. Generate Demo Issuer JWK ────────────────────────────
header "Step 2: Generate demo issuer JWK (P-256)"

JWK_PATH="$DEMOS_DIR/sample-keys/demo-issuer.jwk"

if [ -f "$JWK_PATH" ]; then
  skip "Demo JWK already exists at demos/sample-keys/demo-issuer.jwk"
else
  npx tsx "$DEMOS_DIR/generate-demo-jwk.ts"
  ok "Demo JWK generated at demos/sample-keys/demo-issuer.jwk"
fi

# ── 3. Create API .env ─────────────────────────────────────
header "Step 3: Create apps/api/.env"

API_ENV="$ROOT_DIR/apps/api/.env"

if [ -f "$API_ENV" ]; then
  skip "apps/api/.env already exists"
else
  JWT_SECRET=$(openssl rand -hex 48)
  cat > "$API_ENV" <<ENV_EOF
NODE_ENV=development
CORS_ORIGIN=http://localhost:5173
JWT_SECRET=$JWT_SECRET
JWT_ISSUER=opencred
JWT_EXPIRY_SECONDS=3600
ENV_EOF
  ok "apps/api/.env created with random JWT_SECRET"
fi

# ── 4. Verify Sample Data ──────────────────────────────────
header "Step 4: Verify sample data"

CSV_PATH="$DEMOS_DIR/sample-data/batch-education.csv"

if [ -f "$CSV_PATH" ]; then
  ROWS=$(tail -n +2 "$CSV_PATH" | wc -l | tr -d ' ')
  ok "Batch CSV exists: $ROWS data rows in demos/sample-data/batch-education.csv"
else
  fail "Missing demos/sample-data/batch-education.csv"
  exit 1
fi

# ── 5. Detect SoftHSM2 (Optional) ──────────────────────────
header "Step 5: Detect SoftHSM2 (optional — for PKCS#11 demos)"

SOFTHSM_AVAILABLE=false
SOFTHSM_LIB=""

if command -v softhsm2-util &>/dev/null; then
  # Find the shared library
  for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so \
    /opt/homebrew/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/local/lib/libsofthsm2.dylib \
    /opt/homebrew/lib/libsofthsm2.dylib; do
    if [ -f "$candidate" ]; then
      SOFTHSM_LIB="$candidate"
      break
    fi
  done

  if [ -n "$SOFTHSM_LIB" ]; then
    SOFTHSM_AVAILABLE=true
    ok "SoftHSM2 detected: $SOFTHSM_LIB"

    # Initialize demo token if not already present
    if softhsm2-util --show-slots 2>/dev/null | grep -q "demo-token"; then
      skip "SoftHSM demo token already initialised"
    else
      info "Initialising SoftHSM demo token (PIN: 1234)..."
      softhsm2-util --init-token --free --label "demo-token" --pin 1234 --so-pin 5678 2>/dev/null || true
      ok "SoftHSM demo token initialised (label: demo-token, PIN: 1234)"
    fi
  else
    skip "SoftHSM2 utility found but shared library not located"
  fi
else
  skip "SoftHSM2 not installed — PKCS#11 demos will show graceful skip"
  info "Install with: brew install softhsm (macOS) or apt install softhsm2 (Linux)"
fi

# ── 6. Detect Browser Extension Prerequisites ──────────────
header "Step 6: Detect browser extension prerequisites (optional)"

EXTENSION_DIR="$ROOT_DIR/apps/browser-extension"
if [ -d "$EXTENSION_DIR" ]; then
  ok "Browser extension source found at apps/browser-extension/"
  info "To load in Chrome: chrome://extensions → Load unpacked → select apps/browser-extension/dist"
  info "Content script matches include localhost:5173 and localhost:8080 for local dev"
else
  skip "Browser extension directory not found"
fi

# ── Summary ─────────────────────────────────────────────────
header "Setup Complete — Summary"

printf "  ${GREEN}✓${RESET} Dependencies installed & all packages built\n"
printf "  ${GREEN}✓${RESET} Demo issuer JWK: demos/sample-keys/demo-issuer.jwk\n"
printf "  ${GREEN}✓${RESET} API environment:  apps/api/.env\n"
printf "  ${GREEN}✓${RESET} Batch CSV:        demos/sample-data/batch-education.csv\n"

if [ "$SOFTHSM_AVAILABLE" = true ]; then
  printf "  ${GREEN}✓${RESET} SoftHSM2:         ${SOFTHSM_LIB}\n"
else
  printf "  ${YELLOW}○${RESET} SoftHSM2:         not available (PKCS#11 demos will skip)\n"
fi

printf "\n${BOLD}Next steps:${RESET}\n"
printf "  1. CLI demos:   ${CYAN}cd demos && npx tsx run-all.ts${RESET}\n"
printf "  2. Desktop app: ${CYAN}cd apps/desktop && pnpm dev${RESET}\n"
printf "  3. Web app:     ${CYAN}cd apps/api && pnpm dev${RESET}  (terminal 1)\n"
printf "                  ${CYAN}cd apps/web && pnpm dev${RESET}  (terminal 2)\n"
printf "  4. Docker:      ${CYAN}docker compose up -d${RESET}  →  http://localhost:8080\n"
printf "\n  See ${BOLD}demos/DEMO-WALKTHROUGH.md${RESET} for the full runbook.\n\n"
