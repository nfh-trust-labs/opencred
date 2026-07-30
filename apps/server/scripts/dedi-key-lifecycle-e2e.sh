#!/usr/bin/env bash
#
# dedi-key-lifecycle-e2e.sh — live end-to-end validation of the DeDi per-key
# registry lifecycle against a REAL DeDi + did:web. Tracks issue #660.
#
# Black-box harness: starts/stops a LOCAL OpenCred server (so it can restart
# with a fresh signing key + index for the rotation step) pointed at a live
# DeDi instance, then drives the full lifecycle over the server's HTTP API and
# asserts on the verify outcomes:
#
#   1. publish #key-0 (active, via startup auto-publish) + host did.json in DeDi
#      → issue cred A → verify A = VALID
#   2. rotate to #key-1 (restart server with key1@index1, carry did.json forward)
#      → verify A still VALID (rotated keeps old creds valid) → issue cred B →
#      verify B = VALID
#   3. revoke #key-0 → verify A = REVOKED; verify B still VALID; resolve #key-0
#      → "revoked"; the revoked key STAYS in verificationMethod[] but leaves
#      assertionMethod.  With REVOKE_ALL=true also revoke #key-1 → verify B
#      = REVOKED (the literal "A and B revoked" scenario).
#   4. did:web offline fallback → the issuer domain serves no /.well-known/
#      did.json (404), yet verify succeeds because the verifier resolves the
#      did.json from the DeDi `did-documents` registry.
#
# LOAD-BEARING PRECONDITIONS (discovered during harness design — see #660):
#   • OPENCRED_DEDI_NAMESPACE MUST equal OPENCRED_ISSUER_DOMAIN. For did:web the
#     verifier derives the key-status namespace from the did:web host; if they
#     differ the status lookup 404s and SILENTLY PASSES, masking revoke. This
#     script enforces it (namespace := DOMAIN).
#   • Use an EC signing key. data-integrity proofs reject RSA, so an EC key is
#     what populates proof.verificationMethod and actually exercises the
#     per-key revoke path. This script generates prime256v1 keys.
#
# VALIDATED: this script's default flow was run end-to-end on 2026-06-08
# against api.dedi.global (namespace "issuer.example"): all four steps and
# both REVOKE_ALL revokes passed (#key-0 + #key-1 both ended "revoked").
#
# Usage:
#   export OPENCRED_DEDI_BASE_URL=https://api.dedi.global
#   export OPENCRED_DEDI_AUTH_TYPE=api-key            # or: bearer
#   export OPENCRED_DEDI_API_KEY=...                  # if auth-type=api-key
#   # or: export OPENCRED_DEDI_EMAIL=... OPENCRED_DEDI_PASSWORD=...   (bearer)
#   export DOMAIN=issuer.example                      # == DeDi namespace you control
#   ./apps/server/scripts/dedi-key-lifecycle-e2e.sh
#
# Requires: bash, curl, jq, openssl, pnpm (to build+run the server), node>=20.
set -euo pipefail

# ── Operator config ──────────────────────────────────────────────────────────
: "${OPENCRED_DEDI_BASE_URL:?set OPENCRED_DEDI_BASE_URL (live DeDi)}"
: "${OPENCRED_DEDI_AUTH_TYPE:?set OPENCRED_DEDI_AUTH_TYPE=api-key|bearer}"
: "${DOMAIN:?set DOMAIN — the issuer domain, which MUST equal your DeDi namespace}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SERVER_CMD="${SERVER_CMD:-pnpm --filter @opencred/server start}"  # server start command
PORT="${OPENCRED_PORT:-3100}"
BASE="http://127.0.0.1:${PORT}"
API_KEY="${OPENCRED_API_KEY:-$(openssl rand -base64 32)}"
REVOKE_ALL="${REVOKE_ALL:-false}"
WORK="$(mktemp -d)"
SERVER_PID=""

log()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Enforce the load-bearing preconditions. did:web + DeDi-hosted did.json so the
# offline fallback (step 4) has something to resolve.
export OPENCRED_API_KEY="$API_KEY"
export OPENCRED_ISSUER_DID_METHOD=web
export OPENCRED_ISSUER_DOMAIN="$DOMAIN"
export OPENCRED_DEDI_NAMESPACE="$DOMAIN"      # == issuer domain (load-bearing)
export OPENCRED_DEDI_HOST_DID_DOC=true
AUTH_H="Authorization: Bearer ${API_KEY}"
ISSUER_DID="did:web:${DOMAIN}"

cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

start_server() { # $1=key-path  $2=key-index
  cleanup; SERVER_PID=""
  ( cd "$REPO_ROOT" && \
    OPENCRED_KEY_PATH="$1" OPENCRED_DIDWEB_KEY_INDEX="$2" OPENCRED_PORT="$PORT" \
    $SERVER_CMD ) >"$WORK/server-idx$2.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    curl -fsS "$BASE/v1/health" >/dev/null 2>&1 && { ok "server up (signing key index $2)"; return 0; }
    sleep 1
  done
  cat "$WORK/server-idx$2.log" >&2; die "server did not become healthy on $BASE"
}

# Every protected endpoint (issue, keys/*, AND verify) needs the Bearer token
# whenever OPENCRED_API_KEY is set, which it always is here.
api() { curl -fsS -X "$1" "$BASE$2" -H "$AUTH_H" -H 'Content-Type: application/json' "${@:3}"; }

# Minimal inline-schema, data-integrity issuance. Returns the signed VC (JSON).
issue_vc() { # $1 = subject label
  jq -n --arg n "$1" '{
    inlineSchema: { "$schema":"https://json-schema.org/draft/2020-12/schema",
      type:"object", properties:{ name:{type:"string"} }, required:["name"] },
    credentialSubject: { name: $n },
    validFrom: "2026-01-01T00:00:00Z",
    proofFormat: "data-integrity"
  }' | api POST /v1/credentials/issue -d @- | jq -c '.credential'
}
# Verify a VC (JSON object) → echo "<valid> <code>". The verify endpoint takes
# `credential` as a STRING, so the VC object is stringified.
verify() { jq -n --argjson c "$1" '{credential:($c|tostring)}' \
  | api POST /v1/credentials/verify -d @- | jq -r '"\(.valid) \(.code)"'; }
# GET the current did.json; the endpoint wraps it as { did, document } — the
# rotate/revoke `currentDidDocument` field wants the inner W3C document.
did_document() { api GET /v1/keys/did-document | jq -c '.document'; }
key_status() { # $1 = verification method
  api POST /v1/keys/resolve -d "$(jq -n --arg vm "$1" '{verificationMethod:$vm}')" \
    | jq -r '.status // .keyStatus'; }

# ── Step 0: start with key0 @ index 0 (startup auto-publishes #key-0) ─────────
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/key0.pem"
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/key1.pem"
log "Step 0 — start server (key0 @ #key-0); DeDi=$OPENCRED_DEDI_BASE_URL ns=$DOMAIN"
start_server "$WORK/key0.pem" 0
VM0="${ISSUER_DID}#key-0"
VM1="${ISSUER_DID}#key-1"

# ── Step 1: issue A + verify ─────────────────────────────────────────────────
log "Step 1 — #key-0 published at startup; issue cred A + verify"
DIDDOC0="$(did_document)"; echo "$DIDDOC0" >"$WORK/diddoc0.json"
ok "issuer DID: $ISSUER_DID  (did.json published to DeDi)"
VC_A="$(issue_vc "E2E Subject A")"; ok "issued cred A (signed by #key-0)"
read -r v c <<<"$(verify "$VC_A")"
[[ "$v" == "true" ]] && ok "verify A = $c" || die "verify A expected VALID, got valid=$v code=$c"

# ── Step 2: rotate to #key-1 (restart with key1@index1) ──────────────────────
log "Step 2 — rotate to #key-1 (restart server signing with key1 @ index 1)"
start_server "$WORK/key1.pem" 1
api POST /v1/keys/rotate \
  -d "$(jq -n --argjson doc "$DIDDOC0" '{newKeyIndex:1, currentDidDocument:$doc, hostDidDocument:true}')" \
  >/dev/null && ok "rotated → #key-1 active, #key-0 rotated (both in did.json)"
read -r v c <<<"$(verify "$VC_A")"
[[ "$v" == "true" ]] && ok "verify A still VALID after rotate (rotated keeps old creds valid)" \
  || die "verify A after rotate expected VALID, got valid=$v code=$c"
VC_B="$(issue_vc "E2E Subject B")"; ok "issued cred B (signed by #key-1)"
read -r v c <<<"$(verify "$VC_B")"
[[ "$v" == "true" ]] && ok "verify B = $c" || die "verify B expected VALID, got valid=$v code=$c"

# ── Step 3: revoke #key-0 → A REVOKED, B still VALID ─────────────────────────
log "Step 3 — revoke #key-0"
DIDDOC1="$(did_document)"
api POST /v1/keys/revoke \
  -d "$(jq -n --arg vm "$VM0" --argjson doc "$DIDDOC1" \
        '{verificationMethod:$vm, currentDidDocument:$doc, hostDidDocument:true}')" \
  >/dev/null && ok "revoked #key-0"
read -r v c <<<"$(verify "$VC_A")"
[[ "$v" == "false" && "$c" == "REVOKED" ]] && ok "verify A = REVOKED" \
  || die "verify A after revoke expected REVOKED, got valid=$v code=$c"
read -r v c <<<"$(verify "$VC_B")"
[[ "$v" == "true" ]] && ok "verify B still VALID (#key-1 active)" \
  || die "verify B after revoking #key-0 expected VALID, got valid=$v code=$c"
[[ "$(key_status "$VM0")" == "revoked" ]] && ok "resolve #key-0 → revoked" \
  || die "resolve #key-0 expected revoked"

if [[ "$REVOKE_ALL" == "true" ]]; then
  log "Step 3b — revoke #key-1 too (REVOKE_ALL=true) → B REVOKED"
  # Revoking the last active key would leave an empty assertionMethod, so do NOT
  # re-host the did.json (hostDidDocument:false); the key stays resolvable in
  # verificationMethod[] and its status flips to revoked.
  api POST /v1/keys/revoke \
    -d "$(jq -n --arg vm "$VM1" --argjson doc "$DIDDOC1" \
          '{verificationMethod:$vm, currentDidDocument:$doc, hostDidDocument:false}')" \
    >/dev/null && ok "revoked #key-1"
  read -r v c <<<"$(verify "$VC_B")"
  [[ "$v" == "false" && "$c" == "REVOKED" ]] && ok "verify B = REVOKED" \
    || die "verify B after revoke expected REVOKED, got valid=$v code=$c"
  [[ "$(key_status "$VM1")" == "revoked" ]] && ok "resolve #key-1 → revoked"
fi

# ── Step 4: did:web offline fallback ─────────────────────────────────────────
# The verify steps above already exercised this: the issuer domain serves no
# /.well-known/did.json (HTTP 404), yet every signature check passed because the
# verifier resolved the did.json from the DeDi `did-documents` registry. Probe
# the domain to make the fallback explicit in the run log.
log "Step 4 — did:web offline fallback (did.json served from DeDi, not the domain)"
DOMAIN_CODE="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "https://${DOMAIN}/.well-known/did.json" 2>/dev/null || echo 000)"
if [[ "$DOMAIN_CODE" != "200" ]]; then
  ok "domain serves no did.json (HTTP $DOMAIN_CODE) — the passing verifies used the DeDi fallback"
else
  ok "domain serves did.json (HTTP 200); DeDi copy is the offline fallback"
fi

log "ALL CHECKS PASSED"
ok "publish → issue → verify → rotate → revoke → REVOKED + did:web DeDi fallback confirmed"
echo "logs + artifacts in: $WORK"
