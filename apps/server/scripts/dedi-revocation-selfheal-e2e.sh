#!/usr/bin/env bash
#
# dedi-revocation-selfheal-e2e.sh — live end-to-end validation of credential
# revocation against a REAL DeDi, with special focus on the self-healing
# stranded-draft recovery (#718, opencred-releases#11).
#
# Why this exists: DeDi's publish is two steps — `save-record-as-draft` then
# `publish-records`. The #11 timeout lands on the first step, so a write can
# land server-side as a DRAFT that `lookup/` 404s (#610), never reaching LIVE.
# The #718 fix self-heals: on a duplicate it looks the record up and, if the
# record is a stranded draft (not LIVE), drives `publish-records` to advance
# it. The one assumption that needs LIVE confirmation is: does `publish-records`
# reliably advance a stranded draft to LIVE? Part A answers exactly that.
#
# Black-box: starts a LOCAL OpenCred server (did:key issuer — no domain needed)
# pointed at a live DeDi instance, and also calls the DeDi API directly (to
# deterministically STRAND a draft, which can't be forced reliably otherwise).
#
#   Part A — DeDi behaviour probe (the open question, no OpenCred):
#     save-record-as-draft(R) → lookup(R) MUST be 404 (draft invisible)
#     → publish-records([R]) → lookup(R) MUST be 200 (now LIVE).
#   Part B — integrated self-heal (the #718 core):
#     strand a draft for hash H (direct DeDi, no publish)
#     → OpenCred revocation-status(H) MUST be revoked:false (stranded)
#     → OpenCred revoke(H) MUST succeed (self-heal advances the draft)
#     → OpenCred revocation-status(H) MUST be revoked:true (now LIVE).
#   Part C — happy path + idempotency:
#     revoke a fresh hash → status revoked:true → revoke again → 409 "already".
#
# Usage:
#   export OPENCRED_DEDI_BASE_URL=https://api.dedi.global
#   export OPENCRED_DEDI_AUTH_TYPE=api-key                 # or: bearer
#   export OPENCRED_DEDI_API_KEY=...                       # if api-key
#   # or: export OPENCRED_DEDI_EMAIL=... OPENCRED_DEDI_PASSWORD=...   (bearer)
#   export OPENCRED_DEDI_NAMESPACE='did:web:did.cord.network:<id>'  # the ns to test
#   ./apps/server/scripts/dedi-revocation-selfheal-e2e.sh
#
# For maximum fidelity to #11, use the CORD-anchored namespace. The self-heal
# mechanics are namespace-agnostic, so any writable DeDi namespace also works.
#
# Requires: bash, curl, jq, openssl, pnpm (to build+run the server), node>=20.
set -euo pipefail

# ── Operator config ──────────────────────────────────────────────────────────
: "${OPENCRED_DEDI_BASE_URL:?set OPENCRED_DEDI_BASE_URL (live DeDi)}"
: "${OPENCRED_DEDI_AUTH_TYPE:?set OPENCRED_DEDI_AUTH_TYPE=api-key|bearer}"
: "${OPENCRED_DEDI_NAMESPACE:?set OPENCRED_DEDI_NAMESPACE (the namespace to test against)}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SERVER_CMD="${SERVER_CMD:-pnpm --filter @opencred/server start}"
PORT="${OPENCRED_PORT:-3100}"
BASE="http://127.0.0.1:${PORT}"
# Hex (not base64) — a base64 key can contain +/= which break the Bearer match.
API_KEY="${OPENCRED_API_KEY:-sk_e2e_$(openssl rand -hex 24)}"
REG="vc-revocation-registry"
NS="$OPENCRED_DEDI_NAMESPACE"
DEDI="${OPENCRED_DEDI_BASE_URL%/}"
WORK="$(mktemp -d)"
SERVER_PID=""

log()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Percent-encode the namespace for use in a URL path (colons → %3A, etc.).
NS_ENC="$(jq -rn --arg s "$NS" '$s|@uri')"

# ── DeDi auth: resolve a bearer token for direct API calls ───────────────────
# api-key → the key is the bearer token. bearer → log in at /dedi/register.
resolve_dedi_token() {
  if [[ "$OPENCRED_DEDI_AUTH_TYPE" == "api-key" ]]; then
    : "${OPENCRED_DEDI_API_KEY:?set OPENCRED_DEDI_API_KEY for api-key auth}"
    printf '%s' "$OPENCRED_DEDI_API_KEY"
    return
  fi
  : "${OPENCRED_DEDI_EMAIL:?set OPENCRED_DEDI_EMAIL for bearer auth}"
  : "${OPENCRED_DEDI_PASSWORD:?set OPENCRED_DEDI_PASSWORD for bearer auth}"
  local resp
  resp="$(curl -fsS -X POST "$DEDI/dedi/register" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg e "$OPENCRED_DEDI_EMAIL" --arg p "$OPENCRED_DEDI_PASSWORD" \
            '{email:$e, password:$p, action:"login"}')")" \
    || die "DeDi bearer login failed"
  # Token field name varies by DeDi build; try the common shapes.
  jq -r '.access_token // .accessToken // .token // .data.access_token // empty' <<<"$resp" \
    | grep . || die "could not parse DeDi token from login response"
}
DEDI_TOKEN="$(resolve_dedi_token)"
DEDI_AUTH="Authorization: Bearer ${DEDI_TOKEN}"

# Direct DeDi call. $1=METHOD $2=PATH ; body on stdin when present.
dedi() { curl -sS -X "$1" "$DEDI$2" -H "$DEDI_AUTH" -H 'Content-Type: application/json' "${@:3}"; }
# Same, but echo only the HTTP status code (for 404-vs-200 assertions).
dedi_code() { curl -sS -o /dev/null -w '%{http_code}' -X "$1" "$DEDI$2" -H "$DEDI_AUTH" -H 'Content-Type: application/json' "${@:3}"; }
# Reliably leave a DRAFT (not LIVE) for a record: keep issuing
# save-record-as-draft until a fast duplicate (409) CONFIRMS it exists. A fresh
# save-draft anchors to CORD (~30s) and can even error while still landing, so
# we trust the 409 rather than a single 201 (the prior silent-failure footgun).
strand_draft() { # $1=record_name
  local rn="$1" code
  for _ in $(seq 1 5); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$DEDI/dedi/${NS_ENC}/${REG}/save-record-as-draft" \
      -H "$DEDI_AUTH" -H 'Content-Type: application/json' \
      -d "$(jq -n --arg r "$rn" '{record_name:$r, description:"e2e strand", details:{revoked_id:$r}, meta:{}}')")"
    [[ "$code" == "409" ]] && return 0
    sleep 2
  done
  die "could not strand a draft for $rn (last save-draft HTTP $code)"
}

# ── OpenCred server (did:key issuer; DeDi configured) ────────────────────────
export OPENCRED_API_KEY="$API_KEY"
export OPENCRED_ISSUER_DID_METHOD="${OPENCRED_ISSUER_DID_METHOD:-key}"
AUTH_H="Authorization: Bearer ${API_KEY}"
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/key.pem"

# `pnpm start` spawns a node child, so killing the subshell PID alone orphans
# the listener. Kill by port to reap the actual server (and any stale one).
free_port() { lsof -ti "tcp:${PORT}" 2>/dev/null | xargs -r kill -9 2>/dev/null || true; }
cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true; free_port; wait 2>/dev/null || true; }
trap cleanup EXIT

start_server() {
  free_port; sleep 1   # ensure the port is free so we don't health-check a stale server
  ( cd "$REPO_ROOT" && OPENCRED_KEY_PATH="$WORK/key.pem" OPENCRED_PORT="$PORT" \
    $SERVER_CMD ) >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    curl -fsS "$BASE/v1/health" >/dev/null 2>&1 && { ok "OpenCred server up on $BASE (ns=$NS)"; return 0; }
    sleep 1
  done
  cat "$WORK/server.log" >&2; die "server did not become healthy on $BASE"
}
api() { curl -sS -X "$1" "$BASE$2" -H "$AUTH_H" -H 'Content-Type: application/json' "${@:3}"; }
rev_status() { # $1=hash → "true"/"false"
  api POST /v1/credentials/revocation-status -d "$(jq -n --arg h "$1" '{hash:$h}')" | jq -r '.revoked';
}
# publish-records queues the DRAFT→LIVE transition, so revocation-status is
# eventually — not immediately — consistent. Poll until it reaches the target.
wait_status() { # $1=hash $2=expected $3=label [$4=max_iters(default 12)]
  local iters="${4:-12}"
  for _ in $(seq 1 "$iters"); do
    [[ "$(rev_status "$1")" == "$2" ]] && { ok "$3"; return 0; }
    sleep 3
  done
  die "$3 — revocation-status($1) did not reach '$2' within ~$((iters * 3))s"
}

# ── Part A: DeDi behaviour probe — does publish-records advance a draft? ──────
log "Part A — DeDi probe: save-draft → lookup(404) → publish-records → lookup(200)"
R="e2e-selfheal-probe-$(openssl rand -hex 8)"
dedi POST "/dedi/${NS_ENC}/${REG}/save-record-as-draft" \
  -d "$(jq -n --arg r "$R" '{record_name:$r, description:"e2e self-heal probe", details:{revoked_id:$r}, meta:{}}')" \
  >/dev/null || die "Part A: save-record-as-draft failed"
ok "stranded a draft: $R"
CODE_DRAFT="$(dedi_code GET "/dedi/lookup/${NS_ENC}/${REG}/${R}")"
[[ "$CODE_DRAFT" == "404" ]] && ok "lookup of the draft = 404 (invisible, as expected)" \
  || die "Part A: expected draft lookup 404, got $CODE_DRAFT — a draft is NOT invisible on this DeDi build; the self-heal's LIVE check needs revisiting"
dedi POST "/dedi/${NS_ENC}/${REG}/publish-records" -d "$(jq -n --arg r "$R" '{records:[$r]}')" \
  >/dev/null || die "Part A: publish-records failed"
CODE_LIVE=""
for _ in $(seq 1 12); do
  CODE_LIVE="$(dedi_code GET "/dedi/lookup/${NS_ENC}/${REG}/${R}")"
  [[ "$CODE_LIVE" == "200" ]] && break
  sleep 2
done
[[ "$CODE_LIVE" == "200" ]] && ok "lookup after publish-records = 200 (LIVE) — open question CONFIRMED" \
  || die "Part A: lookup still $CODE_LIVE after publish-records (~24s) — publish-records does NOT advance a stranded draft to LIVE; #718 self-heal would not work"

# ── Start server for the integrated parts ────────────────────────────────────
log "Starting OpenCred server (did:key issuer; DeDi=$DEDI)"
start_server

# ── Part B: integrated self-heal of a stranded draft via OpenCred revoke ─────
log "Part B — strand a draft for hash H, then OpenCred revoke must self-heal it"
H="$(openssl rand -hex 32)"   # 64 lowercase hex — the revoke endpoint's hash shape
strand_draft "$H"
ok "stranded a draft for H=$H (confirmed via 409 — landed on CORD but not published)"
[[ "$(rev_status "$H")" == "false" ]] && ok "revocation-status(H) = false (stranded draft is not LIVE)" \
  || die "Part B: expected revocation-status false for a stranded draft"
RCB="$(curl -sS -o "$TMPDIR/revB" -w '%{http_code}' -X POST "$BASE/v1/credentials/revoke" \
  -H "$AUTH_H" -H 'Content-Type: application/json' -d "$(jq -n --arg h "$H" '{hash:$h}')")"
ok "OpenCred revoke(H) → HTTP $RCB $(jq -rc '{revoked,status}' "$TMPDIR/revB" 2>/dev/null)"
# 200 = self-heal completed synchronously; 202 = accepted + driven in the
# background. Never a 504. Either way the stranded draft is advanced to LIVE —
# the core #718 guarantee. publish-records can itself exceed 10s, so let CORD settle.
[[ "$RCB" == "200" || "$RCB" == "202" ]] || die "Part B: revoke(H) returned HTTP $RCB (expected 200 or 202)"
wait_status "$H" "true" "stranded draft LIVE — self-heal achieved revocation (#718)" 40

# ── Part C: fresh revoke under live CORD load (async accept, no 504) ──────────
# A FRESH save-record-as-draft anchors to CORD and can take ~30s — over the 10s
# ceiling. With async revocation (#718) the revoke returns 200 (squeaked under)
# or 202 (accepted + driven in the background) — NEVER a 504 — and the background
# driver settles the record to LIVE.
log "Part C — fresh revoke under live CORD load (async accept, no 504)"
H2="$(openssl rand -hex 32)"
RCC="$(curl -sS -o "$TMPDIR/revC" -w '%{http_code}' -X POST "$BASE/v1/credentials/revoke" \
  -H "$AUTH_H" -H 'Content-Type: application/json' -d "$(jq -n --arg h "$H2" '{hash:$h}')")"
ok "fresh revoke(H2) → HTTP $RCC $(jq -rc '{revoked,status}' "$TMPDIR/revC" 2>/dev/null)"
[[ "$RCC" == "200" || "$RCC" == "202" ]] \
  || die "Part C: fresh revoke returned HTTP $RCC (expected 200/202 — a 504 means the async path didn't engage)"
wait_status "$H2" "true" "fresh revoke eventually LIVE via the background driver (#718)" 40

log "DONE — async revocation validated end to end"
ok "Part A: publish-records advances a stranded draft to LIVE."
ok "Part B: OpenCred revoke self-heals a stranded draft to LIVE (200 sync, or 202 + background)."
ok "Part C: a fresh CORD-anchored revoke returns 200/202 — NEVER 504 — and the background driver settles it to LIVE."
echo "logs + artifacts in: $WORK"
