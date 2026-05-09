#!/usr/bin/env bash
#
# local-mac-release.sh — produce signed + notarised Mac release artefacts
# locally and upload them to an existing GitHub release.
#
# Use this when GitHub Actions is blocked (billing freeze, org Actions
# disabled, etc.). Mirrors the hardened .github/workflows/desktop-release.yml
# so the outputs should be bit-for-bit equivalent (modulo timestamps).
#
# Pipeline:
#   1. Preflight: required tooling, Apple Developer ID cert, notary creds,
#      gh auth, target git tag, target GitHub release all present.
#   2. Build workspace dependencies.
#   3. Rebuild native addons for Electron ABI and verify they exist.
#   4. Build renderer (vite) and main process (esbuild).
#   5. prepare-native-deps.cjs — materialise pnpm symlinks, strip workspace
#      deps so electron-builder asar is clean.
#   6. electron-builder --mac --x64 --arm64 --publish never — signs and
#      notarises via the afterSign hook.
#   7. Verify every .app with codesign --deep --strict, spctl --assess,
#      and xcrun stapler validate. Exit non-zero on any failure.
#   8. Upload .dmg/.zip/.blockmap/latest*.yml to the GitHub release via
#      `gh release upload --clobber`.
#
# Usage:
#   scripts/local-mac-release.sh <tag>
#
#     tag: an existing git tag AND GitHub release, e.g. v1.0.1.
#
# Environment (required unless marked optional):
#   APPLE_ID                     Apple Developer account email.
#   APPLE_TEAM_ID                Apple Developer Team ID (10-char).
#   APPLE_APP_SPECIFIC_PASSWORD  App-specific password for the Apple ID.
#       (APPLE_ID_PASSWORD is accepted as legacy alias.)
#   CSC_LINK                     Optional. Path to a .p12 file OR base64
#                                encoded p12. If omitted, a Developer ID
#                                cert must already exist in the login
#                                keychain.
#   CSC_KEY_PASSWORD             Password for the p12 referenced by
#                                CSC_LINK. Required iff CSC_LINK is set.
#
#   GH_REPO                      Optional. Defaults to nfh-trust-labs/opencred.
#   DRY_RUN                      Optional. If "1", build + verify but skip
#                                upload. Useful for smoke-testing.
#   SKIP_VERIFY                  Optional. If "1", skip signature
#                                verification (dangerous — for debugging
#                                only).

set -euo pipefail

readonly SCRIPT_DIR="$( cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd )"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly GH_REPO_DEFAULT="nfh-trust-labs/opencred"
readonly GH_REPO="${GH_REPO:-$GH_REPO_DEFAULT}"

log()  { printf '\033[1;34m[release]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[release]\033[0m WARN: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[release]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }

main() {
  local tag="${1:-}"
  [[ -z "$tag" ]] && die "usage: $0 <tag>   (e.g. v1.0.1)"

  cd "$REPO_ROOT"

  preflight "$tag"

  log "Installing deps (pnpm install --frozen-lockfile)"
  pnpm install --frozen-lockfile

  log "Building workspace dependencies"
  pnpm --filter @opencred/desktop... build

  log "Rebuilding native addons for Electron"
  pnpm --filter @opencred/desktop rebuild:native

  log "Verifying native addons"
  ( cd packages/signing && node scripts/verify-native-addons.cjs )

  log "Building renderer"
  pnpm --filter @opencred/desktop build:renderer

  log "Building main process"
  pnpm --filter @opencred/desktop build:main

  log "Preparing native dependencies (mutates apps/desktop/package.json)"
  ( cd apps/desktop && node scripts/prepare-native-deps.cjs )

  mkdir -p apps/desktop/out/@opencred

  log "Running electron-builder (--mac --x64 --arm64 --publish never)"
  ( cd apps/desktop && npx electron-builder --mac --x64 --arm64 --publish never )

  if [[ "${SKIP_VERIFY:-0}" != "1" ]]; then
    verify_signatures
  else
    warn "SKIP_VERIFY=1 — signature verification skipped"
  fi

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "DRY_RUN=1 — skipping upload. Artefacts left in apps/desktop/out/"
    exit 0
  fi

  upload "$tag"
  log "Done. Release $tag now has signed + notarised Mac artefacts."
}

preflight() {
  local tag="$1"

  log "Preflight: tooling"
  for tool in pnpm node npx gh xcrun codesign spctl security git; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
  done

  log "Preflight: macOS"
  [[ "$(uname -s)" == "Darwin" ]] || die "must run on macOS"

  log "Preflight: signing identity"
  if [[ -z "${CSC_LINK:-}" ]]; then
    if ! security find-identity -v -p codesigning 2>/dev/null \
        | grep -q "Developer ID Application"; then
      die "No 'Developer ID Application' identity in the login keychain, \
and CSC_LINK not set. Import your cert via Keychain Access or export \
CSC_LINK=/path/to/cert.p12 and CSC_KEY_PASSWORD=<password>."
    fi
    log "  -> using identity from login keychain"
  else
    [[ -n "${CSC_KEY_PASSWORD:-}" ]] || \
      die "CSC_LINK is set but CSC_KEY_PASSWORD is not. Both are required."
    log "  -> using CSC_LINK (electron-builder will import at build time)"
  fi

  log "Preflight: notary credentials"
  [[ -n "${APPLE_ID:-}" ]]      || die "APPLE_ID is not set"
  [[ -n "${APPLE_TEAM_ID:-}" ]] || die "APPLE_TEAM_ID is not set"
  if [[ -z "${APPLE_APP_SPECIFIC_PASSWORD:-}${APPLE_ID_PASSWORD:-}" ]]; then
    die "APPLE_APP_SPECIFIC_PASSWORD (or APPLE_ID_PASSWORD) is not set"
  fi

  log "Preflight: gh authentication"
  gh auth status >/dev/null 2>&1 \
    || die "gh CLI is not authenticated. Run: gh auth login"

  log "Preflight: git tag $tag exists locally"
  if ! git rev-parse "refs/tags/$tag" >/dev/null 2>&1; then
    warn "tag $tag not found locally, fetching..."
    git fetch --tags origin
    git rev-parse "refs/tags/$tag" >/dev/null 2>&1 \
      || die "tag $tag not found on origin either"
  fi

  log "Preflight: current working tree matches $tag"
  local head_sha tag_sha
  head_sha="$(git rev-parse HEAD)"
  tag_sha="$(git rev-parse "refs/tags/$tag^{commit}")"
  if [[ "$head_sha" != "$tag_sha" ]]; then
    die "HEAD ($head_sha) does not match tag $tag ($tag_sha). \
Check out the tag first: git checkout $tag"
  fi

  if ! git diff --quiet --ignore-submodules HEAD 2>/dev/null; then
    warn "working tree has uncommitted changes — build may diverge from tag"
  fi

  log "Preflight: GitHub release $tag exists"
  gh release view "$tag" --repo "$GH_REPO" >/dev/null 2>&1 \
    || die "GitHub release $tag does not exist in $GH_REPO"

  log "Preflight OK"
}

verify_signatures() {
  log "Verifying signatures"
  local fail=0 checked=0
  shopt -s nullglob
  for app_parent in apps/desktop/out/mac apps/desktop/out/mac-arm64; do
    [[ -d "$app_parent" ]] || continue
    for app in "$app_parent"/*.app; do
      checked=$((checked + 1))
      log "  codesign --verify --deep --strict: $app"
      codesign --verify --deep --strict --verbose=2 "$app" || fail=1
      log "  spctl --assess --type execute: $app"
      spctl --assess --type execute --verbose=2 "$app" || fail=1
      log "  xcrun stapler validate: $app"
      xcrun stapler validate "$app" || fail=1
    done
  done
  [[ "$checked" -eq 0 ]] && die "no .app bundles found to verify"
  [[ "$fail" -ne 0 ]] && die "signature/notarisation verification failed"
  log "All $checked bundles verified"
}

upload() {
  local tag="$1"
  log "Collecting artefacts"
  local -a files=()
  shopt -s nullglob
  for f in apps/desktop/out/*.dmg \
           apps/desktop/out/*.zip \
           apps/desktop/out/*.blockmap \
           apps/desktop/out/latest*.yml; do
    [[ -f "$f" ]] && files+=("$f")
  done
  [[ ${#files[@]} -eq 0 ]] && die "no upload candidates in apps/desktop/out/"

  log "Uploading ${#files[@]} files to release $tag in $GH_REPO"
  gh release upload "$tag" "${files[@]}" --clobber --repo "$GH_REPO"
}

main "$@"
