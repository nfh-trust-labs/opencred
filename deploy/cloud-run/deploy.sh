#\!/usr/bin/env bash
# ==============================================================================
# OpenCred — GCP Cloud Run Deployment Script
# ==============================================================================
# Deploys the OpenCred API to Cloud Run and optionally sets up
# Web UI via Cloud Run (nginx image) or Cloud Storage + CDN.
#
# Prerequisites:
#   - gcloud CLI authenticated (`gcloud auth login`)
#   - Docker images pushed to a registry (GHCR or Artifact Registry)
#   - Secrets created in GCP Secret Manager (see --setup-secrets)
#
# Usage:
#   ./deploy.sh                  # Deploy API only
#   ./deploy.sh --with-web       # Deploy API + Web UI
#   ./deploy.sh --web-only       # Deploy Web UI only
#   ./deploy.sh --dry-run        # Print commands without executing
# ==============================================================================

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Configuration — edit these for your environment
# ──────────────────────────────────────────────────────────────────────────────
GCP_PROJECT="${GCP_PROJECT:-opencred-prod}"
GCP_REGION="${GCP_REGION:-us-central1}"
API_SERVICE_NAME="${API_SERVICE_NAME:-opencred-api}"
WEB_SERVICE_NAME="${WEB_SERVICE_NAME:-opencred-web}"

# Container image references (override via env or edit defaults)
# These default to GHCR; switch to Artifact Registry if using GCP-native registry
API_IMAGE="${API_IMAGE:-ghcr.io/nfh-trust-labs/opencred/opencred-api:latest}"
WEB_IMAGE="${WEB_IMAGE:-ghcr.io/nfh-trust-labs/opencred/opencred-web:latest}"

# Resource limits
API_MEMORY="${API_MEMORY:-512Mi}"
API_CPU="${API_CPU:-1}"
API_MIN_INSTANCES="${API_MIN_INSTANCES:-0}"
API_MAX_INSTANCES="${API_MAX_INSTANCES:-10}"
API_CONCURRENCY="${API_CONCURRENCY:-80}"
API_TIMEOUT="${API_TIMEOUT:-300}"

WEB_MEMORY="${WEB_MEMORY:-256Mi}"
WEB_CPU="${WEB_CPU:-1}"
WEB_MIN_INSTANCES="${WEB_MIN_INSTANCES:-0}"
WEB_MAX_INSTANCES="${WEB_MAX_INSTANCES:-5}"

# VPC connector for private networking (optional — leave empty to skip)
VPC_CONNECTOR="${VPC_CONNECTOR:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Secret Manager mappings
# Format: ENV_VAR=secret-name:version
# These secrets must exist in GCP Secret Manager before deployment.
# ──────────────────────────────────────────────────────────────────────────────
API_SECRETS=(
  "JWT_SECRET=opencred-jwt-secret:latest"
  "DEDI_API_URL=opencred-dedi-api-url:latest"
)

# ──────────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────────
DRY_RUN=false

log() {
  echo "[opencred-deploy] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

error() {
  echo "[opencred-deploy] ERROR: $*" >&2
  exit 1
}

run_cmd() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY RUN] $*"
  else
    log "Running: $*"
    "$@"
  fi
}

check_prerequisites() {
  command -v gcloud >/dev/null 2>&1 || error "gcloud CLI not found. Install: https://cloud.google.com/sdk/docs/install"

  # Verify authentication
  if \! gcloud auth print-identity-token >/dev/null 2>&1; then
    error "Not authenticated with gcloud. Run: gcloud auth login"
  fi

  # Verify project access
  if \! gcloud projects describe "${GCP_PROJECT}" >/dev/null 2>&1; then
    error "Cannot access GCP project '${GCP_PROJECT}'. Check project ID and permissions."
  fi

  log "Prerequisites OK — project=${GCP_PROJECT}, region=${GCP_REGION}"
}

# ──────────────────────────────────────────────────────────────────────────────
# Build Secret Manager flags for gcloud run deploy
# ──────────────────────────────────────────────────────────────────────────────
build_secrets_flags() {
  local flags=""
  for mapping in "${API_SECRETS[@]}"; do
    if [[ -n "${flags}" ]]; then
      flags="${flags},"
    fi
    flags="${flags}${mapping}"
  done
  echo "${flags}"
}

# ──────────────────────────────────────────────────────────────────────────────
# Deploy API to Cloud Run
# ──────────────────────────────────────────────────────────────────────────────
deploy_api() {
  log "Deploying API service: ${API_SERVICE_NAME}"

  local secrets_flag
  secrets_flag="$(build_secrets_flags)"

  local cmd=(
    gcloud run deploy "${API_SERVICE_NAME}"
    --project "${GCP_PROJECT}"
    --region "${GCP_REGION}"
    --image "${API_IMAGE}"
    --platform managed
    --port 3000
    --memory "${API_MEMORY}"
    --cpu "${API_CPU}"
    --min-instances "${API_MIN_INSTANCES}"
    --max-instances "${API_MAX_INSTANCES}"
    --concurrency "${API_CONCURRENCY}"
    --timeout "${API_TIMEOUT}"
    --set-env-vars "NODE_ENV=production,LOG_LEVEL=info,CORS_ORIGIN=${CORS_ORIGIN:-*}"
    --set-secrets "${secrets_flag}"
    --no-allow-unauthenticated
  )

  # Add VPC connector if configured
  if [[ -n "${VPC_CONNECTOR}" ]]; then
    cmd+=(--vpc-connector "${VPC_CONNECTOR}" --vpc-egress all-traffic)
  fi

  run_cmd "${cmd[@]}"

  if [[ "${DRY_RUN}" \!= "true" ]]; then
    local api_url
    api_url=$(gcloud run services describe "${API_SERVICE_NAME}" \
      --project "${GCP_PROJECT}" \
      --region "${GCP_REGION}" \
      --format "value(status.url)")
    log "API deployed at: ${api_url}"
    log "Health check: curl -H 'Authorization: Bearer <token>' ${api_url}/health"
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Deploy Web UI to Cloud Run
# ──────────────────────────────────────────────────────────────────────────────
deploy_web() {
  log "Deploying Web UI service: ${WEB_SERVICE_NAME}"

  local cmd=(
    gcloud run deploy "${WEB_SERVICE_NAME}"
    --project "${GCP_PROJECT}"
    --region "${GCP_REGION}"
    --image "${WEB_IMAGE}"
    --platform managed
    --port 80
    --memory "${WEB_MEMORY}"
    --cpu "${WEB_CPU}"
    --min-instances "${WEB_MIN_INSTANCES}"
    --max-instances "${WEB_MAX_INSTANCES}"
    --allow-unauthenticated
  )

  run_cmd "${cmd[@]}"

  if [[ "${DRY_RUN}" \!= "true" ]]; then
    local web_url
    web_url=$(gcloud run services describe "${WEB_SERVICE_NAME}" \
      --project "${GCP_PROJECT}" \
      --region "${GCP_REGION}" \
      --format "value(status.url)")
    log "Web UI deployed at: ${web_url}"

    log ""
    log "NOTE: Update CORS_ORIGIN on the API service to allow requests from the Web UI:"
    log "  gcloud run services update ${API_SERVICE_NAME} \\"
    log "    --project ${GCP_PROJECT} --region ${GCP_REGION} \\"
    log "    --set-env-vars CORS_ORIGIN=${web_url}"
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Cloud Storage + CDN option (documented, not automated)
# ──────────────────────────────────────────────────────────────────────────────
print_storage_cdn_instructions() {
  cat <<'INSTRUCTIONS'

# ──────────────────────────────────────────────────────────────────────────────
# Alternative: Deploy Web UI to Cloud Storage + Cloud CDN
# ──────────────────────────────────────────────────────────────────────────────
# This option serves the SPA from a GCS bucket with Cloud CDN for caching.
# Better for high-traffic scenarios with aggressive caching.
#
# 1. Build the Web UI locally:
#    pnpm --filter @opencred/web run build
#
# 2. Create a GCS bucket (one-time):
#    gsutil mb -p PROJECT_ID -l REGION gs://BUCKET_NAME
#    gsutil web set -m index.html -e index.html gs://BUCKET_NAME
#    gsutil iam ch allUsers:objectViewer gs://BUCKET_NAME
#
# 3. Upload built files:
#    gsutil -m rsync -r -d apps/web/dist gs://BUCKET_NAME
#
# 4. Set up Cloud CDN (one-time):
#    gcloud compute backend-buckets create opencred-web-backend \
#      --gcs-bucket-name=BUCKET_NAME --enable-cdn
#    gcloud compute url-maps create opencred-web-lb \
#      --default-backend-bucket=opencred-web-backend
#    gcloud compute target-http-proxies create opencred-web-proxy \
#      --url-map=opencred-web-lb
#    gcloud compute forwarding-rules create opencred-web-fwd \
#      --target-http-proxy=opencred-web-proxy --ports=80 --global
#
# 5. For HTTPS, add a managed SSL certificate:
#    gcloud compute ssl-certificates create opencred-web-cert \
#      --domains=app.opencred.example.com --global
#    gcloud compute target-https-proxies create opencred-web-https-proxy \
#      --url-map=opencred-web-lb --ssl-certificates=opencred-web-cert
# ──────────────────────────────────────────────────────────────────────────────
INSTRUCTIONS
}

# ──────────────────────────────────────────────────────────────────────────────
# Verify deployment health
# ──────────────────────────────────────────────────────────────────────────────
verify_health() {
  local service="${1}"
  local endpoint="${2:-/}"

  log "Verifying health for ${service}..."

  local url
  url=$(gcloud run services describe "${service}" \
    --project "${GCP_PROJECT}" \
    --region "${GCP_REGION}" \
    --format "value(status.url)" 2>/dev/null) || error "Service ${service} not found"

  local token
  token=$(gcloud auth print-identity-token 2>/dev/null) || error "Cannot get identity token"

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${token}" \
    "${url}${endpoint}" 2>/dev/null) || true

  if [[ "${http_code}" == "200" ]]; then
    log "Health check PASSED for ${service} (HTTP ${http_code})"
  else
    log "Health check FAILED for ${service} (HTTP ${http_code})"
    log "URL: ${url}${endpoint}"
    return 1
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Create Secret Manager secrets (one-time setup helper)
# ──────────────────────────────────────────────────────────────────────────────
setup_secrets() {
  log "Setting up Secret Manager secrets..."
  log "This is a one-time setup. You will be prompted for secret values."

  local secret_names=(
    "opencred-jwt-secret"
    "opencred-dedi-api-url"
  )

  for secret_name in "${secret_names[@]}"; do
    if gcloud secrets describe "${secret_name}" --project "${GCP_PROJECT}" >/dev/null 2>&1; then
      log "Secret '${secret_name}' already exists — skipping"
    else
      log "Creating secret: ${secret_name}"
      run_cmd gcloud secrets create "${secret_name}" \
        --project "${GCP_PROJECT}" \
        --replication-policy automatic

      echo -n "Enter value for ${secret_name}: "
      read -rs secret_value
      echo ""

      echo -n "${secret_value}" | run_cmd gcloud secrets versions add "${secret_name}" \
        --project "${GCP_PROJECT}" \
        --data-file=-
    fi
  done

  # Grant Cloud Run service account access to secrets
  local sa
  sa="${GCP_PROJECT_NUMBER:-$(gcloud projects describe "${GCP_PROJECT}" --format='value(projectNumber)')}"
  sa="${sa}-compute@developer.gserviceaccount.com"

  for secret_name in "${secret_names[@]}"; do
    run_cmd gcloud secrets add-iam-policy-binding "${secret_name}" \
      --project "${GCP_PROJECT}" \
      --member "serviceAccount:${sa}" \
      --role "roles/secretmanager.secretAccessor" \
      --quiet
  done

  log "Secret Manager setup complete"
}

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
main() {
  local deploy_api_flag=false
  local deploy_web_flag=false
  local show_storage_instructions=false
  local verify_flag=false
  local setup_secrets_flag=false

  # Default: deploy API only
  if [[ $# -eq 0 ]]; then
    deploy_api_flag=true
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --with-web)
        deploy_api_flag=true
        deploy_web_flag=true
        shift
        ;;
      --web-only)
        deploy_web_flag=true
        shift
        ;;
      --api-only)
        deploy_api_flag=true
        shift
        ;;
      --storage-cdn)
        show_storage_instructions=true
        shift
        ;;
      --verify)
        verify_flag=true
        shift
        ;;
      --setup-secrets)
        setup_secrets_flag=true
        shift
        ;;
      --dry-run)
        DRY_RUN=true
        log "Dry-run mode enabled — no changes will be made"
        shift
        ;;
      --help|-h)
        cat <<HELP
Usage: $(basename "$0") [OPTIONS]

Options:
  --api-only          Deploy API service only (default)
  --web-only          Deploy Web UI service only
  --with-web          Deploy both API and Web UI
  --storage-cdn       Print Cloud Storage + CDN setup instructions
  --setup-secrets     Create Secret Manager secrets (one-time setup)
  --verify            Verify deployment health after deploy
  --dry-run           Print commands without executing
  --help, -h          Show this help

Environment variables:
  GCP_PROJECT         GCP project ID (default: opencred-prod)
  GCP_REGION          GCP region (default: us-central1)
  API_IMAGE           API container image reference
  WEB_IMAGE           Web UI container image reference
  API_SERVICE_NAME    Cloud Run API service name (default: opencred-api)
  WEB_SERVICE_NAME    Cloud Run Web service name (default: opencred-web)
  CORS_ORIGIN         Allowed CORS origin for API (default: *)
  VPC_CONNECTOR       VPC connector name for private networking (optional)
HELP
        exit 0
        ;;
      *)
        error "Unknown option: $1 (use --help for usage)"
        ;;
    esac
  done

  check_prerequisites

  if [[ "${setup_secrets_flag}" == "true" ]]; then
    setup_secrets
  fi

  if [[ "${show_storage_instructions}" == "true" ]]; then
    print_storage_cdn_instructions
    exit 0
  fi

  if [[ "${deploy_api_flag}" == "true" ]]; then
    deploy_api
  fi

  if [[ "${deploy_web_flag}" == "true" ]]; then
    deploy_web
  fi

  if [[ "${verify_flag}" == "true" ]]; then
    if [[ "${deploy_api_flag}" == "true" ]]; then
      verify_health "${API_SERVICE_NAME}" "/health"
    fi
    if [[ "${deploy_web_flag}" == "true" ]]; then
      verify_health "${WEB_SERVICE_NAME}" "/"
    fi
  fi

  log "Deployment complete"
}

main "$@"
