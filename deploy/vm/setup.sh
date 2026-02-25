#\!/usr/bin/env bash
# ==============================================================================
# OpenCred — VM Setup Script
# ==============================================================================
# Sets up a fresh Linux VM (Debian/Ubuntu) to run OpenCred via Docker Compose
# managed by systemd.
#
# What this script does:
#   1. Installs Docker Engine and Docker Compose plugin
#   2. Creates an 'opencred' system user and /opt/opencred directory
#   3. Copies Docker Compose configuration files
#   4. Installs the systemd service unit
#   5. Configures Docker log rotation
#   6. Pulls container images from the registry
#   7. Enables and starts the service
#
# Usage:
#   sudo ./setup.sh                     # Full setup
#   sudo ./setup.sh --skip-docker       # Skip Docker installation
#   sudo ./setup.sh --registry URL      # Custom registry URL
#
# Prerequisites:
#   - Root or sudo access
#   - Debian/Ubuntu (apt-based) or RHEL/CentOS (dnf-based)
#   - Internet access (for Docker install and image pull)
# ==============================================================================

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
OPENCRED_USER="opencred"
OPENCRED_DIR="/opt/opencred"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SKIP_DOCKER=false
REGISTRY="${REGISTRY:-ghcr.io/nfh-trust-labs/opencred}"

# ──────────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────────
log() {
  echo "[opencred-setup] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

error() {
  echo "[opencred-setup] ERROR: $*" >&2
  exit 1
}

check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
  fi
}

detect_os() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "debian"
  elif command -v dnf >/dev/null 2>&1; then
    echo "rhel"
  else
    error "Unsupported OS. This script supports Debian/Ubuntu (apt) and RHEL/CentOS (dnf)."
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Install Docker Engine and Compose plugin
# ──────────────────────────────────────────────────────────────────────────────
install_docker() {
  if [[ "${SKIP_DOCKER}" == "true" ]]; then
    log "Skipping Docker installation (--skip-docker)"
    return
  fi

  if command -v docker >/dev/null 2>&1; then
    log "Docker already installed: $(docker --version)"
    # Ensure Compose plugin is available
    if docker compose version >/dev/null 2>&1; then
      log "Docker Compose plugin: $(docker compose version)"
      return
    fi
    log "Docker Compose plugin not found — installing..."
  fi

  local os_type
  os_type="$(detect_os)"

  case "${os_type}" in
    debian)
      log "Installing Docker on Debian/Ubuntu..."

      # Remove old versions
      apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

      # Install prerequisites
      apt-get update -y
      apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

      # Add Docker GPG key
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg

      # Add Docker repository
      local codename
      codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-${UBUNTU_CODENAME:-jammy}}")"
      echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null

      # Install Docker
      apt-get update -y
      apt-get install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin
      ;;

    rhel)
      log "Installing Docker on RHEL/CentOS..."

      # Remove old versions
      dnf remove -y docker docker-client docker-client-latest docker-common \
        docker-latest docker-latest-logrotate docker-logrotate docker-engine 2>/dev/null || true

      # Add Docker repository
      dnf install -y dnf-plugins-core
      dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

      # Install Docker
      dnf install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin
      ;;
  esac

  # Start and enable Docker
  systemctl enable docker
  systemctl start docker

  log "Docker installed: $(docker --version)"
  log "Docker Compose: $(docker compose version)"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Create opencred user and directory
# ──────────────────────────────────────────────────────────────────────────────
create_user_and_dirs() {
  log "Setting up user and directories..."

  # Create system user (no login shell, no home directory)
  if \! id "${OPENCRED_USER}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${OPENCRED_USER}"
    log "Created system user: ${OPENCRED_USER}"
  else
    log "User ${OPENCRED_USER} already exists"
  fi

  # Add opencred user to docker group
  usermod -aG docker "${OPENCRED_USER}"

  # Create application directory
  mkdir -p "${OPENCRED_DIR}"
  mkdir -p "${OPENCRED_DIR}/csca-trust-store"

  log "Created directory: ${OPENCRED_DIR}"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Copy Docker Compose files
# ──────────────────────────────────────────────────────────────────────────────
copy_compose_files() {
  log "Copying Docker Compose configuration..."

  # Copy compose file
  if [[ -f "${REPO_ROOT}/docker-compose.yml" ]]; then
    cp "${REPO_ROOT}/docker-compose.yml" "${OPENCRED_DIR}/docker-compose.yml"
    log "Copied docker-compose.yml"
  else
    error "docker-compose.yml not found at ${REPO_ROOT}/docker-compose.yml"
  fi

  # Create .env file if it doesn't exist
  if [[ \! -f "${OPENCRED_DIR}/.env" ]]; then
    cat > "${OPENCRED_DIR}/.env" << 'ENV_TEMPLATE'
# ==============================================================================
# OpenCred — Environment Configuration
# ==============================================================================
# Copy this file and fill in production values.
# See apps/api/env-reference.txt for all available variables.
# ==============================================================================

# ---------- Container Images ----------
# Override these to pull from your registry
# API_IMAGE=ghcr.io/nfh-trust-labs/opencred/opencred-api:latest
# WEB_IMAGE=ghcr.io/nfh-trust-labs/opencred/opencred-web:latest

# ---------- Port Mapping ----------
API_PORT=3000
WEB_PORT=8080

# ---------- Server ----------
NODE_ENV=production
PORT=3000
LOG_LEVEL=info

# ---------- CORS ----------
CORS_ORIGIN=https://your-domain.example.com

# ---------- Auth / JWT ----------
# Generate with: node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
JWT_SECRET=CHANGE_ME_GENERATE_A_SECURE_SECRET
JWT_ISSUER=opencred
JWT_EXPIRY_SECONDS=3600

# ---------- Session / State ----------
SESSION_TTL_MS=14400000
SESSION_SWEEP_INTERVAL_MS=60000

# ---------- DeDi Integration ----------
# DEDI_API_URL=https://dedi.example.com/api
DEDI_API_TIMEOUT_MS=10000

# ---------- Batch Processing ----------
MAX_BATCH_SIZE=1000

# ---------- CSCA Trust Store ----------
CSCA_TRUST_STORE_PATH=/app/csca-trust-store
ENV_TEMPLATE

    log "Created template .env file at ${OPENCRED_DIR}/.env"
    log "IMPORTANT: Edit ${OPENCRED_DIR}/.env with your production values before starting"
  else
    log ".env file already exists — not overwriting"
  fi

  # Set ownership
  chown -R "${OPENCRED_USER}:${OPENCRED_USER}" "${OPENCRED_DIR}"
  chmod 600 "${OPENCRED_DIR}/.env"

  log "Compose files ready at ${OPENCRED_DIR}"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Install systemd service
# ──────────────────────────────────────────────────────────────────────────────
install_service() {
  log "Installing systemd service..."

  local service_src="${SCRIPT_DIR}/opencred.service"
  local service_dest="/etc/systemd/system/opencred.service"

  if [[ \! -f "${service_src}" ]]; then
    error "Service file not found: ${service_src}"
  fi

  cp "${service_src}" "${service_dest}"
  chmod 644 "${service_dest}"

  systemctl daemon-reload
  systemctl enable opencred

  log "Systemd service installed and enabled"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 5: Configure Docker log rotation
# ──────────────────────────────────────────────────────────────────────────────
configure_log_rotation() {
  log "Configuring Docker log rotation..."

  local docker_daemon_config="/etc/docker/daemon.json"

  # Create or update daemon.json with log rotation settings
  if [[ -f "${docker_daemon_config}" ]]; then
    # If daemon.json exists, check if log-driver is already configured
    if grep -q "log-driver" "${docker_daemon_config}"; then
      log "Docker log driver already configured — skipping"
      return
    fi
    log "WARNING: ${docker_daemon_config} exists but has no log config. Adding manually may be needed."
    return
  fi

  mkdir -p /etc/docker
  cat > "${docker_daemon_config}" << 'DAEMON_JSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  }
}
DAEMON_JSON

  # Restart Docker to apply log configuration
  systemctl restart docker

  log "Docker log rotation configured (max-size: 10m, max-file: 5)"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 6: Pull container images
# ──────────────────────────────────────────────────────────────────────────────
pull_images() {
  log "Pulling container images from registry..."

  local api_image="${REGISTRY}/opencred-api:latest"
  local web_image="${REGISTRY}/opencred-web:latest"

  # If using GHCR, may need authentication
  if [[ "${REGISTRY}" == ghcr.io/* ]]; then
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      echo "${GITHUB_TOKEN}" | docker login ghcr.io -u _token --password-stdin
      log "Authenticated with GHCR"
    else
      log "WARNING: GITHUB_TOKEN not set. GHCR pull may fail for private repos."
      log "Set GITHUB_TOKEN env var or run: docker login ghcr.io"
    fi
  fi

  docker pull "${api_image}" || log "WARNING: Failed to pull ${api_image} — will use locally built image"
  docker pull "${web_image}" || log "WARNING: Failed to pull ${web_image} — will use locally built image"

  log "Image pull complete"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 7: Start the service
# ──────────────────────────────────────────────────────────────────────────────
start_service() {
  log "Starting OpenCred service..."

  systemctl start opencred

  # Wait for service to be active
  sleep 5

  if systemctl is-active --quiet opencred; then
    log "OpenCred service is running"
  else
    log "WARNING: Service may not have started correctly"
    log "Check logs with: journalctl -u opencred -n 50"
  fi

  systemctl status opencred --no-pager || true
}

# ──────────────────────────────────────────────────────────────────────────────
# Print post-setup instructions
# ──────────────────────────────────────────────────────────────────────────────
print_instructions() {
  cat << INSTRUCTIONS

# ==============================================================================
# OpenCred Setup Complete
# ==============================================================================
#
# NEXT STEPS:
#
# 1. Edit the environment file with your production values:
#    sudo nano ${OPENCRED_DIR}/.env
#
# 2. Place CSCA trust store PEM files:
#    sudo cp /path/to/csca/*.pem ${OPENCRED_DIR}/csca-trust-store/
#
# 3. Restart the service to apply changes:
#    sudo systemctl restart opencred
#
# 4. Set up TLS (see deploy/README.md for Caddy instructions):
#    sudo apt install caddy
#    # Configure reverse proxy on ports 3000 (API) and 8080 (Web)
#
# USEFUL COMMANDS:
#
#   sudo systemctl status opencred     # Service status
#   sudo systemctl restart opencred    # Restart
#   sudo systemctl stop opencred       # Stop
#   journalctl -u opencred -f          # Follow logs
#   journalctl -u opencred --since "1 hour ago"
#
#   docker compose -f ${OPENCRED_DIR}/docker-compose.yml ps
#   docker compose -f ${OPENCRED_DIR}/docker-compose.yml logs -f api
#
# ==============================================================================
INSTRUCTIONS
}

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-docker)
        SKIP_DOCKER=true
        shift
        ;;
      --registry)
        REGISTRY="${2}"
        shift 2
        ;;
      --help|-h)
        cat <<HELP
Usage: sudo $(basename "$0") [OPTIONS]

Options:
  --skip-docker       Skip Docker installation (if already installed)
  --registry URL      Container registry URL (default: ghcr.io/nfh-trust-labs/opencred)
  --help, -h          Show this help

Environment variables:
  GITHUB_TOKEN        Token for GHCR authentication (for private repos)
  REGISTRY            Container registry URL (alternative to --registry flag)
HELP
        exit 0
        ;;
      *)
        error "Unknown option: $1 (use --help for usage)"
        ;;
    esac
  done

  log "Starting OpenCred VM setup..."
  check_root

  install_docker
  create_user_and_dirs
  copy_compose_files
  install_service
  configure_log_rotation
  pull_images
  start_service
  print_instructions

  log "Setup complete"
}

main "$@"
