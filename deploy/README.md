# OpenCred — Deployment Guide

This guide covers deploying OpenCred to two supported environments:

1. **GCP Cloud Run** — Fully managed, serverless containers
2. **VM (Systemd)** — Docker Compose on a self-managed Linux VM

Both approaches use the same Docker images built by the CI pipeline (`.github/workflows/docker.yml`).

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [GCP Cloud Run Deployment](#gcp-cloud-run-deployment)
- [VM Deployment](#vm-deployment)
- [TLS Setup](#tls-setup)
- [Environment Variable Reference](#environment-variable-reference)
- [Backup and Recovery](#backup-and-recovery)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Container Images

Images are automatically built and pushed to GHCR on every merge to `anusree-dev`:

| Image | Description |
|---|---|
| `ghcr.io/nfh-trust-labs/opencred/opencred-api` | API server (Node.js) |
| `ghcr.io/nfh-trust-labs/opencred/opencred-web` | Web UI (Nginx + SPA) |

Tags follow the format: `YYYYMMDD-<sha>` (date + git commit SHA).

### Secrets

At minimum, you need:

| Secret | Description |
|---|---|
| `JWT_SECRET` | HMAC secret for capability tokens (min 32 chars). Generate with: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `DEDI_API_URL` | URL of the DeDi API (if using delegation/revocation features) |

> **Security note:** Never store secrets in version control, Docker images, or deployment scripts. Use Secret Manager (GCP) or `.env` files with restricted permissions (VM).

---

## GCP Cloud Run Deployment

Cloud Run provides managed TLS, auto-scaling, and zero-infrastructure overhead.

### Quick Start

```bash
# 1. One-time: set up secrets in Secret Manager
./deploy/cloud-run/deploy.sh --setup-secrets

# 2. Deploy the API
GCP_PROJECT=your-project-id \
API_IMAGE=ghcr.io/nfh-trust-labs/opencred/opencred-api:20260224-abc1234 \
  ./deploy/cloud-run/deploy.sh --verify

# 3. Deploy API + Web UI together
GCP_PROJECT=your-project-id \
  ./deploy/cloud-run/deploy.sh --with-web --verify
```

### Step-by-Step

#### 1. Configure GCP Project

```bash
# Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com
```

#### 2. Create Secrets in Secret Manager

```bash
# Interactive setup (creates secrets and grants IAM)
./deploy/cloud-run/deploy.sh --setup-secrets

# Or manually:
echo -n "your-jwt-secret-value" | \
  gcloud secrets create opencred-jwt-secret --data-file=-

echo -n "https://dedi.example.com/api" | \
  gcloud secrets create opencred-dedi-api-url --data-file=-
```

#### 3. Deploy

```bash
# API only (default)
GCP_PROJECT=opencred-prod \
GCP_REGION=us-central1 \
API_IMAGE=ghcr.io/nfh-trust-labs/opencred/opencred-api:latest \
  ./deploy/cloud-run/deploy.sh

# With Web UI
GCP_PROJECT=opencred-prod \
  ./deploy/cloud-run/deploy.sh --with-web

# Dry run (preview commands without executing)
./deploy/cloud-run/deploy.sh --dry-run --with-web
```

#### 4. Configure Ingress and Authentication

By default, the API is deployed with `--no-allow-unauthenticated`. To allow public access or configure IAP:

```bash
# Allow unauthenticated access (public API)
gcloud run services update opencred-api \
  --allow-unauthenticated \
  --project YOUR_PROJECT --region us-central1

# Or: set up Identity-Aware Proxy (IAP) for org-internal access
# See: https://cloud.google.com/iap/docs/enabling-cloud-run
```

#### 5. Verify

```bash
# Verify deployment health
./deploy/cloud-run/deploy.sh --verify

# Or manually:
API_URL=$(gcloud run services describe opencred-api \
  --region us-central1 --format 'value(status.url)')
curl -s "${API_URL}/health"
```

### Web UI: Cloud Storage + CDN Alternative

For high-traffic scenarios, serve the Web UI from Cloud Storage with Cloud CDN instead of Cloud Run:

```bash
# Print detailed instructions
./deploy/cloud-run/deploy.sh --storage-cdn
```

### Deployment Script Options

```
./deploy/cloud-run/deploy.sh [OPTIONS]

Options:
  --api-only          Deploy API service only (default)
  --web-only          Deploy Web UI service only
  --with-web          Deploy both API and Web UI
  --storage-cdn       Print Cloud Storage + CDN setup instructions
  --setup-secrets     Create Secret Manager secrets (one-time)
  --verify            Verify health after deploy
  --dry-run           Preview commands without executing
  --help              Show full help with env var reference
```

---

## VM Deployment

For organisations that require on-premises or self-managed infrastructure.

### Quick Start

```bash
# On a fresh Debian/Ubuntu VM:
sudo ./deploy/vm/setup.sh

# Edit environment file with production values
sudo nano /opt/opencred/.env

# Restart to apply
sudo systemctl restart opencred
```

### Step-by-Step

#### 1. Run Setup Script

The setup script handles everything: Docker install, user creation, service registration, and log rotation.

```bash
# Full setup (installs Docker, creates user, enables service)
sudo ./deploy/vm/setup.sh

# If Docker is already installed
sudo ./deploy/vm/setup.sh --skip-docker

# Custom registry
sudo ./deploy/vm/setup.sh --registry your-registry.example.com/opencred
```

#### 2. Configure Environment

```bash
# Edit the .env file with production values
sudo nano /opt/opencred/.env

# CRITICAL: Set a secure JWT_SECRET
# Generate one with:
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"

# Set CORS_ORIGIN to your domain
# Set DEDI_API_URL if using delegation features
```

#### 3. Add CSCA Trust Store (if needed)

```bash
# Copy CSCA root certificates
sudo cp /path/to/csca-certs/*.pem /opt/opencred/csca-trust-store/
sudo chown -R opencred:opencred /opt/opencred/csca-trust-store/
```

#### 4. Start the Service

```bash
sudo systemctl restart opencred
sudo systemctl status opencred
```

#### 5. Verify

```bash
# Check health
curl http://localhost:3000/health

# Check Web UI
curl -I http://localhost:8080/

# Follow logs
journalctl -u opencred -f
```

### Service Management

```bash
# Start / stop / restart
sudo systemctl start opencred
sudo systemctl stop opencred
sudo systemctl restart opencred

# Reload (pull latest images and restart)
sudo systemctl reload opencred

# Check status
sudo systemctl status opencred

# View logs
journalctl -u opencred -f                    # Follow logs
journalctl -u opencred --since "1 hour ago"  # Recent logs
journalctl -u opencred -p err                # Errors only

# Docker-level inspection
docker compose -f /opt/opencred/docker-compose.yml ps
docker compose -f /opt/opencred/docker-compose.yml logs -f api
```

### Updating to a New Version

```bash
# Pull latest images and restart
sudo systemctl reload opencred

# Or manually:
cd /opt/opencred
docker compose pull
docker compose up -d --remove-orphans
```

### What the Setup Script Does

| Step | Action |
|---|---|
| 1 | Installs Docker Engine and Compose plugin (Debian/Ubuntu or RHEL/CentOS) |
| 2 | Creates `opencred` system user (no login shell) and `/opt/opencred` directory |
| 3 | Copies `docker-compose.yml` and creates template `.env` |
| 4 | Installs and enables `opencred.service` systemd unit |
| 5 | Configures Docker log rotation (`json-file`, 10MB max, 5 files) |
| 6 | Pulls container images from registry |
| 7 | Starts the service |

---

## TLS Setup

### Cloud Run

TLS is **automatic** on Cloud Run. No additional setup needed. Cloud Run provisions and renews managed TLS certificates for your service URL (`*.run.app`).

For custom domains:

```bash
gcloud beta run domain-mappings create \
  --service opencred-api \
  --domain api.opencred.example.com \
  --region us-central1
```

### VM: Caddy with Let's Encrypt (Recommended)

[Caddy](https://caddyserver.com/) provides automatic TLS with Let's Encrypt and zero-configuration HTTPS.

#### Install Caddy

```bash
# Debian/Ubuntu
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

#### Configure Caddy

Create `/etc/caddy/Caddyfile`:

```
# OpenCred — Caddy Reverse Proxy
# TLS certificates are automatically provisioned via Let's Encrypt

api.opencred.example.com {
    reverse_proxy localhost:3000

    # Security headers
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }

    # Access logs
    log {
        output file /var/log/caddy/api-access.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}

app.opencred.example.com {
    reverse_proxy localhost:8080

    # Security headers
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }

    log {
        output file /var/log/caddy/web-access.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}
```

#### Start Caddy

```bash
sudo systemctl enable caddy
sudo systemctl start caddy

# Verify TLS
curl -v https://api.opencred.example.com/health
```

### VM: Org-Provided Certificates

If your organisation provides TLS certificates instead of using Let's Encrypt:

```
# Caddyfile with custom certificates
api.opencred.example.com {
    tls /etc/ssl/opencred/cert.pem /etc/ssl/opencred/key.pem
    reverse_proxy localhost:3000
}
```

---

## Environment Variable Reference

All variables are validated at API startup via Zod. The server refuses to start if required variables are missing or invalid.

| Variable | Required | Default | Description |
|---|---|---|---|
| `NODE_ENV` | Yes | `production` | Runtime environment |
| `PORT` | No | `3000` | API server port |
| `LOG_LEVEL` | No | `info` | Pino log level (`debug`, `info`, `warn`, `error`) |
| `CORS_ORIGIN` | Yes | — | Allowed CORS origin (Web UI URL) |
| `JWT_SECRET` | Yes | — | HMAC secret for tokens (min 32 chars, use CSPRNG) |
| `JWT_ISSUER` | No | `opencred` | JWT issuer claim |
| `JWT_EXPIRY_SECONDS` | No | `3600` | JWT token expiry |
| `SESSION_TTL_MS` | No | `14400000` | Session/credential payload TTL (4 hours) |
| `SESSION_SWEEP_INTERVAL_MS` | No | `60000` | Session cleanup interval |
| `DEDI_API_URL` | No | — | DeDi API URL (for delegation/revocation) |
| `DEDI_API_TIMEOUT_MS` | No | `10000` | DeDi API request timeout |
| `MAX_BATCH_SIZE` | No | `1000` | Maximum credentials per bulk issuance batch |
| `CSCA_TRUST_STORE_PATH` | No | — | Path to CSCA root certificate PEM directory |
| `API_PORT` | No | `3000` | Host port mapping for API (Docker Compose) |
| `WEB_PORT` | No | `8080` | Host port mapping for Web UI (Docker Compose) |

---

## Backup and Recovery

### What to Back Up

OpenCred is **ephemeral by design** — credential payloads and sessions are purged after TTL (default 4 hours). There is no persistent credential database.

| Item | Location | Frequency | Notes |
|---|---|---|---|
| **Environment file** | `/opt/opencred/.env` | On change | Contains JWT secret, API URLs |
| **CSCA trust store** | `/opt/opencred/csca-trust-store/` | On change | Root certificate PEM files |
| **Delegation signing keys** | Managed by OpenCred | Per rotation | Only for Delegated Signing mode |
| **Docker Compose config** | `/opt/opencred/docker-compose.yml` | On change | Service orchestration config |

### Backup Commands (VM)

```bash
# Create a backup archive
BACKUP_DIR="/var/backups/opencred"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

sudo mkdir -p "${BACKUP_DIR}"
sudo tar -czf "${BACKUP_DIR}/opencred-${TIMESTAMP}.tar.gz" \
  --exclude='*.log' \
  /opt/opencred/.env \
  /opt/opencred/csca-trust-store/ \
  /opt/opencred/docker-compose.yml

# List backups
ls -la "${BACKUP_DIR}"
```

### Recovery (VM)

```bash
# 1. Run setup on a fresh VM
sudo ./deploy/vm/setup.sh

# 2. Restore backup
sudo tar -xzf /var/backups/opencred/opencred-20260224-120000.tar.gz -C /

# 3. Pull images and start
sudo systemctl restart opencred

# 4. Verify
curl http://localhost:3000/health
```

### Recovery (Cloud Run)

Cloud Run services are stateless. To recover:

1. Re-deploy from the container registry (images are immutable)
2. Secrets are in Secret Manager (already persisted)
3. No data restoration needed

```bash
# Re-deploy from last known good image
API_IMAGE=ghcr.io/nfh-trust-labs/opencred/opencred-api:20260224-abc1234 \
  ./deploy/cloud-run/deploy.sh --verify
```

---

## Troubleshooting

### Cloud Run

| Issue | Solution |
|---|---|
| Service returns 403 | Check IAM — service may need `--allow-unauthenticated` or IAP config |
| Secrets not loading | Verify Secret Manager IAM binding: `roles/secretmanager.secretAccessor` |
| Cold start latency | Set `API_MIN_INSTANCES=1` for always-warm instances (increases cost) |
| CORS errors | Update `CORS_ORIGIN` env var to match the Web UI domain |

### VM

| Issue | Solution |
|---|---|
| Service fails to start | `journalctl -u opencred -n 100` — check for missing env vars |
| Docker permission denied | Verify `opencred` user is in `docker` group: `groups opencred` |
| Port already in use | Check: `ss -tlnp \| grep -E '(3000\|8080)'` |
| Images not pulling | Check registry auth: `docker login ghcr.io` |
| Disk space | Prune old images: `docker system prune -af --volumes` |
| TLS certificate not renewing | Check Caddy logs: `journalctl -u caddy -f` |

### General

| Issue | Solution |
|---|---|
| Health check failing | Verify the API container is running and port 3000 is exposed |
| JWT errors | Regenerate `JWT_SECRET` — must be at least 32 characters |
| CSCA validation failing | Check PEM files are readable and in the mounted trust store path |
