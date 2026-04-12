# Configuration Reference

All configuration for your OpenCred Docker deployment is via environment variables, validated at startup with Zod (`apps/server/src/config.ts`). Invalid values cause the process to exit with a descriptive error.

## Core

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_PORT` | integer (1-65535) | `3100` | No | HTTP listen port |
| `OPENCRED_API_KEY` | string | -- | Yes (unless dev mode) | Bearer token for API auth. Server refuses to start without it (fail-closed). Generate with `openssl rand -base64 32`. |
| `OPENCRED_DEV_MODE_NO_AUTH` | boolean | `false` | No | Explicit opt-out of API-key auth for local development only. Mutually exclusive with `OPENCRED_API_KEY`. Refused when `NODE_ENV=production`. |
| `OPENCRED_LOG_LEVEL` | enum | `info` | No | `fatal`, `error`, `warn`, `info`, `debug`, `trace` |

## Signing Key (File-based)

Used when `OPENCRED_KMS_PROVIDER` is `none` (the default).

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_KEY_PATH` | string (path) | -- | No | Path to signing key file (PEM, JWK, PKCS#8, or PFX). Mount at runtime, never bake into images |
| `OPENCRED_KEY_PASSWORD` | string | -- | No | Password for PFX-encrypted key files |
| `OPENCRED_KEY_LABEL` | string | `server-key` | No | Human-readable label for the signing key |

## Cloud HSM

Mutually exclusive with file-based signing. Set `OPENCRED_KMS_PROVIDER` and the matching provider variables. See [Cloud HSM](cloud-hsm.md) for IAM/auth requirements per provider.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_KMS_PROVIDER` | enum | `none` | No | `aws`, `azure`, `gcp`, or `none` |
| `OPENCRED_KMS_KEY_ARN` | string | -- | If `aws` | AWS KMS key ARN |
| `OPENCRED_AZURE_KEY_VAULT_URL` | URL | -- | If `azure` | Azure Key Vault URL |
| `OPENCRED_AZURE_KEY_NAME` | string | -- | If `azure` | Key name in the vault |
| `OPENCRED_GCP_KMS_KEY_NAME` | string | -- | If `gcp` | GCP KMS key resource name (including version, e.g. `projects/.../cryptoKeyVersions/N`) |

## Batch and Session

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_BATCH_ROW_LIMIT` | integer | `1000` | No | Maximum rows per batch CSV |
| `OPENCRED_SESSION_TTL` | integer (seconds, min 60) | `14400` | No | Ephemeral credential data TTL (default 4 hours) |

## Trust Store

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `CSCA_TRUST_STORE_PATH` | string (path) | -- | For DSC verification | Path to a directory of PEM-encoded CSCA root certificates used as trust anchors when verifying credentials with X.509 certificate chains. Mount read-only. |

## Example .env File

```bash
# Core
OPENCRED_PORT=3100
OPENCRED_API_KEY=sk_prod_your_random_token_here
OPENCRED_LOG_LEVEL=info

# Signing key (file-based)
OPENCRED_KEY_PATH=/secrets/issuer-key.pem
# OPENCRED_KEY_PASSWORD=  # Only needed for PFX

# Batch
OPENCRED_BATCH_ROW_LIMIT=1000

# Trust store (for DSC-backed credential verification)
# CSCA_TRUST_STORE_PATH=/app/trust-store
```
