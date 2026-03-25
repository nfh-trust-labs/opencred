# Configuration Reference

All configuration for your OpenCred Docker deployment is via environment variables, validated at startup with Zod. Invalid values cause the process to exit with a descriptive error.

## Core

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_PORT` | integer (1-65535) | `3100` | No | HTTP listen port |
| `OPENCRED_API_KEY` | string | -- | No | Bearer token for API auth. If unset, authentication is disabled (dev mode) |
| `OPENCRED_LOG_LEVEL` | enum | `info` | No | `fatal`, `error`, `warn`, `info`, `debug`, `trace` |

## Signing Key (File-based)

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_KEY_PATH` | string (path) | -- | No | Path to signing key file (PEM, JWK, PKCS#8, or PFX). Mount at runtime, never bake into images |
| `OPENCRED_KEY_PASSWORD` | string | -- | No | Password for PFX-encrypted key files |
| `OPENCRED_KEY_LABEL` | string | `server-key` | No | Human-readable label for the signing key |

## Cloud HSM

Mutually exclusive with file-based signing. See [Cloud HSM](cloud-hsm.md) for setup details.

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_KMS_PROVIDER` | enum | `none` | No | `aws`, `azure`, `gcp`, or `none` |
| `OPENCRED_KMS_KEY_ARN` | string | -- | If `aws` | AWS KMS key ARN |
| `OPENCRED_AZURE_KEY_VAULT_URL` | URL | -- | If `azure` | Azure Key Vault URL |
| `OPENCRED_AZURE_KEY_NAME` | string | -- | If `azure` | Key name in the vault |
| `OPENCRED_GCP_KMS_KEY_NAME` | string | -- | If `gcp` | GCP KMS key resource name |

## Batch and Session

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_BATCH_ROW_LIMIT` | integer | `1000` | No | Maximum rows per batch CSV |
| `OPENCRED_SESSION_TTL` | integer (seconds, min 60) | `14400` | No | Ephemeral credential data TTL (default 4 hours) |

## OID4VCI

Required when using [OID4VCI endpoints](oid4vci.md).

| Variable | Type | Default | Required | Description |
|----------|------|---------|----------|-------------|
| `OPENCRED_OID4VCI_ISSUER_URL` | URL | -- | For OID4VCI | Base URL for issuer metadata |
| `OPENCRED_OID4VCI_ISSUER_NAME` | string | -- | No | Display name in issuer metadata |
| `OPENCRED_OID4VCI_AUTHORIZATION_SERVERS` | comma-separated URLs | -- | No | External authorization server URLs |

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

# OID4VCI (optional)
# OPENCRED_OID4VCI_ISSUER_URL=https://issuer.example.com
# OPENCRED_OID4VCI_ISSUER_NAME=Example Issuer
```
