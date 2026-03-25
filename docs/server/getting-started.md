# Getting Started with OpenCred Server

OpenCred Server is a headless HTTP API for credential issuance, verification, and packaging. It provides the same credential capabilities as the Desktop app, minus the GUI. Designed for Docker deployment with support for file-based and Cloud HSM signing keys.

## Quick Start (Docker)

```bash
# Build the image
docker build -f apps/server/Dockerfile -t opencred-server:latest .

# Create .env file
cat > .env << 'EOF'
OPENCRED_PORT=3100
OPENCRED_API_KEY=your-secret-api-key
OPENCRED_KEY_PATH=/secrets/issuer-key.pem
EOF

# Run with a mounted signing key
docker run -p 3100:3100 --env-file .env \
  -v /path/to/your/key.pem:/secrets/issuer-key.pem:ro \
  opencred-server:latest

# Verify
curl http://localhost:3100/health
```

## Quick Start (Local Development)

```bash
# From the repo root
pnpm install
pnpm build

# Set environment variables
export OPENCRED_PORT=3100
export OPENCRED_KEY_PATH=/path/to/your/key.pem

# Start the dev server
cd apps/server
pnpm dev
```

## Providing a Signing Key

Two options:

**File-based** (default): Set `OPENCRED_KEY_PATH` to a PEM, JWK, PKCS#8, or PFX file. For PFX, also set `OPENCRED_KEY_PASSWORD`.

**Cloud HSM**: Set `OPENCRED_KMS_PROVIDER` to `aws`, `azure`, or `gcp` with the provider-specific variables. See [Cloud HSM](cloud-hsm.md).

## Verifying the Setup

```bash
curl http://localhost:3100/health
```

Response:
```json
{
  "status": "ok",
  "signingKeyLoaded": true,
  "timestamp": "2026-03-25T10:00:00.000Z"
}
```

If `signingKeyLoaded` is `false`, check your key path or KMS configuration.

## Next Steps

- [Configuration Reference](configuration.md) -- all environment variables
- [API Reference](api-reference.md) -- HTTP endpoints
- [CLI Reference](cli-reference.md) -- command-line tool
- [Cloud HSM](cloud-hsm.md) -- AWS KMS, Azure Key Vault, GCP Cloud KMS
