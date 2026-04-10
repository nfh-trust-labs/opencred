# Getting Started with the OpenCred Docker Image

The OpenCred Docker Image is the headless version of the Desktop app — same credential capabilities, no GUI. You deploy it in **your own infrastructure** and it runs entirely under your control. All signing uses your keys, on your machines. No data is sent to OpenCred.

No data is sent to OpenCred.

## Quick Start (Docker)

```bash
# Build the image
docker build -f apps/server/Dockerfile -t opencred:latest .

# Run with a mounted signing key
docker run -p 3100:3100 \
  -e OPENCRED_PORT=3100 \
  -e OPENCRED_API_KEY=your-secret-api-key \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -v /path/to/your/key.pem:/secrets/issuer-key.pem:ro \
  opencred:latest

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
export OPENCRED_DEV_MODE_NO_AUTH=true  # local dev only; never use in production

# Start the dev server
cd apps/server
pnpm dev
```

## Providing a Signing Key

Your signing key stays in your infrastructure — it is loaded at startup and never transmitted.

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
- [API Reference](api-reference.md) -- endpoints exposed by your deployment
- [CLI Reference](cli-reference.md) -- command-line tool
- [Cloud HSM](cloud-hsm.md) -- AWS KMS, Azure Key Vault, GCP Cloud KMS
