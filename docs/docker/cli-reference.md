# CLI Reference

The `opencred` CLI provides command-line access to credential operations. It uses the same packages as the HTTP server but runs locally without starting a server.

## Installation

```bash
# From the monorepo
cd apps/server
pnpm build
node dist/cli.js --help
```

## Commands

### opencred issue

Issue a single Verifiable Credential.

```bash
opencred issue \
  --schema education \
  --input subject.json \
  --key /path/to/key.pem \
  --proof-format vc-jwt \
  --output credential.json
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--schema <id>` | Yes | -- | Schema ID to validate against |
| `--input <file>` | Yes | -- | JSON file with credential subject data |
| `--key <pem-path>` | Yes | -- | Path to signing key file (PEM, JWK, PFX) |
| `--proof-format <format>` | No | `vc-jwt` | `vc-jwt`, `data-integrity`, `sd-jwt-vc` |
| `--output <file>` | Yes | -- | Output file path |
| `--primary-color <hex>` | No | -- | Primary branding color (e.g. `#1a56db`) |
| `--logo <file>` | No | -- | Path to issuer logo image file (PNG/JPG/SVG) |
| `--issuer-name <name>` | No | -- | Issuer display name (overrides DID in output) |

The input JSON can contain top-level fields or a `credentialSubject` wrapper:

```json
{
  "name": "Jane Doe",
  "degree": "BSc Computer Science",
  "institution": "MIT",
  "dateConferred": "2025-06-15"
}
```

Optional fields in the input JSON: `issuerDid` (defaults to key DID), `validFrom` (defaults to now), `validUntil`, `additionalTypes`.

### opencred verify

Verify a signed Verifiable Credential.

```bash
opencred verify --input credential.json
```

| Option | Required | Description |
|--------|----------|-------------|
| `--input <file>` | Yes | Path to the signed credential JSON |

Output:
- `VALID — Credential signature verified successfully.` (exit code 0)
- `INVALID — <reason>` (exit code 1)

Only `did:key` issuers are supported.

### opencred hash

Compute the SHA-256 hash of a credential file.

```bash
opencred hash --input credential.json
```

Outputs the hex-encoded hash to stdout.

### opencred batch

Batch-issue credentials from a CSV file.

```bash
opencred batch \
  --schema education \
  --input students.csv \
  --key /path/to/key.pem \
  --output-dir ./credentials \
  --proof-format vc-jwt
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--schema <id>` | Yes | -- | Schema ID |
| `--input <csv-file>` | Yes | -- | CSV file path |
| `--key <pem-path>` | Yes | -- | Signing key path |
| `--output-dir <dir>` | Yes | -- | Output directory (created if missing) |
| `--proof-format <format>` | No | `vc-jwt` | Proof format |
| `--primary-color <hex>` | No | -- | Primary branding color (e.g. `#1a56db`) |
| `--logo <file>` | No | -- | Path to issuer logo image file (PNG/JPG/SVG) |
| `--issuer-name <name>` | No | -- | Issuer display name (overrides DID in output) |

Output files are named `credential-<rowIndex>.json`. The command prints a summary and exits with code 1 if any rows failed.

### opencred config validate

Validate server configuration from environment variables without starting the server. Useful for CI/CD pre-flight checks.

```bash
opencred config validate
```

Loads and validates all `OPENCRED_*` environment variables via the Zod schema in `apps/server/src/config.ts`. On success, prints the resolved port, auth mode, and KMS provider. On failure, prints the validation error and exits with code 1.

### opencred identity show

Print the configured issuer DID and key-source metadata. Uses the same DID-resolution logic as `opencred issue` / `opencred batch` so the printed DID is exactly what verifiers will see in issued credentials.

```bash
opencred identity show --key ./issuer.pem
```

For `did:web` issuers:

```bash
OPENCRED_ISSUER_DID_METHOD=web \
OPENCRED_ISSUER_DOMAIN=issuer.example.com \
  opencred identity show --key ./issuer.pem
```

| Flag / env var | Required | Description |
|---|---|---|
| `--key <pem-path>` | Yes (or `OPENCRED_KEY_PATH`) | Path to the signing key file (PEM/JWK/PFX). |
| `OPENCRED_KEY_PATH` | Fallback for `--key` | Used when `--key` is not supplied. |
| `OPENCRED_ISSUER_DID_METHOD` | No | `key` (default) or `web`. Drives DID derivation. |
| `OPENCRED_ISSUER_DOMAIN` | When `OPENCRED_ISSUER_DID_METHOD=web` | Domain for did:web. |
| `OPENCRED_DEDI_BASE_URL` | No | Surfaces DeDi configuration status in the output. |
| `OPENCRED_DEDI_HOST_DID_DOC` | No | When `true`, output reports DeDi as the DID-doc host. |

The output lists DID method, derived issuer DID, verification-method ID, signing algorithm, key fingerprint, key source (file / KMS / hardware token), and DeDi configuration state.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (details on stderr) |
