# CLI Reference

The `opencred` CLI provides command-line access to credential operations. It uses the same packages as the HTTP server but runs locally without starting a server.

## Installation

```bash
# From the monorepo
cd apps/server
pnpm build
node dist/cli.js --help

# Or install globally
npm install -g @opencred/server
opencred --help
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
| `--key <path>` | Yes | -- | Path to signing key file (PEM, JWK, PFX) |
| `--proof-format <fmt>` | No | `vc-jwt` | `vc-jwt`, `data-integrity`, `sd-jwt-vc` |
| `--output <file>` | Yes | -- | Output file path |

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
- `VALID -- Credential signature verified successfully.` (exit code 0)
- `INVALID -- <reason>` (exit code 1)

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
| `--input <csv>` | Yes | -- | CSV file path |
| `--key <path>` | Yes | -- | Signing key path |
| `--output-dir <dir>` | Yes | -- | Output directory (created if missing) |
| `--proof-format <fmt>` | No | `vc-jwt` | Proof format |

Output files are named `credential-<rowIndex>.json`. The command prints a summary and exits with code 1 if any rows failed.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (details on stderr) |
