# @opencred/server

Headless OpenCred — the Phase 6 Docker image. A thin HTTP wrapper around
the same `@opencred/crypto`, `@opencred/vc-core`, `@opencred/schema-engine`,
`@opencred/signing`, and `@opencred/verification` packages that the desktop
client uses, exposing them via a versioned `/v1` REST API for cloud
deployment.

This package is the server-side counterpart of the Electron desktop client at
`apps/desktop`. It exposes exactly the same credential issuance and
verification capabilities, minus the GUI, so that issuers running cloud
infrastructure can deploy OpenCred as a container instead of (or in addition
to) the desktop application.

## Status

Issue: [#301 — final sprint: build and test Docker container (Phase 6 + 7)](https://github.com/nfh-trust-labs/opencred/issues/301)

What ships in this scaffold:

- Hono HTTP server with the four endpoints required by the issue and the
  legacy unprefixed routes for backwards compatibility with the desktop
  main process and pre-`/v1` tests.
- Software key signer that loads a PEM/JWK/PKCS#8/PFX file from disk at
  startup. The private key never crosses the HTTP boundary.
- **Fail-closed authentication**: the server refuses to start unless an
  API key (or an explicit dev-mode opt-out) is configured — see
  "Authentication" below and [issue #312](https://github.com/nfh-trust-labs/opencred/issues/312).
- Multi-stage Dockerfile that produces a non-root, alpine-based image.
- In-process tests that boot the server in-memory and exercise every
  endpoint round-trip.
- Defense-in-depth check that rejects any request containing a `privateKey`
  field or a string that looks like a PEM-encoded private key.

## Security invariants

These rules are enforced by code, not by convention:

1. **The HTTP API never accepts a private key.** The server loads its
   signing key once at startup from `OPENCRED_KEY_PATH` (or, optionally, a
   Cloud HSM provider). Any request whose body contains a `privateKey`
   field, or a string starting with `-----BEGIN PRIVATE KEY-----`, is
   rejected with a `400 VALIDATION_ERROR`. See `rejectKeyMaterial()` in
   `src/routes/credentials.ts`.
2. **Authentication is required by default.** The server refuses to start
   if `OPENCRED_API_KEY` is unset. The only way to run without an API key
   is to set `OPENCRED_DEV_MODE_NO_AUTH=true`, which logs a loud warning at
   startup and is **refused** when `NODE_ENV=production`. See
   "Authentication" below.
3. **Key material is never logged.** Pino logs only contain the key id,
   fingerprint, algorithm, and source — never the private key bytes.
4. **JSON-LD contexts are bundled.** The `@opencred/vc-core` document
   loader serves W3C, NFH education, employment, identity, health, and
   business contexts from in-memory JSON. The container makes no outbound
   HTTP calls to fetch contexts at runtime.
5. **Errors are sanitized.** All thrown errors flow through the
   `OpenCredError` hierarchy in `@opencred/shared`, which guarantees
   consistent JSON-shaped responses with no key material, file paths, or
   internal stack traces.
6. **No server-side session.** Issue and verify are pure request/response
   functions with no persistent state. Nothing about a credential is kept
   on the server after the response is written.

## Endpoints (`/v1`)

| Method | Path                       | Description                                       |
|--------|----------------------------|---------------------------------------------------|
| GET    | `/v1/health`               | Liveness probe — returns `{ status, signingKeyLoaded, timestamp }`. **Public** (no auth). |
| GET    | `/v1/keys`                 | Lists configured signer metadata (no key material). Requires auth. |
| POST   | `/v1/credentials/issue`    | Builds, validates, signs, and returns a VC. Requires auth. |
| POST   | `/v1/credentials/verify`   | Verifies a VC (Data Integrity, VC-JWT, SD-JWT VC). Requires auth. |

The same endpoints are also mounted under the unprefixed paths (`/health`,
`/keys`, `/credentials/issue`, `/credentials/verify`) for compatibility with
the existing desktop main process and the test suite that pre-dates the
`/v1` prefix. Auth rules apply to both prefixes.

### Example curl invocations

Health probe (no auth required):

```sh
curl -s http://localhost:3100/v1/health
# {"status":"ok","signingKeyLoaded":true,"timestamp":"2026-04-07T..."}
```

Inspect the active signer (auth required, no key material returned):

```sh
curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY"
# {"keys":[{"id":"did:key:z6Mk...","fingerprint":"d6f4...","algorithm":"P-256","type":"software","hasCertificateChain":false,"source":"software-file","label":"server-key"}]}
```

Issue an education credential (auth required):

```sh
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schemaId": "education",
    "issuerDid": "did:key:z6Mk...",
    "credentialSubject": {
      "name": "Jane Doe",
      "degree": "Master of Science",
      "institution": "MIT",
      "dateConferred": "2025-06-15"
    },
    "validFrom": "2025-06-15T00:00:00Z",
    "proofFormat": "data-integrity"
  }'
```

Verify a credential (auth required):

```sh
curl -s http://localhost:3100/v1/credentials/verify \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "credential": "<JSON-stringified credential or compact SD-JWT VC>"
  }'
```

## Authentication

OpenCred Server's HTTP API is a **signing oracle**. Anyone who can reach
the `/credentials/issue` endpoint can mint credentials signed by the
configured key. The server therefore refuses to start without an explicit
authentication decision.

Exactly one of the following must be set at startup:

1. **`OPENCRED_API_KEY`** (recommended) — a strong, randomly generated
   bearer token. Every protected endpoint then requires
   `Authorization: Bearer <key>`. The server uses a constant-time
   comparison to prevent timing attacks. Generate one with:

   ```sh
   openssl rand -base64 32
   # Or:
   node -e 'console.log(require("crypto").randomBytes(32).toString("base64"))'
   ```

2. **`OPENCRED_DEV_MODE_NO_AUTH=true`** (development only) — explicit,
   loud opt-out from authentication. When set:

   - The server logs a multi-line `WARNING:` banner at startup.
   - All protected endpoints become reachable without an Authorization header.
   - The server **refuses to start** if `NODE_ENV=production` is also set.

   Use this only for `pnpm dev` against `http://localhost:3100` while
   developing locally. Never set this in any environment that is reachable
   from the public internet, a corporate VPN, or a container orchestrator's
   service network.

If neither variable is set, the server exits with the error:

```
[opencred-server] FATAL: OPENCRED_API_KEY is required. Set OPENCRED_API_KEY
to a strong, randomly generated bearer token before starting the server.
For local development only, you may instead set OPENCRED_DEV_MODE_NO_AUTH=true
to disable authentication; this is REFUSED when NODE_ENV=production.
```

This behaviour was added in response to [issue #312](https://github.com/nfh-trust-labs/opencred/issues/312)
(security review CRITICAL-2). Prior to this fix the auth middleware
short-circuited whenever the API key was unset, exposing
`POST /credentials/issue` to anyone with network access.

The `/health` and `/v1/health` endpoints are always reachable without
authentication so that container orchestrators (Kubernetes, ECS, Compose
healthchecks, etc.) can probe liveness without holding the API key.

## Configuration

All configuration is loaded from environment variables at startup. None of
the values below are ever logged.

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCRED_PORT` | `3100` | TCP port the HTTP server listens on. |
| `OPENCRED_LOG_LEVEL` | `info` | One of `fatal\|error\|warn\|info\|debug\|trace`. |
| `OPENCRED_API_KEY` | _(unset — required)_ | Bearer token for protected endpoints. **Required** unless `OPENCRED_DEV_MODE_NO_AUTH=true` is set. The server refuses to start if both are unset. |
| `OPENCRED_DEV_MODE_NO_AUTH` | `false` | Explicit opt-out for authentication. When `true`, protected endpoints are reachable without an API key. **Refused when `NODE_ENV=production`.** Loud warning logged at startup. Local-development only. |
| `NODE_ENV` | _(unset)_ | If set to `production`, the server refuses to start when `OPENCRED_DEV_MODE_NO_AUTH=true`. Defense in depth. |
| `OPENCRED_KEY_PATH` | _(unset)_ | Absolute path to the signing key file. PEM, JWK, PKCS#8, or PFX. |
| `OPENCRED_KEY_PASSWORD` | _(unset)_ | Password for PFX/P12 key files. |
| `OPENCRED_KEY_LABEL` | `server-key` | Display label shown in `/v1/keys`. |
| `OPENCRED_SESSION_TTL` | `14400` | Ephemeral session TTL (seconds). Currently unused — issue/verify are stateless. |
| `OPENCRED_BATCH_ROW_LIMIT` | `1000` | Max rows in a single CSV batch. |
| `OPENCRED_KMS_PROVIDER` | `none` | `aws \| azure \| gcp \| none`. |
| `OPENCRED_KMS_KEY_ARN` | _(unset)_ | Required when provider is `aws`. |
| `OPENCRED_AZURE_KEY_VAULT_URL` | _(unset)_ | Required when provider is `azure`. |
| `OPENCRED_AZURE_KEY_NAME` | _(unset)_ | Required when provider is `azure`. |
| `OPENCRED_GCP_KMS_KEY_NAME` | _(unset)_ | Required when provider is `gcp`. |

## Running locally

From the repo root:

```sh
# Install workspace dependencies
pnpm install

# Build everything @opencred/server depends on
pnpm --filter @opencred/server... build

# Generate a throwaway signing key for development
openssl ecparam -genkey -name prime256v1 -noout -out /tmp/dev-key.pem

# Generate a throwaway API key for development
export OPENCRED_API_KEY="$(openssl rand -base64 32)"

# Start the server (with auth — recommended even for local dev)
OPENCRED_KEY_PATH=/tmp/dev-key.pem \
  OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  pnpm --filter @opencred/server dev
```

Or, for the truly throwaway local case where you just want a curl-able
endpoint with no auth ceremony:

```sh
OPENCRED_KEY_PATH=/tmp/dev-key.pem \
  OPENCRED_DEV_MODE_NO_AUTH=true \
  pnpm --filter @opencred/server dev
# WARNING banner appears in the logs.
```

Then in another terminal:

```sh
# /health is always public
curl -s http://localhost:3100/v1/health

# Protected endpoints need the bearer token (unless dev-mode is on)
curl -s http://localhost:3100/v1/keys -H "Authorization: Bearer $OPENCRED_API_KEY"
```

## Running tests

```sh
pnpm --filter @opencred/server test
```

## Building the Docker image

```sh
# From the repo root (the build context must be the repo root, not apps/server/)
docker build -f apps/server/Dockerfile -t opencred/server:dev .
```

## Running the Docker image

```sh
# Generate a strong API key first.
export OPENCRED_API_KEY="$(openssl rand -base64 32)"

# Mount your signing key as a read-only volume — never bake it into the image.
docker run --rm -p 3100:3100 \
  -e OPENCRED_KEY_PATH=/run/secrets/issuer.pem \
  -e OPENCRED_API_KEY \
  -e OPENCRED_LOG_LEVEL=info \
  -e NODE_ENV=production \
  -v /local/path/issuer.pem:/run/secrets/issuer.pem:ro \
  opencred/server:dev
```

The container's `HEALTHCHECK` probes `/v1/health` (public) every 30 seconds.
The container runs as the non-root `node` user. Setting `NODE_ENV=production`
adds defense-in-depth: even if `OPENCRED_DEV_MODE_NO_AUTH=true` were
accidentally set in the environment, the server would refuse to start.

## Layout

```
apps/server/
├── Dockerfile           # multi-stage build (builder + alpine runtime)
├── package.json
├── README.md            # this file
├── tsconfig.json
├── vitest.config.ts
└── src/
    ├── index.ts         # entrypoint — wires config, logger, signer, routes
    ├── config.ts        # Zod-validated env var schema; enforces auth fail-closed
    ├── logger.ts        # pino logger (key material never logged)
    ├── cli.ts           # operator CLI
    ├── middleware/
    │   ├── auth.ts          # Bearer token auth (constant-time compare)
    │   └── error-handler.ts # OpenCredError → JSON response
    ├── routes/
    │   ├── health.ts        # GET /health, GET /v1/health (public)
    │   ├── keys.ts          # GET /keys, GET /v1/keys (no key material)
    │   ├── credentials.ts   # POST /credentials/issue, /credentials/verify, ...
    │   ├── schemas.ts       # GET /schemas (built-in schema metadata)
    │   ├── batch.ts         # POST /credentials/batch
    │   ├── revocation.ts    # POST /credentials/revocation-hash
    │   └── packaging.ts     # PDF / QR / JSON packaging
    ├── signing/
    │   ├── key-manager.ts   # software key loader
    │   └── cloud-hsm/       # KMS factories
    ├── batch/               # CSV batch engine
    ├── packaging/           # PDF/QR generators
    └── __tests__/
        ├── endpoints.test.ts
        ├── auth.test.ts
        ├── config.test.ts
        ├── cloud-hsm.test.ts
        └── cli.test.ts
```
