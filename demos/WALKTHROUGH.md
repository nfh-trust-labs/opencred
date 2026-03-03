# OpenCred PoC Demo — Walkthrough

This guide walks through the three demo channels: **Desktop App**, **Website + API**, **CLI Scripts**, and **Docker**.

---

## Prerequisites

```bash
# From the monorepo root
pnpm install
pnpm build
```

---

## 1. Desktop App Demo

The Electron desktop app provides fully local, offline-capable credential issuance and verification.

### Start the app

```bash
cd apps/desktop
pnpm dev
```

### Step 1: Import a signing key

1. Navigate to the **Key Management** tab
2. Click **Import Key**
3. Select `demos/sample-keys/demo-issuer.jwk`
4. You should see the key fingerprint and its `did:key:z...` identifier

### Step 2: Issue a credential

1. Navigate to the **Issue Credential** tab
2. Select schema: **Education**
3. Fill in sample data:
   - **Name:** Jane Doe
   - **Degree:** Bachelor of Science in Computer Science
   - **Institution:** Massachusetts Institute of Technology
   - **Date Conferred:** 2025-06-15
4. The issuer DID is auto-filled from the imported key
5. Click **Sign** — the credential is signed locally using your private key
6. Click **Export** to save the signed JSON-LD credential

### Step 3: Verify a credential

1. Navigate to the **Verify Credential** tab
2. Load the JSON-LD file you just exported
3. All checks should pass:
   - Signature integrity
   - Valid dates (issuance, expiration)
   - Issuer DID resolution

### Step 4: Batch issuance

1. Navigate to the **Batch Issuance** tab
2. Upload the sample CSV (see [Sample Data](#sample-data) below)
3. Map CSV columns to credential fields
4. Click **Sign All**
5. Export as ZIP containing all signed credentials

---

## 2. Website Demo (Local Dev)

The web demo uses the Hono API server + React SPA for Interface Signing and Delegated Signing.

### Start the servers

Terminal 1 — API:
```bash
cd apps/api
pnpm dev
```

Terminal 2 — Web:
```bash
cd apps/web
pnpm dev
```

The API runs on `http://localhost:3000`, the web app on `http://localhost:5173`.

> **Note:** The API requires `JWT_SECRET` in `apps/api/.env` for credential routes to be active.
> Copy `apps/api/env-reference.txt` to `apps/api/.env` and set:
> ```
> NODE_ENV=development
> CORS_ORIGIN=http://localhost:5173
> JWT_SECRET=<any 48+ character hex string>
> JWT_ISSUER=opencred
> JWT_EXPIRY_SECONDS=3600
> ```

### Interface Signing (Two-Phase)

1. Open the web app at `http://localhost:5173`
2. Navigate to **Interface Signing**
3. Import your JWK file (the browser uses WebCrypto — your private key never leaves the browser)
4. Fill in credential subject data (Education schema)
5. Click **Build & Sign** — the app:
   - Sends the unsigned credential to the API for proof preparation
   - Signs the proof payload locally in the browser
   - Sends the signature back to complete the proof
6. Download the signed credential

### Delegated Signing

1. Navigate to **Delegated Signing**
2. Enter a delegation ID (from a pre-configured delegation certificate)
3. Fill in credential subject data
4. Click **Issue** — the server signs using OpenCred's managed signing key
5. Download the credential (includes the delegation certificate chain)

### Verification

1. Navigate to **Verify**
2. Paste a signed credential JSON
3. View the verification result with check-by-check breakdown

---

## 3. Docker Demo

Run the full stack (API + Web + nginx reverse proxy) via Docker Compose.

```bash
# From the monorepo root
docker compose up -d
```

Open `http://localhost:8080` — the nginx proxy serves the web app and forwards `/api/` requests to the API container.

The same flows from Section 2 (Interface Signing, Delegated Signing, Verification) are available.

To stop:
```bash
docker compose down
```

---

## 4. CLI Demo Scripts

Eight scripts demonstrate the core package APIs from the command line.

### Run all demos

```bash
cd demos
npx tsx run-all.ts
```

Expected output: 8/8 demos pass with green checkmarks.

### Run individual demos

```bash
npx tsx 01-key-generation.ts      # P-256 keygen, did:key derivation
npx tsx 02-credential-issuance.ts # CredentialBuilder + signing
npx tsx 03-interface-signing.ts   # Two-phase prepareProof/completeProof
npx tsx 04-delegation-lifecycle.ts # Delegation certificates
npx tsx 05-verification.ts        # Signature verification (valid + tampered)
npx tsx 06-schema-validation.ts   # Schema registry + validation
npx tsx 07-revocation.ts          # Revocation hash + JCS canonicalization
npx tsx 08-auth-tokens.ts         # Capability tokens (JWT)
```

### What each demo shows

| Demo | Package | Key Concepts |
|---|---|---|
| 01 | `@opencred/crypto` | ECDSA P-256 key generation, did:key derivation, JWK export |
| 02 | `@opencred/crypto` + `@opencred/vc-core` | Build a VC with CredentialBuilder, sign with Data Integrity Proof |
| 03 | `@opencred/crypto` | Two-phase signing: prepareProof → external sign → completeProof |
| 04 | `@opencred/delegation` | Create delegation certificate, validate authorization |
| 05 | `@opencred/verification` | Verify valid credential, detect tampered credential |
| 06 | `@opencred/schema-engine` | Schema registry, validate credential subjects against schemas |
| 07 | `@opencred/crypto` | Revocation hash computation, JCS canonicalization (RFC 8785) |
| 08 | `@opencred/auth` | Create/validate/scope-check capability tokens (HS256 JWT) |

---

## Sample Data

### Education Credential Subject

```json
{
  "name": "Jane Doe",
  "degree": "Bachelor of Science in Computer Science",
  "institution": "Massachusetts Institute of Technology",
  "dateConferred": "2025-06-15"
}
```

### Employment Credential Subject

```json
{
  "name": "John Smith",
  "employer": "Google LLC",
  "title": "Senior Software Engineer",
  "startDate": "2023-01-15"
}
```

### Batch CSV (Education — 5 rows)

```csv
name,degree,institution,dateConferred
Jane Doe,BSc Computer Science,MIT,2025-06-15
John Smith,MSc Data Science,Stanford University,2025-05-20
Alice Johnson,BA Mathematics,University of Oxford,2025-07-01
Bob Williams,PhD Physics,Caltech,2025-04-30
Carol Davis,BSc Electrical Engineering,ETH Zurich,2025-06-01
```

---

## Troubleshooting

### `tsx` not found or esbuild errors

tsx requires esbuild. If you see errors about missing esbuild:
```bash
pnpm approve-builds    # Select esbuild when prompted
pnpm install
```

### Credential routes return 404

The API's `/credentials/*` routes only mount when `JWT_SECRET` is configured in `apps/api/.env`. Check that the file exists and contains a valid `JWT_SECRET`.

### jsonld / canonicalization errors

If you see `jsonld.canonize is not a function`, rebuild the crypto package:
```bash
pnpm --filter @opencred/crypto build
```

### Docker: web app can't reach API

Ensure the nginx config has the `/api/` proxy block (check `apps/web/nginx.conf`). The API container must be accessible as `http://api:3000` from within the Docker network.

### CORS errors in browser

- **Local dev:** Set `CORS_ORIGIN=http://localhost:5173` in `apps/api/.env`
- **Docker:** The docker-compose.yml sets `CORS_ORIGIN=http://localhost:8080` by default
