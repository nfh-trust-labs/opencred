# OpenCred PoC Demo — Comprehensive Walkthrough

This runbook walks through **every signing method** across **every platform** — CLI, Desktop, Web UI, and Docker. It is designed for a ~40 minute end-to-end demonstration.

---

## Prerequisites

```bash
# One-command setup (from monorepo root):
./demos/setup-demo.sh
```

The setup script handles:
- `pnpm install && pnpm build`
- Demo issuer JWK generation → `demos/sample-keys/demo-issuer.jwk`
- API environment file → `apps/api/.env` (with random JWT_SECRET)
- SoftHSM2 detection and demo token initialization (if installed)

### Optional Dependencies

| Dependency | Purpose | Install |
|---|---|---|
| SoftHSM2 | PKCS#11 hardware token simulation | `brew install softhsm` (macOS) / `apt install softhsm2` (Linux) |
| Browser Extension | Web UI signing via PKCS#11/OS cert | Load `apps/browser-extension/dist` as unpacked extension in Chrome |
| Native Addon | OS certificate store access | Requires compilation (see apps/desktop/native/) |

These are **optional** — all demos gracefully handle their absence with informative skip messages.

---

## Demo Readiness Matrix

| Signing Method | Desktop | Web UI | CLI |
|---|---|---|---|
| Software key (file import) | GREEN | GREEN (JWK via WebCrypto) | GREEN (Demo 01-03) |
| In-app key generation | GREEN | — | GREEN (Demo 01) |
| Hardware token (PKCS#11) | YELLOW | YELLOW (needs extension + signing host) | — |
| OS certificate store | YELLOW | YELLOW (needs extension + native addon) | — |
| Delegated signing | N/A | GREEN | GREEN (Demo 04) |
| Interface signing (two-phase) | — | GREEN | GREEN (Demo 03) |
| Batch issuance | GREEN | GREEN | — |
| Verification | GREEN | GREEN | GREEN (Demo 05) |

**GREEN** = fully functional. **YELLOW** = code complete, needs external dependency; shows graceful degradation without it.

---

## Act 1: CLI Demo Scripts (~3 min)

Run all 9 demos from the command line:

```bash
cd demos
npx tsx run-all.ts
```

Expected output: **9/9 pass** with green checkmarks.

### Individual Demos

```bash
npx tsx 01-key-generation.ts       # P-256 keygen, did:key derivation, rotation
npx tsx 02-credential-issuance.ts  # CredentialBuilder + Data Integrity signing
npx tsx 03-interface-signing.ts    # Two-phase prepareProof → external sign → completeProof
npx tsx 04-delegation-lifecycle.ts # Delegation certificates, scope validation
npx tsx 05-verification.ts         # Valid + tampered credential verification
npx tsx 06-schema-validation.ts    # Schema registry, validation rules
npx tsx 07-revocation.ts           # Revocation hash, JCS canonicalization
npx tsx 08-auth-tokens.ts          # Capability tokens (HS256 JWT)
npx tsx 09-all-signers.ts          # Unified Signer interface across all backends
```

### What Each Demo Shows

| Demo | Packages | Key Concepts |
|---|---|---|
| 01 | `@opencred/crypto` | ECDSA P-256 key generation, did:key derivation, JWK export, key rotation |
| 02 | `@opencred/crypto` + `@opencred/vc-core` | Build a VC with CredentialBuilder, sign with Data Integrity Proof |
| 03 | `@opencred/crypto` | Two-phase signing: `prepareProof` → external sign → `completeProof` |
| 04 | `@opencred/delegation` | Create delegation certificate, validate scope authorization |
| 05 | `@opencred/verification` | Verify valid credential, detect tampered credential |
| 06 | `@opencred/schema-engine` | Schema registry, validate credential subjects against schemas |
| 07 | `@opencred/crypto` | Revocation hash computation, JCS canonicalization (RFC 8785) |
| 08 | `@opencred/auth` | Create/validate/scope-check capability tokens (HS256 JWT) |
| 09 | `@opencred/signing` + `@opencred/crypto` | **NEW** — Unified `Signer` interface: software key, JWK file, PKCS#11 (optional), OS cert (optional) |

### Highlight: Demo 09 — All Signers

Demo 09 exercises the unified `Signer` interface across every available backend:

1. **Software signer (in-memory key)** — generate P-256 key → `buildSigner()` → sign → verify
2. **Software signer (JWK file)** — `createSoftwareSigner(path)` → sign → verify
3. **PKCS#11 signer** — if SoftHSM detected → `createPkcs11Signer()` → sign; otherwise prints "skipped"
4. **OS cert signer** — if native addon available → `listOsCertificates()`; otherwise prints "skipped"
5. **Credential round-trip** — passes each signer through `prepareProof → sign → completeProof → verifyProof`

This proves all backends are interchangeable through the same `Signer` interface.

---

## Act 2: Desktop App (~15 min)

```bash
cd apps/desktop
pnpm dev
```

### Scene A: Key Generation (GREEN)

1. Navigate to **Key Management** → **Generate** sub-tab
2. Click **Generate P-256 Key**
3. A new key appears in the unified key table with its `did:key:z...` identifier and fingerprint

### Scene B: Software Key Import (GREEN)

1. Navigate to **Key Management** → **Import** sub-tab
2. Click **Import Key** → select `demos/sample-keys/demo-issuer.jwk`
3. A second key appears in the key table
4. Both generated and imported keys are available for signing

### Scene C: Hardware Token — PKCS#11 (YELLOW)

1. Navigate to **Key Management** → **Hardware Token** sub-tab
2. **If SoftHSM is installed and configured** (via `setup-demo.sh`):
   - Enter library path (e.g., `/opt/homebrew/lib/softhsm/libsofthsm2.so`)
   - Enter PIN: `1234`
   - Click **Connect** → keys on the token appear in the list
   - Select a P-256 key to register it in the unified key table
3. **If SoftHSM is not installed**:
   - The UI shows "No PKCS#11 library detected" with setup instructions
   - Graceful degradation — the rest of the app works normally

### Scene D: OS Certificate Store (YELLOW)

1. Navigate to **Key Management** → **OS Certificates** sub-tab
2. **If the native addon is compiled**:
   - The app lists P-256 signing certificates from the system keychain (macOS) or certificate store (Windows)
   - Select a certificate to register it in the unified key table
3. **If the native addon is not available**:
   - The UI shows "Native addon not available" with compilation instructions
   - Graceful degradation

### Scene E: Issue a Credential (GREEN)

1. Navigate to **Issue Credential**
2. Select schema: **Education**
3. Fill in sample data:
   - **Name:** Jane Doe
   - **Degree:** Bachelor of Science in Computer Science
   - **Institution:** Massachusetts Institute of Technology
   - **Date Conferred:** 2025-06-15
4. **Select any registered key** from the unified key table (generated, imported, hardware, or OS cert)
5. Click **Sign** — credential is signed locally using the selected key
6. Click **Export** to save the signed JSON-LD credential

### Scene F: Verify a Credential (GREEN)

1. Navigate to **Verify Credential**
2. Load the exported JSON-LD file
3. All checks should pass:
   - Signature integrity (Data Integrity proof verification)
   - Valid dates (issuance, expiration)
   - Issuer DID resolution

### Scene G: Batch Issuance (GREEN)

1. Navigate to **Batch Issuance**
2. Upload `demos/sample-data/batch-education.csv` (5 rows)
3. Map CSV columns to credential fields
4. Select a signing key
5. Click **Sign All** — all 5 credentials are signed
6. Export as ZIP containing all signed JSON-LD credentials

### Note on Delegated Signing

The **Delegated** tab is N/A for the desktop app. Desktop issuers (Type A/DSC) have their own keys and sign locally. Delegated signing is for web-based issuers (Type D) who delegate signing authority to OpenCred's server.

---

## Act 3: Web UI (~15 min)

Start both servers:

**Terminal 1 — API:**
```bash
cd apps/api
pnpm dev
# Runs on http://localhost:3000
```

**Terminal 2 — Web:**
```bash
cd apps/web
pnpm dev
# Runs on http://localhost:5173
```

Open `http://localhost:5173` in the browser.

### Scene A: Interface Signing + Software Key (GREEN)

1. Navigate to **Interface Signing**
2. Click **Import JWK** → select `demos/sample-keys/demo-issuer.jwk`
3. The browser imports the key into WebCrypto — **the private key never leaves the browser**
4. Fill in credential subject data (Education schema)
5. Click **Build & Sign**:
   - The app sends the unsigned credential to the API
   - API calls `prepareProof()` → returns `dataToSign` to the browser
   - Browser signs with WebCrypto (`crypto.subtle.sign`)
   - Browser sends signature back → API calls `completeProof()`
6. Download the signed credential
7. **Key point**: Two-phase flow means the private key stays entirely in the browser

### Scene B: Interface Signing + Hardware Token (YELLOW)

> Requires: Browser extension loaded + SoftHSM installed

1. Navigate to **Interface Signing** → **Extension** tab
2. The extension bridge detects the native messaging host
3. Select a PKCS#11 key from the extension's key list
4. The same two-phase flow works, but signing happens on the hardware token:
   - `prepareProof()` on the server → `dataToSign` sent to extension
   - Extension sends to native host → PKCS#11 `C_Sign` on the token
   - Signature returned → `completeProof()` on the server
5. **Without the extension**: The tab shows "Browser extension not detected" with setup instructions

### Scene C: Interface Signing + OS Certificate (YELLOW)

> Requires: Browser extension loaded + native addon compiled

1. Navigate to **Interface Signing** → **Extension** tab
2. Select an OS certificate from the extension's list
3. Same two-phase flow, signing via the OS cryptography API (macOS Keychain / Windows CNG)
4. **Without the extension/addon**: Graceful skip with instructions

### Scene D: Delegated Signing (GREEN)

1. Navigate to **Delegated Signing**
2. Enter a delegation ID (from a pre-configured delegation certificate)
3. Fill in credential subject data
4. Click **Issue** — the server signs using OpenCred's managed signing key
5. Download the credential (includes the delegation certificate chain)
6. **Key point**: The issuer delegates signing authority; OpenCred signs on their behalf

### Scene E: Batch Issuance (GREEN)

1. Navigate to **Batch Issuance**
2. Upload `demos/sample-data/batch-education.csv`
3. Choose signing mode: **Interface** (browser signs each) or **Delegated** (server signs each)
4. Process all rows → download ZIP

### Scene F: Verification + Revocation (GREEN)

1. Navigate to **Verify**
2. Paste a signed credential JSON
3. View the verification result with check-by-check breakdown:
   - Proof integrity
   - Credential dates
   - Revocation status
   - Issuer DID resolution

### Scene G: Onboarding (GREEN)

1. Navigate to **Onboard**
2. Walk through the onboarding flow for each issuer type:
   - **Type A**: Direct Software — issuer uses own software key
   - **Type B**: SSL Certificate — issuer uses existing SSL/TLS certificate
   - **Type C**: CA-API — Certificate Authority integration
   - **Type D**: Delegated — issuer delegates to OpenCred

---

## Act 4: Docker Deployment (~5 min)

```bash
# From the monorepo root
docker compose up -d
```

Open `http://localhost:8080` — nginx serves the web app and proxies `/api/` to the API container.

### Verify

1. Open `http://localhost:8080`
2. Repeat web demo flows from Act 3 (Interface Signing, Delegated Signing, Verification)
3. The Docker environment provides the same functionality as local dev

### Stop

```bash
docker compose down
```

---

## SoftHSM Setup Guide

SoftHSM2 provides a software implementation of PKCS#11 for development and testing.

### Install

```bash
# macOS
brew install softhsm

# Ubuntu/Debian
sudo apt install softhsm2

# Fedora/RHEL
sudo dnf install softhsm
```

### Initialize Demo Token

The `setup-demo.sh` script handles this automatically. Manual setup:

```bash
# Initialize a token
softhsm2-util --init-token --free --label "demo-token" --pin 1234 --so-pin 5678

# Verify
softhsm2-util --show-slots
```

### Find Library Path

| Platform | Typical Path |
|---|---|
| macOS (Homebrew) | `/opt/homebrew/lib/softhsm/libsofthsm2.so` or `/opt/homebrew/lib/libsofthsm2.dylib` |
| Ubuntu/Debian | `/usr/lib/softhsm/libsofthsm2.so` or `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so` |
| Fedora/RHEL | `/usr/lib64/softhsm/libsofthsm2.so` |

---

## Browser Extension Loading

1. Build the extension:
   ```bash
   cd apps/browser-extension
   pnpm build
   ```

2. Load in Chrome:
   - Navigate to `chrome://extensions`
   - Enable **Developer mode** (toggle in top-right)
   - Click **Load unpacked**
   - Select `apps/browser-extension/dist/`
   - The extension icon should appear in the toolbar

3. The content script is configured to match:
   - `https://*.opencred.example.com/*`
   - `http://localhost:5173/*` (Vite dev server)
   - `http://localhost:8080/*` (Docker nginx)

---

## Sample Data

### Demo Issuer JWK

Generated by `setup-demo.sh` at `demos/sample-keys/demo-issuer.jwk`. This is a P-256 ECDSA key pair in JWK format. **Demo use only.**

### Batch CSV

Located at `demos/sample-data/batch-education.csv` — 5 education credential rows:

```csv
name,degree,institution,dateConferred
Jane Doe,BSc Computer Science,MIT,2025-06-15
John Smith,MSc Data Science,Stanford University,2025-05-20
Alice Johnson,BA Mathematics,University of Oxford,2025-07-01
Bob Williams,PhD Physics,Caltech,2025-04-30
Carol Davis,BSc Electrical Engineering,ETH Zurich,2025-06-01
```

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

---

## Troubleshooting

### `tsx` not found or esbuild errors

tsx requires esbuild. If you see errors about missing esbuild:
```bash
pnpm approve-builds    # Select esbuild when prompted
pnpm install
```

### Credential routes return 404

The API's `/credentials/*` routes only mount when `JWT_SECRET` is configured in `apps/api/.env`. Run `./demos/setup-demo.sh` to auto-create the file, or check that it exists and contains a valid `JWT_SECRET`.

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

### Demo 09 skips PKCS#11 or OS cert

This is expected behavior. PKCS#11 requires SoftHSM2 installed and initialized; OS cert requires the native addon compiled. Both degrade gracefully with informative messages. See the SoftHSM Setup Guide above for PKCS#11.

### SoftHSM "slot not found" or "token not initialized"

```bash
# Check current state
softhsm2-util --show-slots

# Re-initialize if needed
softhsm2-util --init-token --free --label "demo-token" --pin 1234 --so-pin 5678
```

### Browser extension not detected in web UI

1. Verify the extension is loaded: `chrome://extensions` → OpenCred Signing should be listed and enabled
2. Verify the content script matches: the manifest includes `http://localhost:5173/*` and `http://localhost:8080/*`
3. Reload the web page after loading the extension
4. Check the browser console for extension connection errors
