# Verifying Credentials

The Desktop app's **Verify** tab is the most user-friendly way to verify an OpenCred-issued credential — paste it, drop a file, scan a QR with your camera, or upload a QR image. All four input modes feed the same `@opencred/verification` engine that powers the Docker server and the library.

## Four ways to feed in a credential

The Verify tab has four input modes — switch between them with the tabs at the top of the page.

### 1. Paste JSON

Paste a signed credential as JSON into the textarea, or drop a `.json` / `.jsonld` file directly onto it. Works for full Data Integrity VCs (object with a `proof` block) — vc-jwt and sd-jwt-vc compact tokens go in the **Paste QR string** tab instead.

### 2. Upload File

Click **Upload file** and pick from your filesystem. The picker accepts:

* `.json`, `.jsonld` — full credential as JSON
* `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.webp` — **a QR-code image** (e.g. screenshotted from a wallet, exported from PixelPass, or photographed off a printed certificate). The image is decoded client-side and the recovered credential is verified.

### 3. Scan QR

Point your laptop camera at a printed QR code and the app decodes it live. Use this for verifying credentials someone hands you on paper or on another device's screen.

### 4. Paste QR string

Paste a compact token directly:

* **`OPENCRED1:...`** — PixelPass-encoded QR data (what gets printed on PDFs)
* **vc-jwt** — `eyJ...` compact JWS
* **sd-jwt-vc** — compact token with `~`-separated disclosures

## What gets checked

| Check | What it validates |
|---|---|
| Signature | Cryptographic signature integrity against the issuer's public key |
| Not before | `validFrom` date is not in the future |
| Expiry | `validUntil` date has not passed |
| Key resolution | Issuer's DID (`did:key`, `did:jwk`, or `did:web`) resolves to a valid public key |
| x5c chain | If the proof carries an `x5c` certificate chain, validates it against your CSCA trust store |
| Revocation | Bitstring status list lookup (and optionally a DeDi revocation-hash lookup if configured) |
| Schema | If the credential references a `credentialSchema`, validates the subject against the bundled JSON Schema |
| Context | All `@context` URLs resolve to a bundled context (no remote fetch) |

The result panel shows a top-level **VALID / INVALID** badge plus a per-check breakdown so you can see exactly which check failed and why.

## Result codes

| Code | Meaning |
|---|---|
| `VALID` | All checks passed |
| `REVOKED` | Signature is good but the credential's status entry says it has been revoked |
| `EXPIRED` | `validUntil` has passed |
| `INVALID` | Signature verification failed, a date check failed, or the schema check failed |
| `UNRESOLVABLE` | Issuer's DID could not be resolved (network failure for `did:web`, or malformed DID) |
| `CONTEXT_MISSING` | A `@context` URL is not bundled — verification is fail-closed; remote fetch is never performed |

## Offline verification

Verification runs locally against bundled JSON-LD contexts and a local DID resolver. **No network requests are made for `did:key` or `did:jwk` credentials.**

`did:web` credentials need network access to fetch the issuer's DID document from `https://<domain>/.well-known/did.json`. The fetch is restricted to public IPs only (SSRF-protected), HTTPS-only, with a 10-second timeout.

DSC-backed credentials (carrying an `x5c` chain) need a CSCA trust store on disk — set `OPENCRED_CSCA_TRUST_STORE_PATH` in **Settings → Trust anchors** to a directory of PEM-encoded CSCA roots.

## PDF certificates

OpenCred-issued PDF certificates carry the credential as a scannable QR printed on the page. **The PDF file itself is not a verification input today.** To verify one:

* **If you have the printed paper**: use **Scan QR** with your camera.
* **If you have the PDF as a file**: open it, screenshot or export the QR section as a `.png`, then drop the image into **Upload File**.
* **If you have the credential JSON separately** (e.g. from the issuer's API response): paste it into **Paste JSON** directly.

Native PDF-as-input is on the roadmap — uploading a `.pdf` file and getting a verified result without an intermediate QR step.
