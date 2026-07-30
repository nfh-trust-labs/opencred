# Verifying Credentials

The Docker image's HTTP API and CLI both expose the same verification engine that powers the Desktop app. Use the HTTP API for service-to-service verification, the CLI for scripts and CI, and a library directly when embedding verification in another Node service — either the curated [`@opencred/verify`](https://github.com/nfh-trust-labs/opencred-releases/tree/main/sdk/verify) SDK (recommended for external verifiers) or the lower-level `@opencred/verification` package it's built on.

## The three verification surfaces

| Surface | Best for | Endpoint / command |
|---|---|---|
| HTTP API | Service-to-service verification, browser-side flows through a proxy | `POST /v1/credentials/verify` |
| CLI | Scripts, CI checks, air-gapped batch verification | `opencred verify <input>` |
| Library | Embedding verification into a TypeScript/Node service | `createVerifier()` from [`@opencred/verify`](https://github.com/nfh-trust-labs/opencred-releases/tree/main/sdk/verify) (or the lower-level `verifyCredential()` from `@opencred/verification`) |

All three return the same shape: a top-level `code`, a boolean `valid`, and a `checks` array breaking down which steps passed.

## "I only want to verify, not issue"

Verification is a *consumer-side* concern — anyone receiving a credential needs it, but they don't need the issuer's key, the issuer's API token, or even a network connection to the issuer. The Docker image supports four distinct verifier-only setups, none of which require any issuer infrastructure:

### Verifier path 1 — CLI in a one-shot container (zero setup)

The simplest. No long-running server, no signing key, nothing to configure:

```bash
# Pipe a JWT to the verify subcommand (use `--input -` to read from stdin).
echo "$JWT" | docker run --rm -i \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest verify --input -

# Or verify a credential from a file.
docker run --rm -v "$PWD/credential.json:/in.json:ro" \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest verify --input /in.json
```

Exit code is `0` on `valid: true`, non-zero otherwise. Works fully offline for `did:key` / `did:jwk` credentials (those are the common cases for issuers using OpenCred's defaults). `did:web` credentials need outbound HTTPS to the issuer's domain; DSC-signed credentials need a CSCA bundle mounted in.

### Verifier path 2 — Library, embedded in your own service

Add the curated **[`@opencred/verify`](https://github.com/nfh-trust-labs/opencred-releases/tree/main/sdk/verify)** SDK to your Node service and call it directly — no OpenCred container required at all:

```ts
import { createVerifier } from "@opencred/verify";

// Offline did:key / did:jwk verification — no network, no setup.
const verify = createVerifier();

const result = await verify(jwt);
if (result.verified) {
  // proceed
}
```

Need DeDi-backed revocation or `did:web` discovery fallback? Pass `dedi`:

```ts
const verify = createVerifier({
  dedi: {
    baseUrl: "https://dedi.example.com",
    namespace: "issuer-namespace",
    // apiKey is only required for *publishing*; verifiers can omit it.
  },
});
```

The SDK is a single bundled facade over `@opencred/verification`, `@opencred/did`, and `@opencred/dedi-client` — one dependency, dual ESM/CJS, no workspace setup. It is MIT-licensed and lives at [`packages/verify-sdk`](https://github.com/nfh-trust-labs/opencred-releases/tree/main/packages/verify-sdk) in this repository; today, install it from source (clone the repo, `pnpm install && pnpm build`, then `npm install <path>/packages/verify-sdk`). npm publication is on the roadmap.

> **Advanced — in-monorepo or fine-grained control:** if you need to wire DID resolvers, trust anchors, or the verification pipeline yourself (e.g. you're inside this monorepo or you want to swap in a custom DID method), drop down to the lower-level `@opencred/verification` library — see [Library](#library) below for the unwrapped API.

This is what production verifier services should generally use — it bypasses the HTTP/auth overhead and runs in your own process boundary.

### Verifier path 3 — HTTP server in verify-only mode

Run the same Docker image but **omit `OPENCRED_KEY_PATH`** — the server starts without a signing key and the issue endpoint is automatically disabled, but the verify endpoint works normally:

```bash
docker run -d --name opencred-verifier \
  -p 3100:3100 \
  -e OPENCRED_PORT=3100 \
  -e OPENCRED_API_KEY="$(openssl rand -base64 32)" \
  --read-only --tmpfs /tmp:noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

Notes:

* The `OPENCRED_API_KEY` is still required — it's the bearer token callers need to hit `/v1/credentials/verify`. Generate any random secret; this isn't an "issuer" identity, just an access token for the verify endpoint.
* No `OPENCRED_KEY_PATH`, no `-v` mount for a signing key.
* `POST /v1/credentials/issue` returns HTTP 500 (`requireSigner` correctly fails) — call sites that try to issue will surface as errors, which is the desired behaviour for a pure-verifier deployment.
* **Health-probe gotcha:** `GET /v1/health` returns HTTP 503 with `ready: false, signingKeyLoaded: false`. The server is in fact functional, but the health endpoint considers "no signing key" not-ready by design. For orchestrators (Kubernetes, Docker Swarm, Cloud Run), configure a custom liveness probe — e.g. a successful `POST /v1/credentials/verify` against a known-good test credential — instead of relying on `/v1/health`.

Layer DeDi on top with the same `OPENCRED_DEDI_*` env vars if you need revocation checks or did:web fallback — see [Using DeDi for verification](#using-dedi-for-verification).

### Verifier path 4 — Any conformant W3C VC verifier

OpenCred-issued credentials follow the W3C VC Data Model 2.0 with standard proof formats (`vc-jwt` / `data-integrity` / `sd-jwt-vc`). Any conformant verifier should accept them — the MOSIP Inji wallet, generic JOSE libraries (`jose`, `jsonwebtoken`, `python-jose`), and other VC verification toolkits.

The receiver needs:

1. **The credential** (compact JWT, JSON-LD VC, sd-jwt-vc, or PixelPass string from a QR).
2. **The issuer's public key**, which a conformant `did:key` / `did:jwk` / `did:web` resolver derives offline from the DID string itself. No OpenCred-specific code required.

This is the demonstration of W3C VC portability: an OpenCred-issued vc-jwt is just an ES256-signed JOSE token whose `iss` is a self-describing `did:key`. Any stock JOSE library can:

1. Split the JWT, base64url-decode the payload, read `iss`.
2. Resolve the `did:key` locally (the suffix encodes the public key directly — no network call).
3. Verify the ES256 signature over `header.payload`.

A complete worked Python example using only `cryptography` is generated as part of the bootcamp (see [Bootcamp → Local Docker track](../bootcamp/local-docker.md)).

### Pick-the-path-quickly cheat sheet

| Scenario | Best path |
|---|---|
| One-off "does this credential check out?" from a shell | Path 1 (CLI one-shot) |
| Production verifier service in Node | Path 2 (library) |
| Production verifier exposed via HTTP for non-Node clients | Path 3 (verify-only server) |
| Demonstrating that credentials are truly portable | Path 4 (any verifier) |

## Accepted input formats

The verifier auto-detects the credential format. Same set of formats across all three surfaces:

| Format | Wire shape | HTTP body |
|---|---|---|
| **vc-jwt** | Compact JWT (`eyJ…`) | `application/json` with `{"credential":"<jwt>"}` |
| **JSON-LD VC** (DataIntegrityProof) | Full credential object | `application/json` with `{"credential":"<stringified-json>"}` |
| **sd-jwt-vc** | Compact SD-JWT with disclosure tildes | `application/json` with `{"credential":"<sd-jwt>"}` |
| **PixelPass QR data** | Bare Base45 text payload from an OpenCred-issued QR | `application/json` with `{"credential":"<base45-payload>"}` |
| **PDF with embedded VC** | Raw PDF bytes; credential read from the PDF info-dictionary `OpenCredCredential` key | `application/pdf` with the binary body |

> If you have a JSON-LD VC whose `proof.type` is `JsonWebSignature2020` with a `jwt` field (what `/v1/credentials/issue` returns when `proofFormat: "vc-jwt"`), extract `proof.jwt` and send the bare compact JWT. The wrapper is not a recognized proof type — the verifier expects the compact form directly.

## HTTP API

```bash
# vc-jwt / sd-jwt-vc / PixelPass QR data — pass the compact string in `credential`.
JWT="eyJhbGciOiJFUzI1Ni…"
jq -n --arg jwt "$JWT" '{credential: $jwt}' | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @-

# JSON-LD VC — stringify the whole credential.
jq '{credential: (.credential | tostring)}' my-credential.json | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @-

# PDF — binary body, application/pdf Content-Type.
curl -s http://localhost:3100/v1/credentials/verify \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/pdf" \
  --data-binary @my-credential.pdf
```

Successful response:

```json
{
  "valid": true,
  "code": "VALID",
  "message": "Credential is valid.",
  "checks": [
    { "name": "signature",     "passed": true },
    { "name": "vc-jwt-claims", "passed": true },
    { "name": "date",          "passed": true }
  ]
}
```

On failure, `valid: false`, a stable `code` enum, and a generic `message`. The `checks` array shows which check failed by name; the per-check `detail` strings are deliberately **stripped from HTTP responses** to avoid leaking operator config (CSCA subject DNs, parser errors, path-shaped state) to remote callers. To see them, switch the server to debug logging — see [Debugging failed verifications](#debugging-failed-verifications) below.

## QR verification

Holders, kiosks, and field verifiers most often interact with OpenCred credentials through a printed or on-screen **QR code** — the small square on every OpenCred PDF certificate, or the standalone QR a holder presents from their device. This section explains what's inside that QR, how to decode it, and how to verify the recovered credential through any of the surfaces above.

### What's inside an OpenCred QR

OpenCred's QR encoder picks one of two payloads based on how the credential was issued:

| Issuance format | QR payload | Why |
|---|---|---|
| `data-integrity` (JSON-LD VC) | **Bare PixelPass** — `JSON → CBOR → zlib(level 9) → Base45`, no prefix | The compressed payload still fits a standard QR (~1KB from ~3KB). Bare = no `OPENCRED1:` or any other application header, matching `@mosip/pixelpass`'s own default (`generateQRData(data)`). |
| `vc-jwt` / `sd-jwt-vc` | **Raw token verbatim** — `eyJ…` (or `eyJ…~disclosure~`) embedded as-is | JWTs are already small and base64url-encoded; further compression doesn't help and would force scanners to decompress before doing the real cryptographic check. |

There is no version prefix, no application namespace, no QR wrapper. Whatever a QR scanner reads from the image is exactly what `POST /v1/credentials/verify` accepts as the `credential` string. This is deliberate — it keeps OpenCred QR data interoperable with the wider MOSIP / Inji verifier toolchain (which calls `@mosip/pixelpass.decode()` with no prefix-stripping step).

### Decoding the QR payload

Once a scanner returns the QR's text payload, three lines tell you which branch you're on:

```
starts with `{`           → JSON-LD VC, already verifiable
starts with `eyJ…`        → vc-jwt or sd-jwt-vc, already verifiable
otherwise                 → bare PixelPass — decode through `@mosip/pixelpass.decode()`
                              to recover the JSON-LD VC, then verify
```

The Docker server and the desktop app perform this detection automatically — you don't need to classify it yourself before sending. The format-detection module (`@opencred/shared`'s `detectCredentialInputFormat`) tries the cheap pattern checks first (`{`, `~`, `header.payload.signature`) and falls back to a PixelPass try-decode if none match.

### Verifying a scanned QR

#### Option 1 — HTTP API

Pass the raw QR text through verbatim:

```bash
# QR_TEXT is whatever your scanner returned — JWT, SD-JWT, or bare PixelPass.
jq -n --arg cred "$QR_TEXT" '{credential: $cred}' | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @-
```

#### Option 2 — CLI

```bash
echo "$QR_TEXT" | docker run --rm -i opencred:bootcamp verify --input -
```

#### Option 3 — Verify SDK (Node / browser)

```js
import { createVerifier } from "@opencred/verify";

const verifier = createVerifier();
const result = await verifier(qrText);   // accepts JWT, SD-JWT, or bare PixelPass
console.log(result.verified, result.code, result.checks);
```

#### Option 4 — Any MOSIP / Inji-compatible verifier

OpenCred QR data follows the MOSIP PixelPass convention with no extra wrapping. Any toolchain that already handles MOSIP-style QRs — including Inji Verify and direct callers of `@mosip/pixelpass.decode()` — accepts an OpenCred QR with no special handling. The bare-PixelPass interop note is intentional: see the rationale in `apps/server/src/packaging/qr-generator.ts`.

### Manual decode (debugging / when you don't have OpenCred installed)

For triage when you have a QR text and need to inspect the credential without running the verifier:

```js
import { decode } from "@mosip/pixelpass";

// `qrText` is the bare Base45 payload your scanner returned.
const credentialJson = decode(qrText);     // → JSON string
const credential = JSON.parse(credentialJson);
console.log(credential.issuer, credential.credentialSubject);
```

Or with `node-base45` + `pako` + a CBOR decoder if you prefer not to pull in the MOSIP library. The pipeline is exactly `Base45 → zlib inflate → CBOR decode → UTF-8 JSON`.

> **What QR decode does *not* do.** Decoding only recovers the credential payload. The cryptographic signature check, issuer DID resolution, revocation lookup, and date checks all still need to run — use one of the four options above. A successfully-decoded QR is not, on its own, evidence the credential is valid.

### QR verification on a printed PDF

OpenCred PDFs carry the credential in two places: the visible QR and the PDF info-dictionary (`OpenCredCredential` key). Both contain the same bare PixelPass payload, so either path verifies. The PDF-as-upload route (`Content-Type: application/pdf`) is the cleanest end-to-end check — no QR scanner required. See [Branch 2 — PDF upload](../docker/api-reference.md#post-v1credentialsverify) in the API reference.

## CLI

The Docker image ships an `opencred` CLI for offline verification — no long-running server needed.

```bash
# JWT compact from stdin (use `--input -`):
echo "$JWT" | docker run --rm -i opencred:bootcamp verify --input -

# JSON-LD VC from a file:
docker run --rm -v "$PWD/my-credential.json:/in.json:ro" \
  opencred:bootcamp verify --input /in.json

# PDF from a file:
docker run --rm -v "$PWD/my-credential.pdf:/in.pdf:ro" \
  opencred:bootcamp verify --input /in.pdf

# Pass `--json` for machine-readable output, or `--csca-trust-store <dir>`
# for DSC chain validation.
```

Exit code is `0` on `valid: true`, non-zero otherwise. Result JSON goes to stdout. Format detection is automatic. To wire up DeDi or a CSCA trust store, pass the same `OPENCRED_*` env vars via `-e`. See [`CLI reference`](cli-reference.md) for the full command surface.

## Library

> **Most callers should use [`@opencred/verify`](#verifier-path-2--library-embedded-in-your-own-service) instead.** It bundles `@opencred/verification`, `@opencred/did`, and `@opencred/dedi-client` behind a single `createVerifier()` entry point and ships as one published artefact. The unwrapped API below is what `@opencred/verify` is built on — use it directly when you need to swap out the DID resolver, plug in a custom verification step, or work inside this monorepo where the workspace packages are already available.

For embedding in a Node service without the SDK wrapper, install `@opencred/verification` and wire it directly:

```ts
import { verifyCredential, verifyPdf } from "@opencred/verification";
import {
  DIDKeyResolver,
  DIDJwkResolver,
  DIDWebResolver,
  CompositeDIDResolver,
} from "@opencred/did";

const resolver = new CompositeDIDResolver(new Map([
  ["key", new DIDKeyResolver()],
  ["jwk", new DIDJwkResolver()],
  ["web", new DIDWebResolver()],
]));

const result = await verifyCredential(jwtOrJsonLd, { didResolver: resolver });
// result.verified: boolean
// result.code:     "VALID" | "INVALID" | "EXPIRED" | "REVOKED" | "UNRESOLVABLE" | "CONTEXT_MISSING"
// result.checks:   Array<{ name, passed, detail? }>
```

For PDFs, call `verifyPdf(uint8array, config)`. The `config` object accepts `trustAnchors` (PEM array) for DSC validation and `dediClient` (from `@opencred/dedi-client`) for revocation and did:web fallback.

## What gets checked

These are the `name` literals that appear in `result.checks[].name`:

| Check `name` | Validates | When it runs |
|---|---|---|
| `signature` | Cryptographic signature against the issuer's public key (resolved from the DID). Also detects tampering of the credential body or of the JSON-LD `@context` / schema references (those changes invalidate the signed canonical form). | Always |
| `vc-jwt-claims` | The JWT envelope claims (`iss`, `jti`, `nbf`, `exp`, `iat`, `vc`) are well-formed and consistent with the embedded credential. | When the credential is a vc-jwt |
| `vct` | The sd-jwt-vc `vct` (credential type) matches the expected type when one is asserted by the caller. | When the credential is sd-jwt-vc |
| `date` | The credential is currently within `validFrom`…`validUntil`. | Always |
| `x509-chain` | DSC chains to a configured CSCA trust anchor. | When the proof carries an `x5c` chain |
| `revocation` | The credential's hash is not in the issuer's revocation registry. | When `credentialStatus` is present AND a DeDi client is configured |
| `pdf-parse`, `pdf-encrypted`, `pdf-embedded-credential`, `pdf-credential-decode` | The PDF parses, isn't encrypted, has an `OpenCredCredential` info-dict entry, and that entry decodes to a valid credential. | When the input is a PDF |

JSON-LD context resolution and JSON Schema validation are enforced at credential **construction time** (issuer-side) — verification surfaces a context-loader failure as `code: "CONTEXT_MISSING"` and never makes a remote fetch; schema conformance is implied by the credential being a faithful copy of what the issuer signed.

## Result codes

| `code` | Meaning |
|---|---|
| `VALID` | All applicable checks passed. |
| `INVALID` | Signature, claim shape, or proof config rejected. Almost always means tampering or wrong key. |
| `EXPIRED` | Outside the `validFrom`…`validUntil` window. The credential was valid once. |
| `REVOKED` | Issuer published a revocation hash for this credential's UUID. |
| `UNRESOLVABLE` | Could not resolve the issuer DID. did:web is offline, did:key fragment was passed where the base DID was expected. |
| `CONTEXT_MISSING` | JSON-LD context not in the bundled document loader. Verification is fail-closed — remote fetch is never performed. |

## Trust-model configuration

Out of the box, verifying credentials signed by `did:key` or `did:jwk` issuers needs **zero** configuration. For everything else:

| Issuer signed using… | Verifier needs… | Env var |
|---|---|---|
| `did:key` / `did:jwk` | Nothing. Default. | — |
| `did:web` (public HTTPS) | Outbound HTTPS to the issuer's domain. SSRF-guarded: private IPs rejected, HTTPS only, no redirects, 10s timeout. | — |
| `did:web` (published only to DeDi) | DeDi client configured on the verifier — `DIDWebResolver` falls back to DeDi's `public_key_registry` when canonical HTTPS fails. | `OPENCRED_DEDI_*` (see [Using DeDi for verification](#using-dedi-for-verification)) |
| DSC (Document Signer Certificate) with X.509 chain | PEM bundle of trusted CSCA anchors | `OPENCRED_CSCA_TRUST_STORE_PATH` |
| Issuer publishes revocation hashes to DeDi | DeDi client configured | `OPENCRED_DEDI_*` |

These env vars are read at container startup. Restart after changing them.

## Using DeDi for verification

DeDi (the Decentralized Directory) plays three roles in verification. None are required — `did:key` credentials verify with zero infrastructure — but when the issuer chose to publish to DeDi, the verifier needs to be aware.

### What DeDi adds

| DeDi registry | What the verifier uses it for | Without DeDi… |
|---|---|---|
| `public_key_registry` | Resolve `did:web:<host>` via DeDi instead of (or in addition to) `.well-known/did.json` | did:web resolution is HTTPS-only. If the issuer's domain is down, the resolver returns `UNRESOLVABLE`. |
| `vc-revocation-registry` | Check whether a credential has been revoked | The revocation check is **silently skipped**. Credentials with `credentialStatus` still verify as `VALID` because the verifier can't query the registry. |
| `schema_registry` / `context_registry` | Reserved for future use; schemas and contexts are bundled today. | (Currently unused at verification time.) |

### Configuring the verifier for DeDi

Set four env vars on the verifier container:

```bash
docker run -d --name opencred \
  -e OPENCRED_API_KEY="$OPENCRED_API_KEY" \
  -e OPENCRED_KEY_PATH=/secrets/issuer-key.pem \
  -e OPENCRED_DEDI_BASE_URL="https://your-dedi-instance.example.org" \
  -e OPENCRED_DEDI_AUTH_TYPE="api-key" \
  -e OPENCRED_DEDI_API_KEY="$DEDI_TOKEN" \
  -e OPENCRED_DEDI_NAMESPACE="$DEDI_NAMESPACE" \
  -v "$KEY_PATH:/secrets/issuer-key.pem:ro" \
  -p 3100:3100 \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest
```

For bearer auth, swap `OPENCRED_DEDI_AUTH_TYPE=bearer` plus `OPENCRED_DEDI_EMAIL` / `OPENCRED_DEDI_PASSWORD` instead of the API key.

Confirm DeDi is wired:

```bash
curl -s http://localhost:3100/v1/health | jq .dediConfigured
# expect: true
```

If `dediConfigured: false` after setting the vars, the container failed to authenticate against DeDi at startup. Check `docker logs opencred` for the specific error.

### Revocation lifecycle

What you'll see end-to-end:

1. **Issuance** — the issuer calls `/v1/credentials/issue` with `revocationRegistryUrl` set to their DeDi instance:
   ```json
   {
     "schemaId": "electricity/v1",
     "issuerDid": "did:key:zDna…",
     "credentialSubject": { … },
     "validFrom": "2026-05-15T00:00:00Z",
     "revocationRegistryUrl": "https://your-dedi-instance.example.org",
     "proofFormat": "vc-jwt"
   }
   ```
   OpenCred ≥ 1.4.1 derives the canonical lookup URL automatically — the issued credential gets a `credentialStatus.id` of the form `https://<host>/dedi/lookup/<ns>/vc-revocation-registry/<sha256-of-credential-uuid>`.

2. **Revoke** (issuer-side, requires API key):
   ```bash
   curl -s http://localhost:3100/v1/credentials/revoke \
     -H "Authorization: Bearer $OPENCRED_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"credentialId": "urn:uuid:64a29285-…"}'
   ```

3. **Verify the credential as a third party** — must have DeDi configured:
   ```bash
   jq -n --arg jwt "$JWT" '{credential: $jwt}' | \
     curl -s http://localhost:3100/v1/credentials/verify \
       -H "Authorization: Bearer $OPENCRED_API_KEY" \
       -H "Content-Type: application/json" \
       -d @-
   ```

   Before revocation: `valid: true`, `code: "VALID"`. After: `valid: false`, `code: "REVOKED"`, the `revocation` check is the one that failed. The `signature` check still passes — revocation isn't tampering, it's "the issuer changed their mind."

> **Silent-skip warning.** If the verifier doesn't have DeDi configured, it can't query the revocation registry and skips the check entirely — meaning revoked credentials verify as `VALID`. The response shows two checks instead of three. In production deployments that issue with `credentialStatus`, configure DeDi on every verifier or your tamper-evidence guarantee leaks for the revocation case.

### did:web fallback via DeDi

When an issuer publishes their DID document to DeDi's `public_key_registry` and also serves a canonical `.well-known/did.json`, verification uses HTTPS by default and DeDi is the fallback if HTTPS fails.

When the issuer publishes **only** to DeDi (no .well-known endpoint), the verifier *must* have DeDi configured — otherwise canonical HTTPS resolution fails and the verifier returns `UNRESOLVABLE`. Mechanism: when `OPENCRED_DEDI_*` is set, the server wires `createDeDiDIDWebFallback(dediClient)` as the resolver's fallback function. On HTTPS failure, the resolver consults DeDi's `public_key_registry` for a record matching the input DID.

### Inspecting DeDi records directly

When debugging "why does this credential return `UNRESOLVABLE` / `REVOKED`?", you can hit DeDi by hand:

```bash
# Look up a DID's published document in the public_key_registry:
DID="did:web:issuer.example.org"
DID_HASH=$(echo -n "$DID" | shasum -a 256 | cut -d' ' -f1)
curl -s "https://your-dedi-instance.example.org/dedi/lookup/$NAMESPACE/public_key_registry/$DID_HASH"

# Look up a credential's revocation status:
CRED_UUID="urn:uuid:64a29285-a56e-4db2-b491-467983c1405c"
HASH=$(echo -n "${CRED_UUID#urn:uuid:}" | shasum -a 256 | cut -d' ' -f1)
curl -s "https://your-dedi-instance.example.org/dedi/lookup/$NAMESPACE/vc-revocation-registry/$HASH"
```

A `404` means the record isn't in DeDi — for the public-key registry that means the issuer didn't publish there; for the revocation registry that means the credential hasn't been revoked. An `active` state on the revocation registry means **revoked**.

### Operational notes

- **No client-side cache** by default — every revocation check is a round trip. For high-throughput verifiers, wrap `DeDiClient` with a short-TTL cache.
- **Circuit breaker**: `DeDiClient` ships a built-in circuit breaker. If DeDi is repeatedly unreachable, the client fails fast for a short window rather than hammering it. The verify result shows `code: "VALID"` with the `revocation` check missing in this case — same silent-skip semantics as "not configured."
- **SSRF safety**: when DeDi fallback fires for did:web resolution, the resolved IP is still validated. The base DeDi URL itself bypasses this check — make sure `OPENCRED_DEDI_BASE_URL` is a host you trust.

## Offline verification

For `did:key` and `did:jwk` credentials with no revocation status, verification runs **fully offline**:

* The public key is encoded in the DID itself — no network resolution needed.
* JSON-LD contexts are bundled into the image — no remote `@context` fetch in production.
* Schema validation uses the bundled JSON Schema registry.

Useful for air-gapped CI environments, locked-down VPCs, and any case where you want to prove "this credential is valid by math alone, not by network reachability."

## PDF credentials

OpenCred-issued PDF certificates carry the credential in two places: the printed QR on the page, and a copy embedded in the PDF's info-dictionary metadata under the key `OpenCredCredential`. The verifier reads the metadata directly — to verify a freshly-issued OpenCred PDF, just POST the binary PDF to `/v1/credentials/verify` with `Content-Type: application/pdf`.

| PDF shape | Result |
|---|---|
| Freshly issued OpenCred PDF (info-dict embedded) | Extracted from metadata, verified end-to-end |
| Older OpenCred PDF (issued before info-dict embedding shipped) | Clear failure response pointing the caller at the QR-scan path |
| Encrypted PDF | Structured error: "decrypt first, or scan the printed QR" |
| Non-OpenCred PDF | "PDF does not contain an embedded OpenCred credential" |

## The tamper test

The single most convincing demonstration of "why VCs?":

```bash
# Take any valid credential.
ORIG_JWT="eyJhbGciOiJFUzI1Ni…"

# Change one byte of the payload without re-signing.
TAMPERED=$(python3 -c "
import base64, json
jwt = '''$ORIG_JWT'''
h, p, s = jwt.split('.')
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def b64ud(x): return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
payload = json.loads(b64ud(p))
payload['vc']['credentialSubject'] = {'TAMPERED': True}
p_new = b64u(json.dumps(payload, separators=(',', ':')).encode())
print(f'{h}.{p_new}.{s}')
")

# Verify it.
jq -n --arg jwt "$TAMPERED" '{credential: $jwt}' | \
  curl -s http://localhost:3100/v1/credentials/verify \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d @- | jq
```

Result: `valid: false`, `code: "INVALID"`, `signature` check fails. The verifier didn't phone home, didn't query a database, didn't talk to the issuer. The math caught it.

## Debugging failed verifications

The server strips per-check `detail` strings from HTTP responses by design (CLAUDE.md security invariant #5 — don't leak internal config or parser errors to remote callers). To see the detail strings, switch to debug logging:

```bash
docker run -d --name opencred \
  -e OPENCRED_LOG_LEVEL=debug \
  …all your other flags… \
  ghcr.io/nfh-trust-labs/opencred/opencred-server:latest

# Then verify the troublesome credential and tail the logs.
docker logs -f opencred
```

You'll see one structured log line per verify call:

```json
{
  "level": "debug",
  "code": "UNRESOLVABLE",
  "checks": [
    { "name": "signature", "passed": false,
      "detail": "Unable to resolve public key for issuer: did:key:zDna…#zDna…" }
  ],
  "msg": "Credential verification result (detail stripped from HTTP response)"
}
```

Common diagnostic strings:

| `detail` substring | Likely cause | Fix |
|---|---|---|
| `Unable to resolve public key for issuer` | DID fragment passed where base DID expected, OR did:web unreachable | Use the base DID at issuance time (no `#…` suffix). For did:web, check DNS and the `.well-known/did.json` endpoint. |
| `Unsupported proof type: JsonWebSignature2020` | You sent a JSON-LD envelope wrapping a vc-jwt | Extract `proof.jwt` and send the compact JWT directly. |
| `Invalid JSON-LD syntax; tried to redefine a protected term` | Custom `@context` redefines a W3C term | Switch to `vc-jwt` proof format, or fix the upstream context. |
| `Could not resolve revocation registry` | `credentialStatus.id` URL malformed | Reissue with `revocationRegistryUrl` set to either the canonical lookup shape or a bare base URL (OpenCred ≥ 1.4.1 derives the lookup URL for you). |
| `X.509 chain validation failed` | DSC's chain doesn't reach a configured CSCA anchor | Confirm `OPENCRED_CSCA_TRUST_STORE_PATH` includes the right CSCA root. |

## Common pitfalls

* **Issuer DID with `#` fragment.** `/v1/keys` returns the verification-method DID under `keys[0].id` (e.g. `did:key:zDna…#zDna…`). Strip the fragment before passing as `issuerDid` to `/v1/credentials/issue` — the JWT `iss` claim must be the *base* DID, otherwise verification returns `UNRESOLVABLE`.
* **Data Integrity context conflicts.** Some custom JSON-LD contexts redefine W3C-protected terms. If you hit `Invalid JSON-LD syntax; tried to redefine a protected term`, switch to `vc-jwt` proof format — it doesn't canonicalize JSON-LD so it sidesteps the issue.
* **Silent revocation skip.** If you've configured `credentialStatus` at issuance time but didn't configure DeDi on the verifier, revocation isn't checked — the credential verifies as `VALID` even after revocation. Always configure DeDi on verifiers in production.
