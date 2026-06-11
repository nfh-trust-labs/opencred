# @opencred/verify

Verify W3C Verifiable Credentials issued by OpenCred — from any Node service, with zero issuer-side infrastructure.

Source-available SDK. Works fully offline for `did:key` / `did:jwk` credentials. Optional DeDi integration for revocation checks and `did:web` discovery fallback.

> **Status — v0.1.0 source-available, not yet npm-published.**
> The source and a self-contained bundled artefact (in `dist/`) are
> committed to [`opencred-releases`](https://github.com/nfh-trust-labs/opencred-releases)
> under `sdk/verify/`. To use it right now: see [Install from source](#install-from-source)
> below. The maintainers will publish to npm under `@opencred/verify`
> once the API has stabilized — at that point `npm install` will Just Work.

## Install from source

While the package is not yet on npm, install it directly from the public mirror repository:

```sh
# Option A — clone and link via npm/pnpm/yarn file: spec
git clone https://github.com/nfh-trust-labs/opencred-releases.git
cd your-app
npm install ../opencred-releases/sdk/verify
# (or: pnpm add ../opencred-releases/sdk/verify)

# Option B — install directly from the GitHub URL pointing at a release tag
npm install github:nfh-trust-labs/opencred-releases#main --workspace=sdk/verify
```

The package is built ahead of time: the `dist/` directory committed to the repo contains the bundled, self-contained code. No build step is needed at install time.

Requires Node.js 20 or later. Works in any modern Node runtime — long-running services, AWS Lambda, Cloudflare Workers (with the Node compat flag), Bun, Deno (via `npm:` specifier).

## Quick start — fully offline

The simplest case. No DeDi, no trust anchors, no network calls. Verifies any credential whose issuer is a `did:key` or `did:jwk` (the most common OpenCred default):

```ts
import { createVerifier } from "@opencred/verify";

const verify = createVerifier();

const jwt = "eyJhbGciOiJFUzI1Ni…";  // a vc-jwt compact token
const result = await verify(jwt);

if (result.verified) {
  console.log("✅ valid:", result.code);
} else {
  console.log("❌", result.code, result.checks.find(c => !c.passed));
}
```

The `result.code` is one of: `VALID`, `INVALID`, `EXPIRED`, `REVOKED`, `UNRESOLVABLE`, `CONTEXT_MISSING`.

## Quick start — with DeDi (revocation + did:web fallback)

If your issuer publishes revocation hashes to a DeDi instance, or publishes DID documents via DeDi's `public_key_registry`, configure the SDK with DeDi credentials:

```ts
import { createVerifier } from "@opencred/verify";

const verify = createVerifier({
  dedi: {
    baseUrl: "https://your-dedi-instance.example.org",
    namespace: "your-namespace",
    auth: {
      type: "api-key",
      apiKey: process.env.DEDI_API_KEY!,
    },
  },
});

const result = await verify(jwt);
// `result.checks` now includes a `revocation` row if the credential carries a credentialStatus.
```

For bearer auth, use `auth: { type: "bearer", email, password }` instead.

> **Warning — revocation requires DeDi.** If you issue credentials with `credentialStatus` but don't configure DeDi on the verifier, revocation cannot be checked — revoked credentials will still verify as `VALID` because the verifier has no way to query the registry. The skip is visible in the result: `result.checks` contains a `revocation` row whose `detail` says the check was **NOT** performed. Production verifiers should configure DeDi whenever the issuance flow uses revocation, and strict relying parties can treat that check row as a policy failure.

## Verifying PDF certificates

OpenCred-issued PDF certificates embed the credential in the PDF info-dictionary under the `OpenCredCredential` key. Use the `.pdf` method:

```ts
import { createVerifier } from "@opencred/verify";
import fs from "node:fs/promises";

const verify = createVerifier();
const pdfBytes = await fs.readFile("certificate.pdf");
const result = await verify.pdf(pdfBytes);
```

## DSC-signed credentials (Document Signer Certificates)

If you need to verify credentials signed with a DSC backed by an X.509 chain rooted in a Country Signing Certificate Authority (CSCA), supply the trust anchors as PEM strings:

```ts
const verify = createVerifier({
  trustAnchors: [pem1, pem2, pem3],   // your CSCA roots
});
```

The verifier will validate the credential's `x5c` chain against your anchors and surface the result in the `x509-chain` check.

## API

### `createVerifier(options?)` → `Verifier`

The recommended entry point. Builds a verifier with the given configuration; the returned function (and its `.pdf` method) can be reused across many verifications.

**Options** (all fields optional):

| Field | Type | Purpose |
|---|---|---|
| `dedi` | `DeDiClientConfig` | DeDi connection details for revocation + did:web fallback |
| `trustAnchors` | `string[]` | PEM CSCA roots for DSC chain validation |
| `didResolver` | `DIDResolver` | Override the default composite resolver (did:key + did:jwk + did:web) |
| `logger` | `{ debug, info, warn, error }` | Sink for DeDi operational events |

### `verifier(input)` → `Promise<CredentialVerificationResult>`

Verify a credential. Accepts:

* A **vc-jwt** compact string (`"eyJ…"`).
* An **sd-jwt-vc** compact string (`"eyJ…~…~…~"`).
* A **PixelPass QR data** string — the raw Base45 payload of an OpenCred-issued QR (no prefix; what `@mosip/pixelpass.decode()` consumes).
* A **JSON-LD VC** object (with `proof.type === "DataIntegrityProof"`).

### `verifier.pdf(pdfBytes)` → `Promise<CredentialVerificationResult>`

Verify a credential embedded in an OpenCred-issued PDF. Extracts the embedded credential from the PDF info-dictionary, then routes through `verifyCredential`.

### `verifyCredential(input, options?)`, `verifyPdf(bytes, options?)`

One-shot helpers — equivalent to `createVerifier(options)(...)` but discard the verifier after the call. Use `createVerifier` for repeated verifications; use these for incidental ones.

### `detectFormat(input)` → `CredentialFormat`

Returns the detected wire format without verifying. Useful for routing. The `CredentialFormat` union is `"data-integrity" | "vc-jwt" | "sd-jwt-vc" | "jws"`. For PDF inputs and PixelPass QR data strings, the SDK decodes them before reaching `detectFormat` — call `verifyPdf` directly for PDFs, and pass the QR string straight to `verify(input)` to let the SDK route internally.

## Result shape

```ts
type CredentialVerificationResult = {
  verified: boolean;
  code: "VALID" | "INVALID" | "EXPIRED" | "REVOKED" | "UNRESOLVABLE" | "CONTEXT_MISSING";
  checks: Array<{
    name: string;       // "signature" | "vc-jwt-claims" | "date" | "revocation" | "x509-chain" | ...
    passed: boolean;
    detail?: string;    // diagnostic string when the check failed
  }>;
};
```

The set of checks depends on the credential's shape:

| Check | When it runs |
|---|---|
| `signature` | Always |
| `vc-jwt-claims` or `data-integrity-proof-config` | Always (proof-format-appropriate) |
| `envelope-consistency` | When the input is the vc-jwt JSON envelope (`proof: { type: "JsonWebSignature2020", jwt }` — the shape OpenCred PDF/QR/JSON exports carry). Confirms the outer display fields match the signed token; a tampered display copy fails here. |
| `date` | Always |
| `x509-chain` | When the proof carries an `x5c` chain |
| `revocation` | When `credentialStatus` is present AND DeDi is configured; when `credentialStatus` is present WITHOUT DeDi, a non-failing row records that revocation was **not** checked |
| `pdf-*` | When the input is a PDF |

## Trust model

| Issuer DID method | Verifier needs |
|---|---|
| `did:key` / `did:jwk` | Nothing. The public key is encoded in the DID. |
| `did:web` (public HTTPS) | Outbound HTTPS to the issuer's domain. SSRF-protected. |
| `did:web` (DeDi-only) | DeDi configured on the SDK. The DID resolver falls back to DeDi's `public_key_registry`. |
| DSC (X.509 chain) | CSCA `trustAnchors` configured on the SDK. |

## License

See [`LICENSE`](./LICENSE) and the project-wide [`NOTICE.md`](../../NOTICE.md) for full terms. Installation and use in your own services for verifying OpenCred-issued credentials is permitted; redistribution as a separate package, modification, or use in commercial production deployments serving third parties requires prior written permission from NFH Trust Labs.

## Project

Source: [github.com/nfh-trust-labs/opencred-releases](https://github.com/nfh-trust-labs/opencred-releases) under `sdk/verify/`.

Issues and questions: [opencred-releases/issues](https://github.com/nfh-trust-labs/opencred-releases/issues).

The verification engine and DID resolvers wrapped by this SDK are developed in a private monorepo (`nfh-trust-labs/opencred`) and bundled into the published artefact. Nothing else is fetched at install or runtime — the `dist/` directory is the complete, self-contained code.
