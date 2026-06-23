# Server API Reference

This document covers all HTTP endpoints exposed by the OpenCred server (Docker image). Every endpoint is mounted under both `/` (legacy) and `/v1/` (canonical). New consumers should target the `/v1` prefix.

The server is built on [Hono](https://hono.dev/) and runs on Node.js. Source code is in `apps/server/src/routes/`.

## Authentication

Protected endpoints require a Bearer token set via the `OPENCRED_API_KEY` environment variable:

```
Authorization: Bearer <OPENCRED_API_KEY>
```

Authentication is **fail-closed by default**. The server refuses to start unless `OPENCRED_API_KEY` is set or `OPENCRED_DEV_MODE_NO_AUTH=true` is explicitly opted into (local development only; refused when `NODE_ENV=production`).

Generate a token:

```bash
openssl rand -base64 32
```

**Public paths** (no auth required): `GET /health`, `GET /v1/health`, `GET /metrics`, `GET /v1/metrics`.

## Error Format

All errors follow this envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable description",
    "details": []
  }
}
```

Common error codes:

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request body failed Zod parsing or contained forbidden key material |
| `SCHEMA_VALIDATION_ERROR` | 400 | `credentialSubject` did not match the JSON Schema |
| `AUTHENTICATION_ERROR` | 401 | Missing, malformed, or invalid Bearer token |
| `NOT_FOUND` | 404 | Endpoint or resource not found |
| `JOB_RUNNING` | 409 | Batch job still in progress |
| `CRYPTO_ERROR` | 500 | Signing or proof construction failed |
| `DID_RESOLUTION_ERROR` | 500 | DID could not be resolved |
| `DEDI_NOT_CONFIGURED` | 503 | DeDi integration not configured (revocation endpoints) |
| `INTERNAL_ERROR` | 500 | Unhandled error (original message logged, not returned) |

## Security: Key Material Rejection

Every POST endpoint runs `rejectKeyMaterial()` on the request body before any other processing. This recursive check throws `400 VALIDATION_ERROR` if:

- Any JSON key matches a forbidden name (`privateKey`, `private_key`, `privateKeyJwk`, `privateKeyPem`, `pkcs8`, `pkcs12`, `pfx`, `p12`, `keyMaterial`, `key_material`)
- Any string value matches a PEM private key header (`-----BEGIN ... PRIVATE KEY-----`)

This is a defense-in-depth measure. OpenCred never accepts private key material via the HTTP API.

---

## Endpoints

### GET /v1/health

Health and readiness probe. Always public -- no authentication required.

**Response `200 OK`** (signing key loaded, server ready):

```json
{
  "status": "ok",
  "ready": true,
  "signingKeyLoaded": true,
  "dediConfigured": false,
  "didAutoPublished": false,
  "timestamp": "2026-04-13T10:00:00.000Z"
}
```

**Response `503 Service Unavailable`** (signing key not loaded):

```json
{
  "status": "ok",
  "ready": false,
  "signingKeyLoaded": false,
  "dediConfigured": false,
  "didAutoPublished": false,
  "timestamp": "2026-04-13T10:00:00.000Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"ok"` if the process is running |
| `ready` | boolean | `true` when the signing key is loaded |
| `signingKeyLoaded` | boolean | Whether a signer was loaded at startup |
| `dediConfigured` | boolean | Whether a DeDi client is configured |
| `didAutoPublished` | boolean | `true` when the issuer DID was auto-published to DeDi at startup (via `OPENCRED_AUTO_PUBLISH_KEY=true` or `OPENCRED_DEDI_HOST_DID_DOC=true` for did:web). Stays `false` when the flag is off, when the publish failed (warn-logged, non-blocking), or when DeDi is not configured. An already-published DID is also reported as `true` (the idempotent skip path is treated as success). |
| `timestamp` | string | ISO-8601 server timestamp |

**Example:**

```bash
curl -s http://localhost:3100/v1/health
```

Source: `apps/server/src/routes/health.ts`

---

### GET /v1/metrics

Prometheus metrics in text format. Always public -- no authentication required.

**Response `200 OK`:**

Returns Prometheus text exposition format with `Content-Type: text/plain`.

Exposed metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `http_requests_total` | Counter | method, path, status | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | method, path, status | Request duration |
| `opencred_credentials_issued_total` | Counter | proof_format, schema_id | Credentials issued |
| `opencred_credentials_verified_total` | Counter | result | Credentials verified |
| `opencred_batch_jobs_total` | Counter | status | Batch jobs (started/completed/cancelled/failed) |
| `opencred_revocations_published_total` | Counter | -- | Revocation hashes published to DeDi |

Plus Node.js default metrics (heap, event loop, GC, etc.) from `prom-client`.

**Example:**

```bash
curl -s http://localhost:3100/v1/metrics
```

Source: `apps/server/src/routes/metrics.ts`, `apps/server/src/metrics.ts`

---

### GET /v1/keys

Returns metadata about the configured signing key. Never returns private key material, raw public key bytes, or filesystem paths.

**Auth:** Required.

**Response `200 OK`** (key configured):

```json
{
  "keys": [
    {
      "id": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
      "fingerprint": "d6f4e2c9b7a8...e1f0",
      "algorithm": "P-256",
      "type": "software",
      "hasCertificateChain": false,
      "label": "server-key",
      "source": "software-file"
    }
  ]
}
```

**Response `200 OK`** (no key configured):

```json
{
  "keys": [],
  "message": "No signing key configured. Set OPENCRED_KEY_PATH or a Cloud HSM provider."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `keys[].id` | string | Verification method DID (did:key or did:jwk) |
| `keys[].fingerprint` | string | SHA-256 fingerprint of the public key (hex) |
| `keys[].algorithm` | string | `P-256`, `P-384`, `Ed25519`, `RSA-2048`, `RSA-3072`, or `RSA-4096` |
| `keys[].type` | string | `software`, `pkcs11`, or `os-cert` |
| `keys[].hasCertificateChain` | boolean | Whether an X.509 certificate chain is bound (e.g. from PFX) |
| `keys[].label` | string (optional) | Human-readable label from `OPENCRED_KEY_LABEL` |
| `keys[].source` | string | `software-file`, `aws-kms`, `azure-kv`, or `gcp-kms` |

**Example:**

```bash
curl -s http://localhost:3100/v1/keys \
  -H "Authorization: Bearer $OPENCRED_API_KEY"
```

Source: `apps/server/src/routes/keys.ts`

---

### POST /v1/keys/publish

Publish the active signer's signing key to the DeDi `opencred-key-registry` (status `active`). The server publishes only its own active public key — no key material is accepted from the request body.

**Auth:** Required.

**Request body**

```ts
{
  namespace?: string;        // override OPENCRED_DEDI_NAMESPACE
  hostDidDocument?: boolean; // also embed the did.json snapshot on the key record (did:web only)
}
```

**Response `200 OK`**

```json
{
  "published": true,
  "recordName": "did-web-issuer-example-org--key-0",
  "namespace": "issuer.example.org",
  "keyId": "did:web:issuer.example.org#key-0",
  "didDocumentStored": false
}
```

**Error responses**

| Status | Code | When |
|--------|------|------|
| `400` | `VALIDATION_ERROR` | Body failed Zod parsing, contained a PEM string, or signer doesn't expose `publicKeyJwk`. |
| `409` | `DEDI_RECORD_EXISTS` | This key is already in the registry. Response carries a `hint` pointing at `POST /v1/keys/resolve`. |
| `503` | `DEDI_NOT_CONFIGURED` | DeDi env vars not set. |

Source: `apps/server/src/routes/keys.ts`

---

### POST /v1/keys/rotate

Clean rotation for a `did:web` issuer. Publishes the new key (status `active`) at its own sequential `#key-<newKeyIndex>`, flips the previous key to `rotated`, and regenerates the multi-key `did.json`. Credentials signed by the retired key remain valid — a clean rotation is not a compromise, and the retired key keeps its distinct fragment in `verificationMethod[]` so its credentials still resolve ([#653](https://github.com/nfh-trust-labs/opencred/issues/653) resolved). When DeDi-hosting is enabled the regenerated `did.json` is embedded as the snapshot on the new key's record — there is no separate `did-documents` registry.

**Scope:** `did:web` only. For `did:key`, regenerate the key (produces a new DID).

**Auth:** Required.

**Request body**

```ts
{
  newKeyIndex: number;                 // sequential index of the NEW key, e.g. 1
  previousVerificationMethod?: string; // the key being retired, e.g. "did:web:issuer.example.org#key-0"
  currentDidDocument?: Record<string, unknown>; // the issuer's CURRENT did.json (existing key set)
  namespace?: string;
  hostDidDocument?: boolean;           // embed the regenerated did.json on the new key record
}
```

**Response `200 OK`**

```json
{
  "rotated": true,
  "did": "did:web:issuer.example.org",
  "currentKeyId": "did:web:issuer.example.org#key-1",
  "newKeyIndex": 1,
  "retired": {
    "changed": true,
    "keyId": "did:web:issuer.example.org#key-0",
    "from": "active",
    "to": "rotated",
    "namespace": "issuer.example.org"
  },
  "didDocument": { "id": "did:web:issuer.example.org", "verificationMethod": ["..."] },
  "didDocumentStored": true
}
```

**Error responses**

| Status | Code | When |
|--------|------|------|
| `400` | `VALIDATION_ERROR` | No active signer or signer doesn't expose `publicKeyJwk`. |
| `400` | `KEY_METHOD_MISMATCH` | Active signer DID is `did:key:` — regenerate instead. |
| `400` | `NO_CURRENT_DOCUMENT` | No `currentDidDocument` supplied and none projectable from the per-key snapshots. |
| `400` | `DID_MISMATCH` | Supplied `currentDidDocument` is for a different DID. |
| `403` | `READ_ONLY_MODE` | Replica running with `OPENCRED_READ_ONLY=true`. |
| `409` | `KEY_INDEX_TAKEN` | `#key-<newKeyIndex>` is already present in the current `did.json`. |
| `503` | `DEDI_NOT_CONFIGURED` | DeDi env vars not set. |

Source: `apps/server/src/routes/keys.ts`

---

### POST /v1/keys/revoke

Revoke a signing key — flips its `opencred-key-registry` status to `revoked`. Every credential that key ever signed will be rejected by DeDi-aware verifiers. Use only for key compromise. Optionally regenerates the `did.json` (revoked key dropped from relationships but kept in `verificationMethod[]`); there is no separate `did-documents` registry.

**Auth:** Required.

**Request body**

```ts
{
  verificationMethod: string;  // e.g. "did:web:issuer.example.org#key-0"
  currentDidDocument?: Record<string, unknown>; // the issuer's CURRENT did.json
  namespace?: string;
  hostDidDocument?: boolean;   // regenerate did.json with the key de-authorized (did:web only)
}
```

**Response `200 OK`**

```json
{
  "revoked": true,
  "changed": true,
  "keyId": "did:web:issuer.example.org#key-0",
  "from": "active",
  "to": "revoked",
  "namespace": "issuer.example.org",
  "didDocument": { "id": "did:web:issuer.example.org", "verificationMethod": ["..."] },
  "didDocumentRegenerated": true
}
```

**Error responses**

| Status | Code | When |
|--------|------|------|
| `400` | `VALIDATION_ERROR` | Body failed Zod or `verificationMethod` is empty. |
| `403` | `READ_ONLY_MODE` | Replica running with `OPENCRED_READ_ONLY=true`. |
| `503` | `DEDI_NOT_CONFIGURED` | DeDi env vars not set. |

Source: `apps/server/src/routes/keys.ts`

---

### POST /v1/keys/resolve

Resolve a signing key's record from the DeDi `opencred-key-registry`. Returns the full `KeyRecord` including current `status` (`active`, `rotated`, or `revoked`).

> **Breaking change.** Previously accepted `{ did }` and returned a DID-document record. Now accepts `{ verificationMethod }` and returns a per-key `KeyRecord`. DID Document resolution is served via `GET /v1/keys/did-document`.

**Auth:** Required.

**Request body**

```ts
{
  verificationMethod: string;  // e.g. "did:web:issuer.example.org#key-0"
  namespace?: string;
}
```

**Response `200 OK`**

```json
{
  "keyId": "did:web:issuer.example.org#key-0",
  "controllerDid": "did:web:issuer.example.org",
  "algorithm": "P-256",
  "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "purpose": ["assertionMethod"],
  "status": "active"
}
```

`status` is `"active"`, `"rotated"` (cleanly retired — credentials remain valid), or `"revoked"` (compromised — all credentials rejected). The record may also carry an optional `document` (the immutable `did.json` snapshot for the key's era, did:web + DeDi-hosting only) and a `proof` (CORD anchor) block.

A `GET /v1/keys/resolve?verificationMethod=...&namespace=...` variant exists for CDN-cacheable reads.

**Error responses**

| Status | Code | When |
|--------|------|------|
| `400` | `VALIDATION_ERROR` | Missing or invalid `verificationMethod`. |
| `503` | `DEDI_NOT_CONFIGURED` | DeDi env vars not set. |

Source: `apps/server/src/routes/keys.ts`

---

### GET /v1/schemas

List available credential schemas. Supports optional `?category=` query parameter to filter by schema category.

**Auth:** Required.

**Response `200 OK`:**

```json
{
  "schemas": [
    {
      "id": "functional-identity/v1",
      "version": "1.0.0",
      "contextUrl": "https://opencred.org/contexts/functional-identity/v1",
      "source": { "name": "opencred", "version": "1.0.0" },
      "category": "identity"
    },
    {
      "id": "electricity/v1",
      "version": "1.0.0",
      "contextUrl": "https://opencred.org/contexts/electricity/v1",
      "source": { "name": "opencred", "version": "1.0.0" },
      "category": "utility"
    },
    {
      "id": "ies/electricity-credential/v1.2",
      "version": "1.2.0",
      "source": { "kind": "referenced", "upstreamOwner": "India Energy Stack", "upstreamLicense": "MIT" },
      "category": "utility"
    },
    {
      "id": "ies/meter-data-credential/v0.6",
      "version": "0.6.0",
      "source": { "kind": "referenced", "upstreamOwner": "India Energy Stack", "upstreamLicense": "MIT" },
      "category": "utility"
    }
  ]
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/schemas \
  -H "Authorization: Bearer $OPENCRED_API_KEY"

# Filter by category
curl -s "http://localhost:3100/v1/schemas?category=education" \
  -H "Authorization: Bearer $OPENCRED_API_KEY"
```

Source: `apps/server/src/routes/schemas.ts`

---

### GET /v1/schemas/:id

Get a specific schema definition by ID. Schema IDs may contain slashes (e.g. `traceability/commercial-invoice/v1`).

**Auth:** Required.

**Response `200 OK`:**

```json
{
  "id": "functional-identity/v1",
  "version": "1.0.0",
  "schema": {
    "$id": "https://opencred.org/schemas/functional-identity/v1",
    "type": "object",
    "properties": {
      "name": { "type": "string" },
      "dateOfBirth": { "type": "string", "format": "date" },
      "nationality": { "type": "string" }
    },
    "required": ["name"]
  },
  "contextUrl": "https://opencred.org/contexts/functional-identity/v1",
  "source": { "name": "opencred", "version": "1.0.0" },
  "category": "identity"
}
```

**Error `404 NOT_FOUND`:**

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Schema not found: unknown-schema/v1"
  }
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/schemas/functional-identity/v1 \
  -H "Authorization: Bearer $OPENCRED_API_KEY"
```

Source: `apps/server/src/routes/schemas.ts`

---

### POST /v1/schemas/generate

Generate a JSON Schema from a set of fields. Useful for ad-hoc credential types that do not use a bundled schema.

**Auth:** Required.

**Request body:**

```json
{
  "fields": {
    "name": "Jane Doe",
    "age": 30,
    "active": true
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fields` | object | Yes | Key-value pairs from which to infer a JSON Schema |

**Response `200 OK`:**

```json
{
  "schema": {
    "type": "object",
    "properties": {
      "name": { "type": "string" },
      "age": { "type": "number" },
      "active": { "type": "boolean" }
    }
  },
  "fields": {
    "name": "Jane Doe",
    "age": 30,
    "active": true
  }
}
```

**Error `400 VALIDATION_ERROR`:**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Body must include a fields object"
  }
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/schemas/generate \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "employeeName": "John Smith",
      "department": "Engineering",
      "startDate": "2025-03-01"
    }
  }'
```

Source: `apps/server/src/routes/schemas.ts`

---

### POST /v1/credentials/issue

Build, validate, and sign a Verifiable Credential. The signing key is loaded at startup and never leaves the server -- the request provides only the public credential payload.

**Auth:** Required.

**Request body:**

```json
{
  "schemaId": "functional-identity/v1",
  "issuerDid": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
  "credentialSubject": {
    "name": "Jane Doe",
    "dateOfBirth": "1990-01-15",
    "nationality": "US"
  },
  "validFrom": "2026-01-01T00:00:00Z",
  "validUntil": "2031-01-01T00:00:00Z",
  "proofFormat": "vc-jwt",
  "subjectDid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "packageFormats": ["qr-png", "json"],
  "customization": {
    "primaryColor": "#1a56db",
    "issuerDisplayName": "Acme University"
  }
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `schemaId` | string | Yes | -- | Schema ID from the registry (use `GET /v1/schemas` to list) |
| `issuerDid` | string | Yes | -- | Issuer DID |
| `credentialSubject` | object | Yes | -- | Credential claims, validated against the schema |
| `validFrom` | string (ISO 8601) | Yes | -- | Start of validity period |
| `validUntil` | string (ISO 8601) | No | -- | End of validity period |
| `proofFormat` | enum | No | `vc-jwt` | `vc-jwt`, `data-integrity`, or `sd-jwt-vc` |
| `additionalTypes` | string[] | No | -- | Extra credential type URIs |
| `subjectDid` | string | No | -- | Subject DID (set as `credentialSubject.id`) |
| `selectiveDisclosureClaims` | string[] | No | -- | Claims for SD-JWT-VC selective disclosure |
| `revocationRegistryUrl` | URL | No | -- | DeDi revocation registry URL |
| `credentialSchemaUrl` | URL | No | -- | External JSON Schema URL for `credentialSchema` |
| `packageFormats` | string[] | No | -- | `qr-png`, `qr-svg`, `pdf`, `json`, `json-compact` |
| `customization` | object | No | -- | Branding customization (see [Credential Customization](credential-customization.md)) |

**Response `200 OK`** (JSON credential):

```json
{
  "credential": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    "validFrom": "2026-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "name": "Jane Doe",
      "dateOfBirth": "1990-01-15",
      "nationality": "US"
    },
    "proof": {
      "type": "JsonWebSignature2020",
      "jwt": "eyJhbGciOiJFUzI1NiIs..."
    }
  },
  "proofFormat": "vc-jwt",
  "isCompactToken": false,
  "packagedOutputs": [
    {
      "format": "qr-png",
      "data": "iVBORw0KGgo...",
      "mimeType": "image/png",
      "suggestedFileName": "credential-qr.png",
      "encoding": "base64"
    },
    {
      "format": "json",
      "data": "{\"@context\":[...]}",
      "mimeType": "application/ld+json",
      "suggestedFileName": "credential.json",
      "encoding": "utf-8"
    }
  ]
}
```

**Response `200 OK`** (SD-JWT-VC compact token):

```json
{
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJ2Y3QiOi...~WyJzYWx0IiwibmFtZSIsIkphbmUgRG9lIl0~",
  "proofFormat": "sd-jwt-vc",
  "isCompactToken": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `credential` | object or string | Signed credential. Object for vc-jwt/data-integrity; compact string for sd-jwt-vc |
| `proofFormat` | string | The proof format used |
| `isCompactToken` | boolean | `true` only for sd-jwt-vc |
| `packagedOutputs` | array (optional) | Present when `packageFormats` was specified and credential is not a compact token |

**Notes:**

- `data-integrity` proofs require ECDSA (P-256, P-384) or Ed25519. RSA keys return `500 CRYPTO_ERROR`.
- `packagedOutputs` is only included when `packageFormats` is specified and the credential is not a compact token.
- The `credentialSubject` is validated against the JSON Schema bound to `schemaId`. Invalid fields return `400 SCHEMA_VALIDATION_ERROR`.

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 400 | `VALIDATION_ERROR` | Zod parsing failed, forbidden key detected, or PEM string found |
| 400 | `SCHEMA_VALIDATION_ERROR` | `credentialSubject` did not match the schema |
| 401 | `AUTHENTICATION_ERROR` | Missing or invalid Bearer token |
| 500 | `CRYPTO_ERROR` | `data-integrity` requested with RSA key |
| 500 | `INTERNAL_ERROR` | Unhandled error |

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/issue \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "schemaId": "functional-identity/v1",
    "issuerDid": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    "credentialSubject": {
      "name": "Jane Doe",
      "dateOfBirth": "1990-01-15",
      "nationality": "US"
    },
    "validFrom": "2026-01-01T00:00:00Z",
    "proofFormat": "vc-jwt"
  }'
```

Source: `apps/server/src/routes/credentials.ts`

---

### POST /v1/credentials/verify

Verify a signed Verifiable Credential. Accepts JSON-LD credentials (data-integrity), compact JWTs (vc-jwt), SD-JWT-VC tokens, and PixelPass-encoded QR data. The format is auto-detected.

**Auth:** Required.

**Request body:**

```json
{
  "credential": "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"did:key:zDnae...\",\"proof\":{\"type\":\"DataIntegrityProof\",\"proofValue\":\"z3M...\"}}"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential` | string | Yes | The credential as a JSON string, compact JWT, SD-JWT-VC token, or PixelPass-encoded data |

**Response `200 OK`:**

```json
{
  "valid": true,
  "code": "VALID",
  "message": "Credential is valid.",
  "checks": [
    { "name": "signature", "passed": true },
    { "name": "date", "passed": true }
  ]
}
```

For an invalid credential:

```json
{
  "valid": false,
  "code": "INVALID",
  "message": "Verification failed.",
  "checks": [
    { "name": "signature", "passed": false }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | `true` if every check passed |
| `code` | string | `VALID`, `REVOKED`, `EXPIRED`, `INVALID`, `UNRESOLVABLE`, or `CONTEXT_MISSING` |
| `message` | string | `"Credential is valid."` or `"Verification failed."` |
| `checks` | array | Each entry has `name` (string) and `passed` (boolean). No `detail` field -- stripped for security |

The endpoint returns `200 OK` even for invalid credentials. Inspect `valid` or `code` for the trust decision. HTTP 4xx/5xx means verification could not run at all.

DID resolution covers `did:key`, `did:jwk`, and `did:web`. For credentials with X.509 certificate chains, set `OPENCRED_CSCA_TRUST_STORE_PATH` to enable trust anchor validation.

**Error responses:**

| Status | Code | When |
|--------|------|------|
| 400 | `VALIDATION_ERROR` | Missing `credential` field or forbidden key material detected |
| 400 | `BAD_REQUEST` | Unrecognized credential format |
| 401 | `AUTHENTICATION_ERROR` | Missing or invalid Bearer token |
| 500 | `DID_RESOLUTION_ERROR` | DID could not be resolved |
| 500 | `INTERNAL_ERROR` | Unhandled error |

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/verify \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6a2V5Ono..."
  }'
```

Source: `apps/server/src/routes/credentials.ts`

---

### POST /v1/credentials/package

Package an already-signed credential into one or more delivery formats.

**Auth:** Required.

**Request body:**

```json
{
  "credential": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:key:zDnae...",
    "credentialSubject": { "name": "Jane Doe" },
    "proof": { "type": "JsonWebSignature2020", "jwt": "eyJ..." }
  },
  "formats": ["qr-png", "pdf", "json"],
  "customization": {
    "primaryColor": "#1a56db",
    "logoDataUri": "data:image/png;base64,iVBORw0KGgo...",
    "issuerDisplayName": "Acme Corp"
  }
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `credential` | object | Yes | -- | The signed credential object |
| `formats` | string[] | No | `["json"]` | `qr-png`, `qr-svg`, `pdf`, `json`, `json-compact` |
| `customization` | object | No | -- | Branding customization (see [Credential Customization](credential-customization.md)) |

**Response `200 OK`:**

```json
{
  "outputs": [
    {
      "format": "qr-png",
      "data": "iVBORw0KGgo...",
      "mimeType": "image/png",
      "suggestedFileName": "credential-qr.png",
      "encoding": "base64"
    },
    {
      "format": "pdf",
      "data": "JVBERi0xLjQK...",
      "mimeType": "application/pdf",
      "suggestedFileName": "credential.pdf",
      "encoding": "base64"
    },
    {
      "format": "json",
      "data": "{\"@context\":[...]}",
      "mimeType": "application/ld+json",
      "suggestedFileName": "credential.json",
      "encoding": "utf-8"
    }
  ],
  "errors": []
}
```

Binary formats (PDF, QR PNG) are base64-encoded with `encoding: "base64"`. Text formats (JSON, SVG) are returned inline with `encoding: "utf-8"`. Per-format failures are reported in `errors` without failing the whole request.

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/package \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "credential": {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:key:zDnae...","credentialSubject":{"name":"Jane Doe"},"proof":{"type":"JsonWebSignature2020","jwt":"eyJ..."}},
    "formats": ["pdf", "qr-svg"]
  }'
```

Source: `apps/server/src/routes/packaging.ts`

---

### POST /v1/credentials/batch

Start a batch issuance job from CSV data. Returns `202 Accepted` immediately; processing runs in the background. Poll `GET /v1/credentials/batch/:jobId` for progress.

**Auth:** Required.

**Request body:**

```json
{
  "csvContent": "name,degree,institution\nJane Doe,MSc,MIT\nJohn Smith,PhD,Stanford",
  "schemaId": "education/v1",
  "issuerDid": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
  "validFrom": "2026-01-01T00:00:00Z",
  "proofFormat": "vc-jwt",
  "webhookUrl": "https://example.com/webhook/batch-complete",
  "customization": {
    "primaryColor": "#1a56db"
  }
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `csvContent` | string | Yes | -- | CSV file content as a string |
| `schemaId` | string | Yes | -- | Schema ID for validation |
| `issuerDid` | string | Yes | -- | Issuer DID |
| `validFrom` | string (ISO 8601) | Yes | -- | Start of validity |
| `validUntil` | string (ISO 8601) | No | -- | End of validity |
| `proofFormat` | enum | No | `vc-jwt` | `vc-jwt`, `data-integrity`, or `sd-jwt-vc` |
| `additionalTypes` | string[] | No | -- | Extra credential type URIs |
| `revocationRegistryUrl` | URL | No | -- | DeDi revocation registry URL |
| `credentialSchemaUrl` | URL | No | -- | External JSON Schema URL |
| `selectiveDisclosureClaims` | string[] | No | -- | SD-JWT-VC claims |
| `columnMapping` | object | No | -- | Map CSV column headers to schema field names |
| `delimiter` | enum | No | `,` | CSV delimiter: `,`, `;`, or `\t` |
| `webhookUrl` | URL (HTTPS) | No | -- | HTTPS URL for completion notification |
| `customization` | object | No | -- | Branding customization |

Row count is capped by `OPENCRED_BATCH_ROW_LIMIT` (default 1000).

**Response `202 Accepted`:**

```json
{
  "jobId": "a1e7c3f9-4b2d-4f21-8c3a-1f4d7e9b2c01",
  "headers": ["name", "degree", "institution"],
  "validCount": 2,
  "invalidCount": 0,
  "totalCount": 2,
  "webhookUrl": "https://example.com/webhook/batch-complete"
}
```

With parse errors:

```json
{
  "jobId": "a1e7c3f9-4b2d-4f21-8c3a-1f4d7e9b2c01",
  "headers": ["name", "degree", "institution"],
  "validCount": 95,
  "invalidCount": 5,
  "totalCount": 100,
  "parseErrors": [
    { "rowIndex": 3, "errors": ["Missing required field: name"] },
    { "rowIndex": 7, "errors": ["Missing required field: degree"] }
  ]
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/batch \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "csvContent": "name,degree,institution\nJane Doe,MSc,MIT\nJohn Smith,PhD,Stanford",
    "schemaId": "education/v1",
    "issuerDid": "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    "validFrom": "2026-01-01T00:00:00Z"
  }'
```

Source: `apps/server/src/routes/batch.ts`

---

### GET /v1/credentials/batch/:jobId

Get batch job progress. Safe to poll.

**Auth:** Required.

**Response `200 OK`:**

```json
{
  "jobId": "a1e7c3f9-4b2d-4f21-8c3a-1f4d7e9b2c01",
  "total": 100,
  "completed": 50,
  "successCount": 48,
  "errorCount": 2,
  "skippedCount": 0,
  "running": true,
  "cancelled": false
}
```

**Error `404 NOT_FOUND`:**

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Batch job not found: <jobId>"
  }
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/batch/a1e7c3f9-4b2d-4f21-8c3a-1f4d7e9b2c01 \
  -H "Authorization: Bearer $OPENCRED_API_KEY"
```

Source: `apps/server/src/routes/batch.ts`

---

### GET /v1/credentials/batch/:jobId/results

Get per-row results for a completed batch job. Returns `409` if the job is still running.

**Auth:** Required.

**Response `200 OK`:**

```json
{
  "jobId": "a1e7c3f9-4b2d-4f21-8c3a-1f4d7e9b2c01",
  "results": [
    {
      "rowIndex": 0,
      "status": "success",
      "credential": { "@context": ["..."], "type": ["VerifiableCredential"], "proof": {} },
      "isCompactToken": false
    },
    {
      "rowIndex": 1,
      "status": "error",
      "error": "Validation failed: missing required field 'name'"
    }
  ]
}
```

**Error `409 JOB_RUNNING`:**

```json
{
  "error": {
    "code": "JOB_RUNNING",
    "message": "Batch is still running. Check progress first."
  }
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/batch/a1e7c3f9-4b2d-4f21-8c3a-1f4d7e9b2c01/results \
  -H "Authorization: Bearer $OPENCRED_API_KEY"
```

Source: `apps/server/src/routes/batch.ts`

---

### POST /v1/credentials/revocation-hash

Compute the revocation hash for a single credential using JCS canonicalization + SHA-256.

**Auth:** Required.

**Request body:**

```json
{
  "credential": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:key:zDnae...",
    "credentialSubject": { "name": "Jane Doe" },
    "proof": { "type": "JsonWebSignature2020", "jwt": "eyJ..." }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential` | object | Yes | The signed credential |

**Response `200 OK`:**

```json
{
  "hash": "d6f4e2c9b7a8f1234567890abcdef1234567890abcdef1234567890abcde1f0"
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/revocation-hash \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "credential": {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:key:zDnae...","credentialSubject":{"name":"Jane Doe"},"proof":{"type":"JsonWebSignature2020","jwt":"eyJ..."}}
  }'
```

Source: `apps/server/src/routes/revocation.ts`

---

### POST /v1/credentials/revocation-hash/batch

Compute revocation hashes for multiple credentials. Results are returned in input order.

**Auth:** Required.

**Request body:**

```json
{
  "credentials": [
    { "@context": ["..."], "type": ["VerifiableCredential"], "proof": {} },
    { "@context": ["..."], "type": ["VerifiableCredential"], "proof": {} }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credentials` | array of objects | Yes | Array of signed credentials |

**Response `200 OK`:**

```json
{
  "hashes": [
    { "index": 0, "hash": "d6f4e2c9b7a8...e1f0" },
    { "index": 1, "hash": "b8f2a1d3e5c7...4a2c" }
  ]
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/revocation-hash/batch \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": [
      {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"proof":{}},
      {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"proof":{}}
    ]
  }'
```

Source: `apps/server/src/routes/revocation.ts`

---

### POST /v1/credentials/revoke

Publish a revocation to DeDi. Requires DeDi to be configured (`OPENCRED_DEDI_BASE_URL` and related env vars).

**Auth:** Required.

**Request body:**

Provide either the credential (hash is computed automatically) or a pre-computed hash:

```json
{
  "credential": { "@context": ["..."], "type": ["VerifiableCredential"], "proof": {} },
  "namespace": "my-namespace"
}
```

Or:

```json
{
  "hash": "d6f4e2c9b7a8f1234567890abcdef1234567890abcdef1234567890abcde1f0",
  "namespace": "my-namespace"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential` | object | One of `credential` or `hash` | The credential to revoke |
| `hash` | string (64 hex chars) | One of `credential` or `hash` | Pre-computed revocation hash |
| `namespace` | string | No | DeDi namespace (defaults to `OPENCRED_DEDI_NAMESPACE`) |

**Response `200 OK`** — revocation completed synchronously (the DeDi/CORD write finished within the request budget):

```json
{
  "hash": "d6f4e2c9b7a8f1234567890abcdef1234567890abcdef1234567890abcde1f0",
  "revoked": true,
  "revokedAt": "2026-04-13T10:00:00.000Z"
}
```

**Response `202 Accepted`** — DeDi anchors revocation records to CORD, and the write can exceed the server's hard 10s per-request ceiling. When it does, the revoke is **accepted and completed in the background** (idempotent and self-healing) instead of failing. Poll `POST /v1/credentials/revocation-status` until it returns `{"revoked": true}` to confirm:

```json
{
  "hash": "d6f4e2c9b7a8f1234567890abcdef1234567890abcdef1234567890abcde1f0",
  "revoked": false,
  "status": "pending",
  "message": "Revocation accepted and is being published to DeDi..."
}
```

**Error `409 DEDI_RECORD_EXISTS`** — the hash is already revoked; confirm with `revocation-status`.

**Error `503 DEDI_NOT_CONFIGURED`:**

```json
{
  "error": {
    "code": "DEDI_NOT_CONFIGURED",
    "message": "DeDi not configured"
  }
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/revoke \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "d6f4e2c9b7a8f1234567890abcdef1234567890abcdef1234567890abcde1f0"
  }'
```

Source: `apps/server/src/routes/revocation.ts`

---

### POST /v1/credentials/revocation-status

Query the revocation status of a credential via DeDi. Requires DeDi to be configured.

**Auth:** Required.

**Request body:**

```json
{
  "hash": "d6f4e2c9b7a8f1234567890abcdef1234567890abcdef1234567890abcde1f0",
  "namespace": "my-namespace"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hash` | string (64 hex chars) | Yes | Revocation hash to query |
| `namespace` | string | No | DeDi namespace |

**Response `200 OK`:**

Returns the revocation record from DeDi. The shape depends on the DeDi client response.

**Error `503 DEDI_NOT_CONFIGURED`:**

```json
{
  "error": {
    "code": "DEDI_NOT_CONFIGURED",
    "message": "DeDi not configured"
  }
}
```

**Example:**

```bash
curl -s http://localhost:3100/v1/credentials/revocation-status \
  -H "Authorization: Bearer $OPENCRED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "d6f4e2c9b7a8f1234567890abcdef1234567890abcdef1234567890abcde1f0"
  }'
```

Source: `apps/server/src/routes/revocation.ts`
