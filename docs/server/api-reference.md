# API Reference

## Authentication

Protected endpoints require a Bearer token:

```
Authorization: Bearer <OPENCRED_API_KEY>
```

If `OPENCRED_API_KEY` is not set, authentication is disabled (development mode). The `/health` endpoint is always public.

## Error Format

All errors follow this structure:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [{ "path": "schemaId", "message": "Required" }]
  }
}
```

## Endpoints

### GET /health

Health check. No authentication required.

**Response** `200`
```json
{
  "status": "ok",
  "signingKeyLoaded": true,
  "timestamp": "2026-03-25T10:00:00.000Z"
}
```

---

### GET /schemas

List available credential schemas.

**Response** `200`
```json
{
  "schemas": [
    { "id": "education", "contextUrl": "https://opencred.dev/schemas/education/v1" }
  ]
}
```

---

### GET /schemas/:id

Get a schema definition by ID.

**Response** `200`
```json
{
  "id": "education",
  "schema": { "$id": "...", "title": "Education Credential", "properties": { "..." : "..." } },
  "contextUrl": "https://opencred.dev/schemas/education/v1"
}
```

---

### POST /credentials/issue

Issue a single Verifiable Credential.

**Request Body**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `schemaId` | string | Yes | -- | Schema ID to validate against |
| `issuerDid` | string | Yes | -- | Issuer DID |
| `credentialSubject` | object | Yes | -- | Credential subject fields |
| `validFrom` | string (ISO 8601) | Yes | -- | Start of validity |
| `validUntil` | string (ISO 8601) | No | -- | End of validity |
| `proofFormat` | enum | No | `vc-jwt` | `vc-jwt`, `data-integrity`, or `sd-jwt-vc` |
| `additionalTypes` | string[] | No | -- | Additional credential types |
| `subjectDid` | string | No | -- | Subject DID (set as `credentialSubject.id`) |
| `selectiveDisclosureClaims` | string[] | No | -- | Claims for SD-JWT-VC selective disclosure |
| `revocationRegistryUrl` | URL | No | -- | Revocation registry URL |
| `credentialSchemaUrl` | URL | No | -- | Credential schema URL |
| `packageFormats` | string[] | No | -- | `qr-png`, `qr-svg`, `pdf`, `json-ld`, `json-compact` |

**Response** `200`
```json
{
  "credential": { "..." : "..." },
  "proofFormat": "vc-jwt",
  "isCompactToken": false,
  "packagedOutputs": [
    { "format": "pdf", "data": "<base64>", "mimeType": "application/pdf", "suggestedFileName": "credential.pdf", "encoding": "base64" }
  ]
}
```

**Notes:**
- `data-integrity` proofs require ECDSA (P-256, P-384) or Ed25519. RSA is not supported.
- `sd-jwt-vc` returns a compact token string in the `credential` field with `isCompactToken: true`.
- `packagedOutputs` is only included when `packageFormats` is specified and the credential is not a compact token.

---

### POST /credentials/verify

Verify a signed Verifiable Credential.

**Request Body**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential` | string | Yes | The signed credential as a JSON string |

**Response** `200`
```json
{
  "valid": true,
  "message": "Credential is valid.",
  "checks": [
    { "name": "signature", "passed": true },
    { "name": "not-before", "passed": true },
    { "name": "expiry", "passed": true }
  ]
}
```

Only `did:key` issuers are supported for verification.

---

### POST /credentials/batch

Start a batch issuance job from CSV data. Returns `202 Accepted` immediately; processing runs in the background.

**Request Body**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `csvContent` | string | Yes | -- | CSV file content |
| `schemaId` | string | Yes | -- | Schema ID |
| `issuerDid` | string | Yes | -- | Issuer DID |
| `validFrom` | string (ISO 8601) | Yes | -- | Start of validity |
| `validUntil` | string | No | -- | End of validity |
| `proofFormat` | enum | No | `vc-jwt` | `vc-jwt`, `data-integrity`, `sd-jwt-vc` |
| `columnMapping` | object | No | -- | Map CSV headers to schema fields |
| `delimiter` | enum | No | `,` | `,`, `;`, or `\t` |
| `additionalTypes` | string[] | No | -- | Additional credential types |
| `revocationRegistryUrl` | URL | No | -- | Revocation registry URL |
| `credentialSchemaUrl` | URL | No | -- | Credential schema URL |
| `selectiveDisclosureClaims` | string[] | No | -- | SD-JWT-VC claims |

**Response** `202`
```json
{
  "jobId": "uuid",
  "headers": ["name", "degree", "institution"],
  "validCount": 95,
  "invalidCount": 5,
  "totalCount": 100,
  "parseErrors": [{ "rowIndex": 3, "errors": ["Missing required field: name"] }]
}
```

Row count is enforced by `OPENCRED_BATCH_ROW_LIMIT` (default 1000).

---

### GET /credentials/batch/:jobId

Get batch job progress.

**Response** `200`
```json
{
  "jobId": "uuid",
  "total": 95,
  "completed": 50,
  "successCount": 48,
  "errorCount": 2,
  "skippedCount": 0,
  "running": true,
  "cancelled": false
}
```

---

### GET /credentials/batch/:jobId/results

Get batch job results. Returns `409` if the job is still running.

**Response** `200`
```json
{
  "jobId": "uuid",
  "results": [
    { "rowIndex": 0, "status": "success", "credential": { "..." : "..." } },
    { "rowIndex": 1, "status": "error", "error": "Validation failed" }
  ]
}
```

---

### POST /credentials/revocation-hash

Compute a single revocation hash (JCS canonicalization + SHA-256).

**Request Body**
```json
{ "credential": { "..." : "..." } }
```

**Response** `200`
```json
{ "hash": "a1b2c3d4..." }
```

---

### POST /credentials/revocation-hash/batch

Compute revocation hashes for multiple credentials.

**Request Body**
```json
{ "credentials": [{ "..." : "..." }, { "..." : "..." }] }
```

**Response** `200`
```json
{
  "hashes": [
    { "index": 0, "hash": "a1b2c3d4..." },
    { "index": 1, "hash": "e5f6a7b8..." }
  ]
}
```

---

### POST /credentials/package

Package a signed credential into various output formats.

**Request Body**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `credential` | object | Yes | -- | The signed credential |
| `formats` | string[] | No | `["json-ld"]` | `qr-png`, `qr-svg`, `pdf`, `json-ld`, `json-compact` |

**Response** `200`
```json
{
  "outputs": [
    { "format": "pdf", "data": "<base64>", "mimeType": "application/pdf", "suggestedFileName": "credential.pdf", "encoding": "base64" },
    { "format": "json-ld", "data": "{...}", "mimeType": "application/ld+json", "suggestedFileName": "credential.json", "encoding": "utf-8" }
  ],
  "errors": []
}
```

Binary formats (PDF, QR PNG) are base64-encoded. Text formats (JSON, SVG) are UTF-8.

---

### POST /attestation/challenge

Create a domain verification challenge.

**Request Body**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | Yes | Domain to verify |
| `method` | enum | Yes | `dns-txt` or `http` |

**Response** `200`
```json
{
  "challengeId": "uuid",
  "token": "hex-string",
  "instructions": "Add a DNS TXT record...",
  "expiresAt": "2026-03-25T11:00:00.000Z"
}
```

---

### POST /attestation/challenge/:id/verify

Verify domain ownership and receive a Key Attestation VC.

**Request Body**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `publicKeyJwk` | object | Yes | Issuer's public key in JWK format |
| `issuerDid` | string | Yes | Issuer DID (must start with `did:`) |
| `keyFingerprint` | string | Yes | SHA-256 fingerprint of the public key |
| `keyAlgorithm` | string | Yes | Key algorithm (e.g., `P-256`) |
| `verificationMethodId` | string | Yes | Verification method ID |
| `organizationName` | string | Yes | Organization name for the attestation |

**Response** `200`
```json
{ "credential": { "..." : "..." } }
```

Challenges are single-use and deleted after verification.

---

### POST /attestation/attest-by-vc

Submit a verified business VC for Key Attestation (alternative to domain verification).

**Request Body**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `businessVc` | string or object | Yes | The business VC (JSON string or object) |
| `publicKeyJwk` | object | Yes | Issuer's public key in JWK format |
| `issuerDid` | string | Yes | Issuer DID |
| `keyFingerprint` | string | Yes | Key fingerprint |
| `keyAlgorithm` | string | Yes | Key algorithm |
| `verificationMethodId` | string | Yes | Verification method ID |

**Response** `200`
```json
{ "credential": { "..." : "..." } }
```
