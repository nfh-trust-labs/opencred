# OID4VCI (OpenID for Verifiable Credential Issuance)

Your OpenCred Docker deployment can act as a Credential Issuer under the OID4VCI specification, supporting the **pre-authorized code** grant type. This runs entirely in your infrastructure.

## Configuration

Set these environment variables to enable OID4VCI:

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENCRED_OID4VCI_ISSUER_URL` | Yes | Base URL for issuer metadata (e.g., `https://issuer.example.com`) |
| `OPENCRED_OID4VCI_ISSUER_NAME` | No | Display name in metadata |
| `OPENCRED_OID4VCI_AUTHORIZATION_SERVERS` | No | Comma-separated external AS URLs |

## Protocol Flow

```
1. Your server creates a credential offer (POST /oid4vci/offers)
   |
2. Offer URI is presented to wallet (QR code or deep link)
   openid-credential-offer://...
   |
3. Wallet exchanges pre-authorized code for access token (POST /oid4vci/token)
   |
4. Wallet requests credential with proof-of-possession (POST /oid4vci/credential)
   |
5. Your server issues credential and returns it to wallet
```

## Credential Formats

| Format | OID4VCI Identifier | Description |
|--------|--------------------|-------------|
| SD-JWT-VC | `dc+sd-jwt` | Selective Disclosure JWT Verifiable Credential |
| JWT VC JSON | `jwt_vc_json` | Standard JWT-based Verifiable Credential |

## Endpoints

### GET /.well-known/openid-credential-issuer

Public. Returns OID4VCI-compliant issuer metadata including supported credential configurations, token endpoint, and credential endpoint.

### POST /oid4vci/token

Public. Token endpoint for the pre-authorized code grant.

**Request** (`application/x-www-form-urlencoded` or JSON)
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `urn:ietf:params:oauth:grant-type:pre-authorized_code` |
| `pre-authorized_code` | string | Yes | Code from the credential offer |
| `user_pin` | string | No | User PIN if required by the offer |

**Response** `200`
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 600,
  "c_nonce": "...",
  "c_nonce_expires_in": 300
}
```

Pre-authorized codes are single-use. PIN comparison uses constant-time comparison.

### POST /oid4vci/credential

Public. Requires Bearer token from the token endpoint.

**Request**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format` | enum | Yes | `dc+sd-jwt` or `jwt_vc_json` |
| `credential_identifier` | string | No | Credential configuration ID |
| `vct` | string | No | Verifiable Credential Type (for SD-JWT-VC) |
| `credential_definition` | object | No | Credential type and subject definition |
| `proof` | object | No | Wallet proof-of-possession |
| `proof.proof_type` | string | Yes (if proof) | Must be `jwt` |
| `proof.jwt` | string | Yes (if proof) | JWT proving key possession |

**Response** `200`
```json
{
  "credential": "eyJ...",
  "format": "dc+sd-jwt",
  "c_nonce": "...",
  "c_nonce_expires_in": 300
}
```

Access tokens are single-use -- consumed after credential issuance.

### POST /oid4vci/offers

Internal API. Protected by `OPENCRED_API_KEY` Bearer auth.

Creates a credential offer with a pre-authorized code for wallet consumption.

**Request**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credentialConfigurationIds` | string[] | Yes | Credential configuration IDs |
| `credentialSubject` | object | Yes | Pre-populated credential subject |
| `issuerDid` | string | Yes | Issuer DID |
| `schemaId` | string | Yes | Schema ID |
| `subjectDid` | string | No | Subject DID |
| `userPin` | string | No | Required PIN for token exchange |
| `ttlSeconds` | integer (60-3600) | No | Offer TTL (default 300s) |

**Response** `200`
```json
{
  "offer": { "..." : "..." },
  "offerUri": "openid-credential-offer://...",
  "userPin": "1234"
}
```

## Security

- Pre-authorized codes: CSPRNG-generated, single-use
- Access tokens: single-use, time-limited
- c_nonce: single-use, time-limited
- PIN comparison: constant-time to prevent timing attacks
- All state is in-memory with TTL-based cleanup
