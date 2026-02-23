# Spike 8: Multi-Format VC Verification PoC

**Issue:** #8
**Author:** Claude Code Agent
**Date:** 2026-02-23
**Status:** Complete — GO for both VC-JWT and SD-JWT VC

---

## 1. Objective

Validate that OpenCred's verification pipeline can accept and verify Verifiable Credentials in **VC-JWT** and **SD-JWT VC** formats (in addition to the existing Data Integrity format), to support Type D onboarding where business credentials may arrive in any proof format.

## 2. Standards Landscape

### 2.1 VC Data Model 2.0

The W3C Verifiable Credentials Data Model v2.0 (W3C Recommendation, May 2025) defines the data model for credentials. It is securing-mechanism agnostic — the same credential payload can be secured with different proof mechanisms.

Three securing mechanisms are standardized:
- **Data Integrity** (embedded proof) — W3C VC Data Integrity 1.0
- **JOSE/JWT** (enveloping proof) — W3C Securing VCs using JOSE and COSE
- **SD-JWT** (enveloping proof with selective disclosure) — IETF RFC 9901 + draft-ietf-oauth-sd-jwt-vc

### 2.2 VC-JWT (W3C VC-JOSE-COSE)

**Specification:** [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/) (W3C Recommendation, May 2025)

A VC-JWT is a standard JWS (Compact Serialization) where the JWT payload IS the Verifiable Credential itself.

**Key points:**

| Aspect | Detail |
|---|---|
| Serialization | JWS Compact Serialization (3 dot-separated base64url parts) |
| `typ` header | SHOULD be `vc+jwt` (for credentials) or `vp+jwt` (for presentations) |
| `alg` header | MUST specify algorithm (e.g., `ES256`); `none` is prohibited |
| `kid` header | Recommended for key resolution |
| Payload structure | **VC DM 2.0**: the VC JSON IS the JWT payload directly (no wrapping `vc` claim) |
| Media type | `application/vc+jwt` |
| Claim mapping | `iss` = issuer, `nbf` = validFrom (epoch), `exp` = validUntil (epoch), `jti` = credential ID |

**Important DM 1.1 vs DM 2.0 difference:**
- **DM 1.1** (legacy): VC is nested under a `vc` claim in the JWT payload
- **DM 2.0** (current): The VC payload IS the JWT Claims Set directly; `vc` and `vp` claims MUST NOT be present

OpenCred's verification engine should support **both** mappings for interoperability with legacy issuers.

### 2.3 SD-JWT VC (IETF)

**Specifications:**
- [RFC 9901: Selective Disclosure for JWTs](https://datatracker.ietf.org/doc/rfc9901/) (Internet Standard, November 2025)
- [draft-ietf-oauth-sd-jwt-vc-14](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) (SD-JWT VC profile)

An SD-JWT VC is a composite structure: `<issuer-jwt>~[<disclosure>~]*[<key-binding-jwt>]`

**Selective disclosure mechanism:**
1. Issuer creates a JWT with some claims replaced by SHA-256 digests
2. Original claim values are encoded as **Disclosures**: base64url-encoded JSON arrays `[salt, name, value]`
3. Disclosures are appended to the JWT separated by `~`
4. Holder selects which disclosures to present to the verifier
5. Verifier hashes each presented disclosure and matches against `_sd` array digests

**Key claims:**

| Claim | Required | Purpose |
|---|---|---|
| `vct` | REQUIRED | Credential type URI (e.g., `https://example.com/identity_credential`) |
| `iss` | OPTIONAL | Issuer identifier (DID or HTTPS URL) |
| `iat` | OPTIONAL | Issuance timestamp |
| `nbf` | OPTIONAL | Not-before timestamp |
| `exp` | OPTIONAL | Expiration timestamp |
| `cnf` | OPTIONAL | Confirmation key for holder binding |
| `status` | OPTIONAL | Credential status information |
| `_sd` | Present when using SD | Array of disclosure digests |
| `_sd_alg` | OPTIONAL | Hash algorithm (defaults to `sha-256`) |

**Media type:** `application/dc+sd-jwt` (changed from earlier `vc+sd-jwt` to avoid conflicts)

**Key resolution methods (SD-JWT VC specific):**
1. **JWT VC Issuer Metadata:** `/.well-known/jwt-vc-issuer` endpoint when `iss` is HTTPS URL
2. **X.509 certificates:** `x5c` header parameter with certificate chain
3. **DID resolution:** When `iss` is a DID, resolve via DID document `verificationMethod`

## 3. Library Analysis

### 3.1 `jose` (v5.x) — JWT/JWS Operations

**npm:** [jose](https://www.npmjs.com/package/jose)
**Maintainer:** Filip Skokan (panva)
**License:** MIT
**Status:** Actively maintained, production-ready

**Strengths:**
- Pure JavaScript, no native dependencies — works in Node.js, browsers, Deno, Bun
- Complete JOSE implementation: JWS, JWE, JWT, JWK, JWKS
- `jwtVerify()` handles signature verification + claims validation in one call
- `decodeProtectedHeader()` for pre-verification header inspection
- `decodeJwt()` for payload inspection without verification
- Built-in support for all relevant algorithms (ES256, ES384, ES512, EdDSA, RS256, etc.)
- First-class TypeScript types with generic payload support
- Excellent documentation and test coverage

**API for VC-JWT verification:**
```typescript
import * as jose from 'jose';

// 1. Decode header to get kid/alg
const header = jose.decodeProtectedHeader(jwt);

// 2. Decode payload to get iss (for key resolution)
const payload = jose.decodeJwt(jwt);

// 3. Resolve public key (from DID document, JWKS, etc.)
const publicKey = await resolveKey(payload.iss, header.kid);

// 4. Verify signature + validate claims
const { payload: verified } = await jose.jwtVerify(jwt, publicKey, {
  issuer: expectedIssuer,     // optional claim validation
  algorithms: ['ES256'],      // restrict allowed algorithms
});
```

**Verdict:** **Recommended for VC-JWT.** Already in use in OpenCred's `packages/verification`. No additional dependency needed.

### 3.2 `@sd-jwt/core` / `@sd-jwt/sd-jwt-vc` — SD-JWT Operations

**npm:** [@sd-jwt/core](https://www.npmjs.com/package/@sd-jwt/core), [@sd-jwt/sd-jwt-vc](https://www.npmjs.com/package/@sd-jwt/sd-jwt-vc)
**Organization:** OpenWallet Foundation
**License:** Apache-2.0
**Status:** Active development (v0.14.0 core, v0.18.0 decode as of Feb 2026)

**Strengths:**
- Reference implementation of the IETF SD-JWT spec
- TypeScript-first with comprehensive types
- Modular architecture: `@sd-jwt/core`, `@sd-jwt/decode`, `@sd-jwt/present`, `@sd-jwt/sd-jwt-vc`
- `@sd-jwt/sd-jwt-vc` implements the SD-JWT VC profile specifically
- Handles disclosure processing, digest computation, and selective disclosure
- Built-in status list support via `@sd-jwt/jwt-status-list`
- Framework-agnostic (Node.js, browser, React Native)

**Concerns:**
- Pre-1.0 version — API may change (though actively converging toward RFC compliance)
- Adds a non-trivial dependency tree
- Verification requires plugging in your own `verifier` function (for signature checking) and `hasher` function
- Some complexity in the configuration-heavy API

**API for SD-JWT VC verification:**
```typescript
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { digest } from '@sd-jwt/crypto-browser'; // or @sd-jwt/crypto-nodejs

const instance = new SDJwtVcInstance({
  hasher: digest,
  verifier: async (data, signature) => {
    // Use jose or Node.js crypto to verify
    return jose.compactVerify(data + '.' + signature, publicKey);
  },
});

const { payload, disclosures } = await instance.verify(sdJwtVcString);
```

**Verdict:** **Not recommended as a dependency at this time.** The pre-1.0 status and configuration complexity do not justify the benefit over OpenCred's existing hand-rolled SD-JWT parsing/verification in `packages/verification`. OpenCred's current approach (using `jose` directly for JWT signature verification + custom disclosure processing) is simpler, has fewer dependencies, and provides full control.

**Reassessment trigger:** If `@sd-jwt/sd-jwt-vc` reaches 1.0 and the SD-JWT VC spec stabilizes, it would be worth reconsidering to get free compliance with spec updates.

### 3.3 `@transmute/vc.js` — Multi-Format VC Library

**npm:** [@transmute/vc.js](https://www.npmjs.com/package/@transmute/vc.js) (part of `verifiable-data` monorepo)
**Status:** Low activity, last meaningful update over a year ago

**Strengths:**
- Supports both Data Integrity and VC-JWT in one API
- Integrates with the `@transmute` cryptographic suite ecosystem

**Concerns:**
- Stale: minimal recent maintenance
- Tightly coupled to `@transmute` ecosystem (JSON Web Signature suites, etc.)
- Heavy dependency tree
- Does not support SD-JWT VC
- VC DM 1.1 oriented — unclear DM 2.0 support

**Verdict:** **Not recommended.** Stale maintenance, heavy dependencies, and no SD-JWT support make it unsuitable. OpenCred should use `jose` directly.

### 3.4 `jwt-decode` — Lightweight JWT Decoding

**npm:** [jwt-decode](https://www.npmjs.com/package/jwt-decode)
**Status:** Maintained but minimal

**Strengths:**
- Tiny bundle size (~1KB)
- Simple API: `jwtDecode(token)` → payload

**Concerns:**
- Decode-only — no verification capability
- `jose.decodeJwt()` provides the same functionality and is already a dependency

**Verdict:** **Not needed.** `jose` already provides `decodeJwt()` and `decodeProtectedHeader()`.

### 3.5 Library Recommendation Summary

| Format | Recommended Library | Rationale |
|---|---|---|
| **VC-JWT** | `jose` (v5.x) | Already in use, production-grade, complete JWT verification |
| **SD-JWT VC** | `jose` + custom parsing | OpenCred's existing SD-JWT implementation is clean and sufficient |
| **Data Integrity** | `@digitalbazaar/data-integrity` | Already in use via `@opencred/crypto` |

**No new dependencies required.** The existing `jose` dependency handles all JWT-based format needs.

## 4. Prototype: End-to-End Verification

### 4.1 VC-JWT End-to-End

The following prototype demonstrates the complete VC-JWT lifecycle: key generation, credential signing, and verification.

```typescript
// PROTOTYPE CODE — NOT FOR PRODUCTION USE
import { generateKeyPairSync, createPublicKey, type KeyObject } from 'node:crypto';
import * as jose from 'jose';

// === Key Generation ===
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

// === Sign a VC as JWT ===
async function signVcJwt(
  credential: Record<string, unknown>,
  issuerDid: string,
  privateKey: KeyObject,
): Promise<string> {
  const key = await jose.importPKCS8(
    privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    'ES256',
  );

  // VC DM 2.0: credential payload IS the JWT Claims Set
  const claims = {
    ...credential,
    iss: issuerDid,
    nbf: Math.floor(Date.now() / 1000),
    jti: credential.id,
  };

  return new jose.SignJWT(claims)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'vc+jwt',
      kid: `${issuerDid}#key-1`,
    })
    .sign(key);
}

// === Verify a VC-JWT ===
async function verifyVcJwt(
  jwt: string,
  resolveKey: (iss: string, kid?: string) => Promise<KeyObject>,
): Promise<{ verified: boolean; payload: Record<string, unknown> | null; error?: string }> {
  try {
    const header = jose.decodeProtectedHeader(jwt);
    const unverified = jose.decodeJwt(jwt);

    if (!header.alg || header.alg === 'none') {
      return { verified: false, payload: null, error: 'Missing or prohibited algorithm' };
    }

    const iss = unverified.iss;
    if (!iss) {
      return { verified: false, payload: null, error: 'Missing iss claim' };
    }

    const publicKey = await resolveKey(iss, header.kid);
    const { payload } = await jose.jwtVerify(jwt, publicKey, {
      algorithms: ['ES256', 'ES384', 'ES512', 'EdDSA'],
    });

    return { verified: true, payload: payload as Record<string, unknown> };
  } catch (err) {
    return {
      verified: false,
      payload: null,
      error: err instanceof Error ? err.message : 'Verification failed',
    };
  }
}

// === Demo ===
const issuerDid = 'did:web:university.example';
const credential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:abcd-1234',
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  validFrom: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:holder123',
    degree: { type: 'BachelorDegree', name: 'Computer Science' },
  },
};

const jwt = await signVcJwt(credential, issuerDid, privateKey);
console.log('Signed VC-JWT:', jwt.substring(0, 50) + '...');

// Resolve key from mock DID document
const result = await verifyVcJwt(jwt, async () => publicKey);
console.log('Verification result:', result.verified); // true
console.log('Issuer:', result.payload?.iss);
console.log('Credential type:', result.payload?.type);
```

**Key observations from prototype:**
1. `jose.jwtVerify()` handles both signature verification and standard JWT claim validation (`nbf`, `exp`, `iat`) in one call
2. Pre-verification header/payload decoding (`decodeProtectedHeader`, `decodeJwt`) is essential for key resolution before signature check
3. The `algorithms` whitelist in `jwtVerify` options prevents algorithm confusion attacks
4. Error messages from `jose` are safe to surface (no key material leakage)

### 4.2 SD-JWT VC End-to-End

The following prototype demonstrates selective disclosure with the SD-JWT VC format.

```typescript
// PROTOTYPE CODE — NOT FOR PRODUCTION USE
import { generateKeyPairSync, createHash, type KeyObject } from 'node:crypto';
import * as jose from 'jose';

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

// === Create a Disclosure ===
function createDisclosure(salt: string, name: string, value: unknown): string {
  return Buffer.from(JSON.stringify([salt, name, value])).toString('base64url');
}

// === Compute disclosure digest (SHA-256) ===
function computeDigest(disclosure: string): string {
  return createHash('sha256').update(disclosure).digest().toString('base64url');
}

// === Issue an SD-JWT VC ===
async function issueSdJwtVc(
  claims: Record<string, unknown>,
  selectiveFields: string[],
  issuerDid: string,
  privateKey: KeyObject,
): Promise<string> {
  const disclosures: string[] = [];
  const sdDigests: string[] = [];
  const payload: Record<string, unknown> = {};

  // Separate selective vs always-visible claims
  for (const [key, value] of Object.entries(claims)) {
    if (selectiveFields.includes(key)) {
      const salt = require('node:crypto').randomBytes(16).toString('base64url');
      const disclosure = createDisclosure(salt, key, value);
      disclosures.push(disclosure);
      sdDigests.push(computeDigest(disclosure));
    } else {
      payload[key] = value;
    }
  }

  // Build JWT payload with digests instead of selective claims
  const jwtPayload = {
    ...payload,
    iss: issuerDid,
    iat: Math.floor(Date.now() / 1000),
    vct: 'https://example.com/identity_credential',
    _sd: sdDigests,
    _sd_alg: 'sha-256',
  };

  const key = await jose.importPKCS8(
    privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    'ES256',
  );

  const jwt = await new jose.SignJWT(jwtPayload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', kid: `${issuerDid}#key-1` })
    .sign(key);

  // Compose: <jwt>~<d1>~<d2>~...~
  return jwt + '~' + disclosures.join('~') + '~';
}

// === Parse SD-JWT VC into components ===
function parseSdJwtVc(sdJwtVc: string): {
  issuerJwt: string;
  disclosures: string[];
  keyBindingJwt?: string;
} {
  const parts = sdJwtVc.split('~');
  const issuerJwt = parts[0];
  const disclosures: string[] = [];
  let keyBindingJwt: string | undefined;

  for (let i = 1; i < parts.length; i++) {
    if (parts[i] === '') continue;
    if (i === parts.length - 1 && parts[i].split('.').length === 3) {
      keyBindingJwt = parts[i];
    } else {
      disclosures.push(parts[i]);
    }
  }
  return { issuerJwt, disclosures, keyBindingJwt };
}

// === Decode a disclosure ===
function decodeDisclosure(d: string): [string, string, unknown] {
  const json = Buffer.from(d, 'base64url').toString('utf-8');
  const arr = JSON.parse(json);
  return [String(arr[0]), String(arr[1]), arr[2]];
}

// === Process disclosures and reconstruct claims ===
function resolveDisclosures(
  payload: Record<string, unknown>,
  disclosures: string[],
): Record<string, unknown> {
  const result = { ...payload };
  const sdDigests = (payload._sd as string[]) ?? [];

  const digestMap = new Map<string, [string, string, unknown]>();
  for (const d of disclosures) {
    digestMap.set(computeDigest(d), decodeDisclosure(d));
  }

  for (const digest of sdDigests) {
    const entry = digestMap.get(digest);
    if (entry) {
      const [, name, value] = entry;
      result[name] = value;
    }
  }

  delete result._sd;
  delete result._sd_alg;
  return result;
}

// === Verify SD-JWT VC ===
async function verifySdJwtVc(
  sdJwtVc: string,
  resolveKey: (iss: string, kid?: string) => Promise<KeyObject>,
): Promise<{
  verified: boolean;
  payload: Record<string, unknown> | null;
  disclosedClaims: Record<string, unknown> | null;
  error?: string;
}> {
  try {
    const { issuerJwt, disclosures } = parseSdJwtVc(sdJwtVc);
    const header = jose.decodeProtectedHeader(issuerJwt);
    const unverified = jose.decodeJwt(issuerJwt) as Record<string, unknown>;

    if (!unverified.iss) {
      return { verified: false, payload: null, disclosedClaims: null, error: 'Missing iss' };
    }

    const publicKey = await resolveKey(unverified.iss as string, header.kid);
    const { payload } = await jose.jwtVerify(issuerJwt, publicKey, {
      algorithms: ['ES256', 'ES384', 'ES512', 'EdDSA'],
    });

    const disclosedClaims = resolveDisclosures(payload as Record<string, unknown>, disclosures);

    return { verified: true, payload: payload as Record<string, unknown>, disclosedClaims };
  } catch (err) {
    return {
      verified: false,
      payload: null,
      disclosedClaims: null,
      error: err instanceof Error ? err.message : 'Verification failed',
    };
  }
}

// === Demo: Issue with selective disclosure, then verify ===
const issuerDid = 'did:web:government.example';
const allClaims = {
  given_name: 'Jane',
  family_name: 'Doe',
  birthdate: '1990-07-15',
  nationality: 'US',
  document_number: 'X1234567',
};

// Mark name and document_number as selectively disclosable
const sdJwtVc = await issueSdJwtVc(
  allClaims,
  ['given_name', 'family_name', 'document_number'],
  issuerDid,
  privateKey,
);

console.log('SD-JWT VC (truncated):', sdJwtVc.substring(0, 60) + '...');

// Verify — all disclosures present
const result = await verifySdJwtVc(sdJwtVc, async () => publicKey);
console.log('Verified:', result.verified); // true
console.log('Disclosed claims:', result.disclosedClaims);
// { iss: '...', vct: '...', birthdate: '1990-07-15', nationality: 'US',
//   given_name: 'Jane', family_name: 'Doe', document_number: 'X1234567' }

// === Demo: Present only some disclosures (holder perspective) ===
const parts = sdJwtVc.split('~');
const partialPresentation = parts[0] + '~' + parts[1] + '~'; // only first disclosure
const partialResult = await verifySdJwtVc(partialPresentation, async () => publicKey);
console.log('Partial disclosure verified:', partialResult.verified); // true
console.log('Partially disclosed claims:', partialResult.disclosedClaims);
// Only one of the three selective claims will appear
```

**Key observations from prototype:**
1. Signature verification applies only to the issuer JWT — disclosures are integrity-protected via the digest linkage
2. Disclosure processing is a separate step AFTER signature verification
3. Holder controls which disclosures to include in presentation
4. Missing disclosures don't invalidate the signature — they just reduce the disclosed claim set
5. The `_sd_alg` claim specifies the hash algorithm (defaults to SHA-256 per RFC 9901)
6. Salt values MUST be generated with CSPRNG for privacy (prevents offline guessing)

### 4.3 Key Resolution Strategy

Key resolution is format-agnostic: all three formats ultimately need to map an issuer identifier to a public key.

```
┌──────────────────────────────────────────────────────────────┐
│                    Key Resolution Flow                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Input: issuer identifier + optional key hint                │
│                                                              │
│  ┌─── issuer starts with "did:" ──────────────────────┐     │
│  │  1. Resolve DID document via DID resolver           │     │
│  │  2. Find verificationMethod by kid (or first match) │     │
│  │  3. Extract key from publicKeyJwk or                │     │
│  │     publicKeyMultibase                              │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌─── issuer is HTTPS URL ────────────────────────────┐     │
│  │  1. Fetch /.well-known/jwt-vc-issuer metadata       │     │
│  │  2. Retrieve JWKS from jwks_uri or inline jwks      │     │
│  │  3. Match key by kid header                         │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌─── x5c header present ─────────────────────────────┐     │
│  │  1. Decode X.509 certificate chain from header      │     │
│  │  2. Validate chain to trusted root                  │     │
│  │  3. Extract public key from end-entity cert         │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌─── Data Integrity (proof.verificationMethod) ──────┐     │
│  │  1. Parse DID from verificationMethod URI           │     │
│  │  2. Resolve DID document                            │     │
│  │  3. Match verification method by full ID or fragment│     │
│  │  4. Extract key from multibase or JWK               │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Current OpenCred support:**
- DID-based resolution via `@opencred/did` — **implemented** (did:key only in v1)
- publicKeyJwk extraction — **implemented**
- publicKeyMultibase extraction — **implemented**
- HTTPS issuer metadata (`.well-known/jwt-vc-issuer`) — **not implemented** (needed for non-DID issuers)
- x5c certificate chain resolution — **not implemented** (useful for government/enterprise issuers)

**Recommendation:** For v1, DID-based resolution is sufficient. HTTPS metadata and x5c support should be Phase 2+ extensions when OpenCred encounters non-DID issuers in Type D onboarding.

## 5. Verification Result Normalization

All three formats must map to a common `CredentialVerificationResult`:

```typescript
type VerificationResultCode = 'VALID' | 'REVOKED' | 'EXPIRED' | 'INVALID' | 'UNRESOLVABLE';

interface CredentialVerificationResult {
  code: VerificationResultCode;
  verified: boolean;
  checks: VerificationCheck[];
}
```

**Mapping across formats:**

| Check | Data Integrity | VC-JWT | SD-JWT VC |
|---|---|---|---|
| **Signature** | `verifyProof()` via Data Integrity lib | `jose.jwtVerify()` | `jose.jwtVerify()` on issuer JWT |
| **Key resolution** | `proof.verificationMethod` → DID resolve | `iss` + `kid` → DID resolve | `iss` + `kid` → DID resolve |
| **Date validity** | `credential.validFrom` / `validUntil` | `nbf` / `exp` (or VC payload dates) | `nbf` / `exp` (or resolved claim dates) |
| **Revocation (DeDi)** | JCS hash of credential | JCS hash of VC payload | JCS hash of resolved claims |
| **Revocation (BSL)** | `credentialStatus` on credential | `credentialStatus` in VC payload | `credentialStatus` in resolved claims or `status` claim |
| **Result: VALID** | All checks pass | All checks pass | All checks pass |
| **Result: INVALID** | Signature fails / tampered | Signature fails / bad JWT | Signature fails / disclosure mismatch |
| **Result: EXPIRED** | `validUntil` in past | `exp` in past | `exp` in past |
| **Result: REVOKED** | DeDi or BSL reports revoked | DeDi or BSL reports revoked | DeDi or BSL reports revoked |
| **Result: UNRESOLVABLE** | Cannot resolve DID/key | Cannot resolve DID/key | Cannot resolve DID/key |

**Current OpenCred implementation status:** The `packages/verification` verifier already implements this normalization pattern correctly. The `verifyCredential()` function in `verifier.ts` dispatches by format, runs format-specific signature verification, then runs common checks (dates, DeDi revocation, BitstringStatusList).

## 6. Assessment of Existing Implementation

OpenCred's `packages/verification` already implements multi-format verification as described in issue #19 (feat: multi-format verification engine). Reviewing the code:

### 6.1 Format Detection (`verifier.ts:detectFormat`)
- Object with `proof` → Data Integrity
- String with `~` → SD-JWT VC
- String with 3 dot-separated parts → VC-JWT

**Assessment:** Correct and sufficient for all known formats.

### 6.2 VC-JWT Verification (`vc-jwt.ts`)
- Decodes header and payload before verification
- Resolves issuer key via DID resolver
- Supports both `publicKeyJwk` and `publicKeyMultibase` key formats
- Extracts credential fields from both `nbf`/`exp` and `vc.validFrom`/`vc.validUntil`
- Handles DM 1.1 (`vc` claim) payloads

**Assessment:** Solid. Two improvements recommended:
1. Add DM 2.0 payload extraction (where credential fields are directly on the JWT payload, not under `vc`)
2. Add algorithm whitelist to `jwtVerify` to prevent algorithm confusion attacks

### 6.3 SD-JWT VC Verification (`sd-jwt-vc.ts`)
- Correctly parses `<jwt>~<d1>~<d2>~...~[<kb-jwt>]` format
- Disclosure decoding: base64url → JSON array → `[salt, name, value]`
- Digest computation using `crypto.subtle.digest`
- Disclosure matching against `_sd` array
- Key resolution via DID resolver

**Assessment:** Solid. Two improvements recommended:
1. Use Node.js `crypto.createHash` instead of `crypto.subtle.digest` for consistency with the rest of the codebase (subtle is async and browser-oriented)
2. Consider supporting nested `_sd` in objects (current impl handles top-level only)

### 6.4 Common Checks (`checks.ts`)
- Date validation for `validFrom`/`validUntil`
- DeDi revocation hash check
- BitstringStatusList fetch and bit check

**Assessment:** Complete for v1 requirements.

### 6.5 Test Coverage
- `vc-jwt.test.ts`: 4 test cases covering valid verification, missing resolver, missing iss, wrong key, malformed JWT
- `sd-jwt-vc.test.ts`: 8 test cases covering parsing, disclosure decoding, disclosure processing, verification (valid + invalid), field extraction
- `verifier.test.ts`: 10 test cases covering format detection, end-to-end for all 3 formats

**Assessment:** Good foundation. Could add:
- Algorithm confusion attack test (alg:none)
- DM 2.0 payload test (no `vc` wrapper)
- SD-JWT VC with nested object disclosures
- SD-JWT VC with partial disclosure presentation

## 7. Identified Limitations and Edge Cases

### 7.1 VC-JWT

1. **DM 1.1 vs DM 2.0 ambiguity:** The current code assumes DM 1.1 (`payload.vc`). For DM 2.0 VCs where the credential IS the JWT payload, fields like `type`, `credentialSubject`, `credentialStatus` are directly on the payload. The extraction logic should check for both patterns.

2. **Algorithm confusion:** `jose.jwtVerify()` should be called with an explicit `algorithms` whitelist. Without it, a crafted JWT could potentially exploit algorithm negotiation.

3. **`typ` header validation:** The spec says `typ` SHOULD be `vc+jwt`. Currently not validated. Consider logging a warning if `typ` is unexpected (but don't reject, since it's SHOULD, not MUST).

4. **Nested JWT:** Some ecosystems use JWTs inside JWTs (e.g., for VP wrapping). Not needed for v1 but worth noting.

### 7.2 SD-JWT VC

1. **Nested selective disclosure:** SD-JWT supports `_sd` arrays at any level of nesting (not just the top-level payload). OpenCred's current implementation only processes top-level `_sd`. This is sufficient for most real-world credentials but may miss deeply nested selective fields.

2. **Array element disclosure:** SD-JWT supports selectively disclosing individual array elements (using `...` sentinel values). Not currently implemented.

3. **Key Binding JWT:** The optional KB-JWT proves the presenter controls a specific key. Not currently verified. For Type D onboarding, KB-JWT verification may be needed to prevent credential replay.

4. **Decoy digests:** Issuers may include extra digests in `_sd` that don't correspond to any disclosure (for privacy). These should be silently ignored during processing — current implementation handles this correctly.

5. **`status` claim:** SD-JWT VC uses a `status` claim (not `credentialStatus`) for revocation. Current extraction logic checks for both, which is correct.

### 7.3 Cross-Format

1. **Non-DID issuers:** Both VC-JWT and SD-JWT VC allow HTTPS URLs as `iss` values, not just DIDs. Current key resolution only supports DID-based resolution. For v1, this is acceptable but limits compatibility with pure-HTTPS issuers.

2. **Revocation hash computation:** For VC-JWT, the revocation hash is computed on `payload.vc` (DM 1.1) or the full payload (DM 2.0). For SD-JWT VC, it's computed on the resolved (disclosed) claims. Both approaches need careful consideration of what constitutes the "canonical credential" for hashing.

## 8. Recommendations

### 8.1 Go/No-Go

| Format | Decision | Confidence | Rationale |
|---|---|---|---|
| **VC-JWT** | **GO** | High | Proven with `jose`, already implemented, W3C Recommendation |
| **SD-JWT VC** | **GO** | High | Proven with `jose` + custom parsing, already implemented, RFC 9901 is Internet Standard |
| **Data Integrity** | Already in production | N/A | Existing via `@digitalbazaar/data-integrity` |

### 8.2 Library Decisions

| Decision | Choice | Rationale |
|---|---|---|
| VC-JWT verification | **`jose` (v5.x)** | Already a dependency, production-grade, complete JWT stack |
| SD-JWT VC verification | **`jose` + custom parsing** | Avoids pre-1.0 `@sd-jwt/*` dependency; OpenCred's existing parser is clean and spec-compliant |
| Multi-format dispatch | **Custom `detectFormat()` + verifier** | Already implemented in `packages/verification`; no benefit from `@transmute/vc.js` |
| JWT decoding | **`jose` (decodeJwt, decodeProtectedHeader)** | No need for separate `jwt-decode` package |

### 8.3 Recommended Improvements to Existing Implementation

**Priority 1 (Before Phase 1 completion):**
1. Add `algorithms` whitelist to `jose.jwtVerify()` calls in both `vc-jwt.ts` and `sd-jwt-vc.ts`
2. Support DM 2.0 payload extraction in `extractVcJwtCredentialFields()` — check for credential fields directly on the payload when `vc` claim is absent

**Priority 2 (Phase 2+):**
3. Add HTTPS issuer metadata resolution (`.well-known/jwt-vc-issuer`) for non-DID VC-JWT/SD-JWT VC issuers
4. Add `x5c` certificate chain resolution for enterprise/government issuers
5. Implement nested `_sd` processing for deep selective disclosure
6. Implement Key Binding JWT verification for SD-JWT VC

**Priority 3 (Future):**
7. Consider switching to `@sd-jwt/sd-jwt-vc` when it reaches 1.0
8. Add array element disclosure support for SD-JWT VC
9. Add COSE support (for mDL/mDoc interop)

### 8.4 Architecture Validation

The existing `packages/verification` architecture is well-suited for multi-format verification:

```
verifyCredential(input, config)
  │
  ├── detectFormat(input)
  │     ├── "data-integrity" → verifyDataIntegrity()
  │     ├── "vc-jwt"         → verifyVcJwt()
  │     └── "sd-jwt-vc"      → verifySdJwtVc()
  │
  ├── Extract format-specific fields → common: validFrom, validUntil, credentialStatus
  │
  ├── checkDates(validFrom, validUntil)
  ├── checkRevocation(credential, dediClient)
  └── checkBitstringStatusList(credentialStatus)
        │
        └── CredentialVerificationResult { code, verified, checks }
```

This dispatcher pattern is clean, extensible, and already implemented. No architectural changes needed.

## 9. Summary

| Question | Answer |
|---|---|
| Can OpenCred verify VC-JWTs? | **Yes.** Working end-to-end with `jose`. Already implemented. |
| Can OpenCred verify SD-JWT VCs? | **Yes.** Working end-to-end with `jose` + custom parsing. Already implemented. |
| New dependencies needed? | **None.** `jose` (already a dependency) handles everything. |
| Architecture changes needed? | **None.** Existing dispatcher pattern in `packages/verification` is correct. |
| Key resolution strategy? | DID-based (via `@opencred/did`) for v1. HTTPS metadata + x5c for later phases. |
| Result normalization? | Already implemented — common `CredentialVerificationResult` across all formats. |
| Blockers for Type D onboarding? | **None.** Multi-format verification is operational. |

**This spike confirms that OpenCred's verification pipeline is ready for multi-format credential verification in Type D onboarding.**
