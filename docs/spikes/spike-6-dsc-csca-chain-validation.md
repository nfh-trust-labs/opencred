# Spike 6: DSC/CSCA Chain Validation PoC

**Issue:** #6
**Date:** 2026-02-23
**Status:** Complete — GO (Node.js native sufficient for v1)

## Goal

Prove the planned PKI validation approach works for DSC (Document Signer Certificate) → CSCA (Country Signing Certificate Authority) certificate chains using Node.js native crypto, and decide whether external libraries are needed.

## What Was Tested

### Test Certificate Hierarchy

Generated via openssl (P-256 / ECDSA):

```
Test CSCA (root CA, self-signed, 10yr)
├── Test DSC 001 (leaf, 2yr) — good chain
├── Expired DSC (leaf, 0-day validity) — expired cert
├── Test Intermediate CA
│   └── DSC via Intermediate (leaf, 2yr) — 3-level chain
└── (NOT signed by this CSCA):
    ├── Self-Signed DSC (rogue, self-signed leaf)
    └── Wrong Issuer DSC (signed by Other CSCA)
```

All certificates use ECDSA P-256 with SHA-256 signatures, matching OpenCred's target cryptosuite (ecdsa-rdfc-2019).

### Test Results (46/46 passed)

| Test | Result | Notes |
|---|---|---|
| Good DSC → CSCA chain | PASS | `checkIssued()` + `verify()` |
| Self-signed rogue DSC rejected | PASS | Not issued by any trust anchor |
| Wrong issuer DSC rejected | PASS | AKI/SKI mismatch + sig fails |
| Expired DSC detected | PASS | Manual date comparison required |
| Intermediate chain (3-level) | PASS | Manual chain walk succeeds |
| Incomplete chain rejected | PASS | Missing intermediate detected |
| verify() ignores dates | PASS | Confirmed: must check dates manually |

Full prototype: [`spike-6-prototype.mjs`](./spike-6-prototype.mjs)

## Node.js Native API Assessment

### What Works (Node.js v23.9.0, `crypto.X509Certificate`)

| Feature | API | Notes |
|---|---|---|
| Parse PEM/DER certs | `new X509Certificate(buffer)` | Works with PEM strings or DER buffers |
| Subject / Issuer DN | `.subject`, `.issuer` | Multiline string format |
| Serial number | `.serialNumber` | Hex string |
| Fingerprints | `.fingerprint256`, `.fingerprint512` | Colon-separated hex |
| CA flag | `.ca` | Boolean from `basicConstraints` |
| Validity dates | `.validFromDate`, `.validToDate` | Native `Date` objects (Node >=20) |
| Issuer check | `.checkIssued(parentCert)` | Matches AKI/SKI + issuer/subject DN |
| Signature verify | `.verify(publicKey)` | Cryptographic signature only |
| Public key extract | `.publicKey` | Returns `KeyObject` |

### Critical Finding: `checkIssued()` Semantics

The API semantics are **`child.checkIssued(parent)`** — "was the child cert issued by this parent?"

```js
// CORRECT:
dsc.checkIssued(csca)     // → true ("was DSC issued by CSCA?")
csca.checkIssued(csca)    // → true ("was CSCA issued by itself?" — self-signed)

// WRONG (common mistake):
csca.checkIssued(dsc)     // → false (this asks "was CSCA issued by DSC?")
```

This method checks:
1. AKI (Authority Key Identifier) of child matches SKI (Subject Key Identifier) of parent
2. Issuer DN of child matches Subject DN of parent

**Requirement:** Certificates MUST include `subjectKeyIdentifier` and `authorityKeyIdentifier` extensions for `checkIssued()` to work. Without these, the method may return incorrect results.

### Critical Finding: `keyUsage` Returns Extended Key Usage

Despite its name, `x509.keyUsage` returns **Extended Key Usage OIDs** (e.g., `1.3.6.1.5.5.7.3.1` for serverAuth), **NOT** basic Key Usage values (digitalSignature, keyCertSign, cRLSign, etc.).

- Certificates with only basic Key Usage → `keyUsage` returns `undefined`
- Certificates with Extended Key Usage → `keyUsage` returns OID array
- **Basic Key Usage is NOT accessible** via any native API property

**Impact on OpenCred:** Cannot verify that a DSC has `digitalSignature` key usage or that a CSCA has `keyCertSign` via native API alone. The `.ca` property partially covers the CSCA case (checks `basicConstraints`), but DSC key usage checking requires either:
1. Parsing raw DER (`x509.raw`) with ASN.1 decoder
2. Using `@peculiar/x509` for extension access

### Critical Finding: `verify()` Ignores Certificate Dates

`verify()` only checks cryptographic signature validity. It does NOT check:
- Whether the certificate is expired
- Whether the certificate is not yet valid
- Whether the issuer certificate is expired

**All date validation must be done manually** by comparing `validFromDate`/`validToDate` against the current time.

### Native API Gaps

| Gap | Impact on OpenCred | Workaround |
|---|---|---|
| No chain builder | Must walk chain manually | ~60 lines of code (see prototype) |
| No date enforcement | verify() ignores dates | Manual Date comparison |
| No basic Key Usage access | Cannot check digitalSignature/keyCertSign | `.ca` covers CA case; leaf KU needs DER parsing or `@peculiar/x509` |
| No CRL support | Cannot check revocation via CRL | `pkijs` has full CRL support |
| No OCSP support | Cannot check revocation via OCSP | `pkijs` has full OCSP support |
| No trust store | Must manage trust anchors in code | Simple Map/Set of CSCA certs |
| No pathLen enforcement | Cannot enforce max chain depth | Manual check on `.ca` + DER parse |
| No name constraints | Cannot enforce name restrictions | Not needed for DSC/CSCA chains |

## Library Comparison

| Library | Chain Validation | CRL | OCSP | Basic Key Usage | Bundle Size | TypeScript |
|---|---|---|---|---|---|---|
| **Node.js native** | Manual (~60 LOC) | No | No | No | 0 KB | N/A |
| **@peculiar/x509** | `X509ChainBuilder` | No | No | Yes (extension parsing) | ~45 KB | Yes |
| **pkijs** | Full engine (NIST PKITS) | Yes | Yes | Yes | ~200 KB | Yes |
| **node-forge** | `verifyCertificateChain` | Partial | No | Yes | ~300 KB | No (types available) |

### node-forge: NOT Recommended

node-forge has a critical ASN.1 validation bypass vulnerability (CVE-2025-12816, patched in 1.3.2) that could allow malformed certificates to pass validation. Given that OpenCred's security model depends on certificate chain integrity, this is disqualifying. The library also has no CRL/OCSP support and larger bundle size.

### @peculiar/x509: Good Supplement

Written in TypeScript, lightweight (~45 KB), provides `X509ChainBuilder` for chain building and full extension parsing including basic Key Usage. Does NOT include CRL or OCSP checking. Would complement Node.js native nicely for extension access.

### pkijs: Full PKI Stack

Comprehensive PKI library with its own chain validation engine (passed NIST PKITS). Includes CRL parsing/validation and OCSP request/response handling. Larger footprint but covers everything. Best choice if CRL/OCSP is needed.

## ICAO PKD / CSCA Trust Anchors

For production deployment, CSCA trust anchors come from:

1. **ICAO Master List** — ICAO compiles CSCA certificates from member states, distributed via PKD
2. **Bilateral exchange** — Countries exchange CSCAs directly
3. **National master lists** — Individual countries publish their trusted CSCAs

OpenCred v1 approach:
- Load CSCA trust anchors from PEM files at startup (bundled or configured)
- No runtime fetching of ICAO PKD (security: avoid remote trust anchor fetch)
- Trust store is a simple in-memory Map keyed by SKI or fingerprint

## Go/No-Go Recommendation

### GO — Node.js native API for v1

**Rationale:**
1. `checkIssued()` + `verify()` correctly handle DSC → CSCA signature chain validation
2. `.ca` property correctly distinguishes CA from leaf certificates
3. `validFromDate`/`validToDate` enable date validation
4. Manual chain walking (~60 lines) handles 2-3 level chains (CSCA → DSC, CSCA → Intermediate → DSC)
5. All failure modes detected: rogue certs, wrong issuer, expired certs, incomplete chains

**Known limitations accepted for v1:**
- Basic Key Usage checking deferred (`.ca` is sufficient for CA identification; DSC key usage not strictly required for chain validation)
- CRL/OCSP revocation checking deferred to later phase
- Trust store is application-managed (acceptable for v1)

**Future enhancement path:**
- **If basic Key Usage checking needed:** Add `@peculiar/x509` (~45 KB) for extension parsing
- **If CRL/OCSP needed:** Add `pkijs` (~200 KB) for revocation checking
- **If complex chains needed (cross-certs, bridge CAs):** Switch to `pkijs` chain engine

### Implementation Guidance for `packages/verification`

```typescript
// Recommended chain validation approach for v1
// (production version of the prototype's validateChain function)

interface ChainValidationResult {
  valid: boolean;
  errors: string[];
  chain: X509Certificate[];  // leaf → ... → trust anchor
}

function validateDscChain(
  dscPem: string,
  trustStore: Map<string, X509Certificate>,  // keyed by fingerprint256
  intermediates?: X509Certificate[],
): ChainValidationResult {
  // 1. Parse DSC, check ca=false
  // 2. Validate DSC dates
  // 3. Find issuer via checkIssued() + verify()
  // 4. If issuer in trust store → done
  // 5. If issuer is intermediate → walk up to trust anchor
  // 6. Validate all certs in chain have valid dates
  // 7. Return chain or errors
}
```

## Prototype Code

The full prototype is in [`spike-6-prototype.mjs`](./spike-6-prototype.mjs). It:
- Generates test certificates via openssl (ECDSA P-256)
- Tests all Node.js `X509Certificate` API methods
- Validates 6 scenarios (good chain, rogue, wrong issuer, expired, intermediate, incomplete)
- Includes a manual chain validation function (~60 lines)
- All 46 tests pass
- Self-cleaning (removes generated certificates after run)
