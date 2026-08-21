# Verifiable Credentials

A **Verifiable Credential** (VC) is a tamper-evident container of claims about a subject, signed by an issuer in a way that anyone can verify. OpenCred produces credentials that conform to the [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/).

## Anatomy of a Credential

A VC has three logical parts:

1. **Metadata** — `@context`, `type`, `issuer`, `id`, `validFrom`, `validUntil`, optional `credentialStatus` and `credentialSchema`.
2. **Payload** — the `credentialSubject`, which contains the actual claims (e.g., name, degree, dates).
3. **Proof** — a cryptographic signature binding the payload to the issuer.

Example (Data Integrity proof, JSON-LD format):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://schema.nfh.global/contexts/education/v1"
  ],
  "id": "urn:uuid:c8e0e6b1-1b6c-4c2e-aa6d-0a3a15f8b0d4",
  "type": ["VerifiableCredential", "EducationCredential"],
  "issuer": "did:key:zDnaeXgu...",
  "validFrom": "2026-04-01T00:00:00Z",
  "validUntil": "2027-04-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:holder123",
    "name": "Jane Doe",
    "degree": "BSc Computer Science",
    "institution": "MIT",
    "dateConferred": "2026-06-15"
  },
  "credentialStatus": {
    "id": "https://dedi.global/dedi/lookup/mit/vc-revocation-registry/<hash>",
    "type": "dedi",
    "statusPurpose": "revocation",
    "statusListCredential": "https://dedi.global/dedi/query/mit/vc-revocation-registry"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "created": "2026-04-01T10:00:00Z",
    "verificationMethod": "did:key:zDnaeXgu...#zDnaeXgu...",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FXQjecWufY46..."
  }
}
```

## Proof Formats

OpenCred supports four proof formats. The choice affects compatibility, key types, and selective disclosure:

| Format | Identifier | Output | Selective Disclosure | Algorithm Support |
|---|---|---|---|---|
| Data Integrity | `data-integrity` | JSON-LD with embedded `proof` block | No | ECDSA P-256, ECDSA P-384, Ed25519 |
| VC-JWT (default) | `vc-jwt` | JSON-LD with embedded JWT in `proof.jwt` | No | ECDSA, Ed25519, RSA |
| JWS 2020 | `jws-2020` | JSON-LD with detached JWS in `proof.jws` | No | ECDSA, Ed25519, RSA |
| SD-JWT VC | `sd-jwt-vc` | Compact SD-JWT token string | Yes | ECDSA, Ed25519, RSA |

* **Data Integrity** uses the [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) framework with the `ecdsa-rdfc-2019` or `eddsa-rdfc-2022` cryptosuite. RSA is not supported in this format.
* **VC-JWT** wraps the credential as a JWT signed by the issuer's key. It is the default format because it works with every algorithm OpenCred supports.
* **JWS 2020** ([JsonWebSignature2020](https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/)) embeds a proof whose `jws` field is a detached RFC 7797 JWS (`<header>..<signature>`, header `{"alg", "b64": false, "crit": ["b64"]}`) over the RDFC-1.0-canonicalized credential. Works with every algorithm. Some existing verifier ecosystems (e.g. DigiLocker) require this shape. The suite context `https://w3id.org/security/suites/jws-2020/v1` is bundled and appended to `@context` automatically at issuance.
* **SD-JWT VC** ([IETF draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)) supports selective disclosure: the issuer marks claims as selectively disclosable, and the holder reveals only chosen claims to a verifier.

The implementation lives in `packages/crypto`:

* `prepareVcJwtProof` / `completeVcJwtProof` — VC-JWT
* `prepareProof` / `completeProof` — Data Integrity (ECDSA)
* `prepareEdDsaProof` / `completeEdDsaProof` — Data Integrity (Ed25519)
* `prepareJws2020Proof` / `completeJws2020Proof` — JWS 2020 (all algorithms)
* `prepareSdJwtVcProof` / `completeSdJwtVcProof` — SD-JWT VC

The `prepare/complete` split exists so that the actual signing operation can run elsewhere (hardware token, OS cert store, Cloud KMS) without exposing the unsigned credential or the signing buffer to a remote service.

## Building Credentials

OpenCred constructs unsigned credentials with `CredentialBuilder` from `packages/vc-core`:

```ts
import { CredentialBuilder } from "@opencred/vc-core";

const unsigned = new CredentialBuilder()
  .setIssuer("did:web:university.example")
  .setCredentialSubject({
    id: "did:example:holder123",
    name: "Jane Doe",
    degree: "BSc Computer Science",
  })
  .setValidFrom("2026-04-01T00:00:00Z")
  .setValidUntil("2027-04-01T00:00:00Z")
  .addType("EducationCredential")
  .build();
```

The builder enforces W3C VC 2.0 conformance: it requires `@context` to start with `https://www.w3.org/ns/credentials/v2`, requires strict ISO-8601 datetimes, and validates issuer and credential URIs.

## Status (Revocation)

Every credential OpenCred issues SHOULD include a `credentialStatus` block so that verifiers can check whether the credential has been revoked. OpenCred uses **DeDi Revocation List v1**, where the issuer's DeDi namespace stores only revoked hashes and verifiers query by computing the same hash from the credential body.

See the [Revocation](revocation.md) page for the full lifecycle.

OpenCred's verifier also accepts `BitstringStatusListEntry` (the W3C status list standard) and dispatches to the bitstring check when that type is present, but OpenCred itself does not generate bitstring status lists.

## Verification

The full verification flow lives in `packages/verification/src/verifier.ts`. For any input, OpenCred:

1. **Detects format** — Data Integrity (object with `proof`), VC-JWT (3 dot-separated parts with `vc` claim), JWS (3 parts with full credential payload), or SD-JWT VC (string containing `~`).
2. **Verifies the cryptographic proof** — dispatches to the format-specific verifier, which retrieves the issuer's public key via DID resolution.
3. **Checks dates** — `validFrom` is not in the future, `validUntil` has not passed.
4. **Checks revocation** — if `credentialStatus` is present and is a `dedi` or `BitstringStatusListEntry` type, the corresponding registry is queried.

The result is a `CredentialVerificationResult` with a list of named checks, each marked passed or failed with an optional detail string. The Desktop client surfaces this list in the Verify tab; the Docker server returns it in the `POST /credentials/verify` response.

## Further Reading

* W3C — [Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
* W3C — [Verifiable Credentials Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
* IETF — [SD-JWT-based Verifiable Credentials (draft)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
* RFC — [JSON Canonicalization Scheme (JCS) — RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) — used by OpenCred for revocation hashing
