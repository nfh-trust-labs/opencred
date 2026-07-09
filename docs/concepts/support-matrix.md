# Credential support matrix

The contract for what OpenCred can issue and verify, across both products (Desktop Client and Docker image). Every **valid** cell below is exercised on every release tag by the E2E matrix harness (`e2e/`, [workflow](../../.github/workflows/e2e-matrix.yml)) against the real Docker image — issue → verify through the public `@opencred/verify` SDK **and** the server's `/v1/credentials/verify` → tampered copy rejected.

## Algorithm × proof format

| Algorithm | `vc-jwt` | `data-integrity` | `sd-jwt-vc` |
|---|---|---|---|
| P-256 (ES256) | ✅ | ✅ (`ecdsa-rdfc-2019`) | ✅ |
| P-384 (ES384) | ✅ | ✅ (`ecdsa-rdfc-2019`) | ✅ |
| Ed25519 (EdDSA) | ✅ | ✅ (`eddsa-rdfc-2022`) | ✅ |
| RSA-2048/3072/4096 (PS256) | ✅ | ❌ **excluded by design** | ✅ |

**Why RSA × data-integrity is excluded**: the supported Data Integrity cryptosuites (`ecdsa-rdfc-2019`, `eddsa-rdfc-2022`) have no RSA variant. The issuance endpoint rejects the combination with a clear error; RSA issuers use `vc-jwt` or `sd-jwt-vc`.

## Issuer identity (DID method) × key type

| Signer key | Derived DID (method `key`) | did:web (method `web`) |
|---|---|---|
| EC (P-256/P-384) / Ed25519 | `did:key` (multicodec) | ✅ |
| RSA | `did:jwk` (no RSA multicodec exists) | ✅ |

Both `did:key` and `did:jwk` are self-describing — verifiers resolve them fully offline. `OPENCRED_ISSUER_DID_METHOD=key` accepts either. `did:web` requires `OPENCRED_ISSUER_DOMAIN` and gives you key rotation and a human-readable issuer identity.

**Rotation**: did:web only. A self-describing DID *is* its key, so "rotation" for did:key/did:jwk means regenerating the key (a new DID) and revoking the old key's record in DeDi.

## Key source × platform × DeDi lifecycle

Every signer type surfaces its public JWK (`SignerMetadata.publicKeyJwk`), so key publish/rotate/revoke against the DeDi `opencred-key-registry` works for all of them (#675, #676).

| Key source | Desktop | Docker | DeDi publish/rotate/revoke |
|---|---|---|---|
| Software key file (PEM/PKCS#8/PFX/JWK) | ✅ | ✅ | ✅ |
| macOS Keychain / Windows CNG | ✅ | — | ✅ |
| PKCS#11 hardware token | ✅ | ✅ | ✅ |
| AWS KMS / Azure Key Vault / GCP Cloud KMS | — | ✅ | ✅ |

## Export formats

Each issued credential round-trips through: JSON envelope (vc-jwt wraps its compact token as `proof: { type: "JsonWebSignature2020", jwt }` — the verifier unwraps and cross-validates it via the `envelope-consistency` check), compact token (sd-jwt-vc), PixelPass QR, and PDF (credential embedded in the info dictionary, verified by `verify.pdf()`).

## Verification result codes

Consistent across proof formats: `VALID`, `INVALID` (signature/structure), `EXPIRED` (validUntil passed — including vc-jwt `exp`), `REVOKED` (credential revoked **or** signing key revoked), `UNRESOLVABLE` (issuer DID or registry unreachable when required). A rotated (not revoked) key keeps previously-issued credentials `VALID`.

## DeDi-dependent checks

| Check | DeDi configured | DeDi not configured |
|---|---|---|
| Credential revocation | enforced (fail-closed on outage) | **not checked** — surfaced as a non-failing `revocation` check row saying so |
| Key status (active/rotated/revoked) | enforced; revoked key ⇒ `REVOKED` | not checked |
| did:web resolution | HTTPS, falls back to DeDi registry | HTTPS only |

## Known limits

- Per-key status writes are serialised in-process; concurrent writers on **different** machines can still race (last-writer-wins) until DeDi exposes compare-and-swap on `update-record` — tracked with the DeDi team.
- DeDi registry queries are not paginated by the client; lifecycle operations use direct record lookups, which is why this hasn't mattered in practice.
- The health endpoint reports DeDi *configuration*, not DeDi *reachability* — probing DeDi from every replica's health check would add load and flakiness for little signal; outages surface in the issuance/verification paths' own errors and metrics.
