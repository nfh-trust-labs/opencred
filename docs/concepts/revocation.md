# Revocation

Verifiable credentials need a way to be invalidated after they're issued — for example, a degree may be rescinded, or a key may be compromised. The W3C VC Data Model 2.0 defines [`credentialStatus`](https://www.w3.org/TR/vc-data-model-2.0/#status) as the extension point. OpenCred uses **DeDi Revocation List v1**, a deterministic hash-lookup model backed by the [Decentralized Directory (DeDi)](https://dedi.global/).

## DeDi Revocation List v1

Under DeDi Revocation List v1, the registry stores **only revoked hashes** — never issuance-time hashes. A credential is valid if its hash is *not* in the registry, and revoked if it is. This is the canonical DeDi `revoke` tag ([`revoke.json`](https://dedi.global/revoke.json)) — **record existence signifies revocation**; there is no boolean flag inside `details`. The optional `reason` field on a revocation record is preserved verbatim and surfaced by `/v1/credentials/revocation-status` lookups.

The hash is deterministic: any party (issuer or verifier) can compute the same hash from the credential body. The formula is:

```
revocationHash = SHA-256(JCS(credential))
```

In other words, the implementation JCS-canonicalizes the **entire credential** (exactly as passed in) and takes the lowercase-hex SHA-256 of the canonical bytes. Where **JCS** is [JSON Canonicalization Scheme — RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). JCS guarantees that any two JSON values that are semantically equivalent serialize to the same byte sequence, which makes the hash reproducible across implementations.

Callers that want a stable hash across issuance and verification MUST pass the same credential shape to both sides — typically the unsigned credential, or the signed credential with the `proof` block stripped. The crypto package does not strip fields for you.

The implementation lives in `packages/crypto/src/jcs.ts`:

* `jcsCanonicalize(value)` — RFC 8785 canonicalization
* `computeRevocationHash(credential)` — full hash computation

## credentialStatus Block

OpenCred embeds `credentialStatus` at issuance time. The `id` is a deterministic lookup URL inside the issuer's DeDi namespace; the `statusListCredential` is the registry endpoint.

```json
{
  "credentialStatus": {
    "id": "https://dedi.global/dedi/lookup/<namespace>/vc-revocation-registry/<hash>",
    "type": "dedi",
    "statusPurpose": "revocation",
    "statusListCredential": "https://dedi.global/dedi/query/<namespace>/vc-revocation-registry"
  }
}
```

`namespace` is the issuer's DeDi namespace. The actual `<hash>` is computed at issuance and embedded in the `id` URL so that a verifier can simply GET the URL to check status.

For requests where the issuer wants to use this flow they pass `revocationRegistryUrl` to the issue endpoint and OpenCred fills in the `credentialStatus` block. The Docker server's `POST /credentials/issue` endpoint accepts `revocationRegistryUrl` as an optional field; see `apps/server/src/routes/credentials.ts`.

## Lifecycle

### At issuance time

OpenCred:

1. Builds the unsigned credential with `CredentialBuilder` (see `packages/vc-core`).
2. If a `revocationRegistryUrl` is supplied, computes the revocation hash and embeds `credentialStatus`.
3. Signs the credential with the issuer's local key.

OpenCred does **not** publish anything to DeDi at issuance time. There is nothing to publish — the registry only stores revoked hashes, not issued ones.

### At revocation time

The issuer:

1. Computes the revocation hash for the credential they want to revoke. The Desktop client computes this locally (see `apps/desktop/src/main/`); the Docker server exposes `POST /credentials/revocation-hash` and `POST /credentials/revocation-hash/batch`.
2. Publishes the hash to **their own** DeDi namespace using their own DeDi credentials.

OpenCred deliberately does not publish hashes to DeDi on the issuer's behalf. The issuer is the only party with authority over their namespace, and OpenCred has no business handling DeDi auth tokens for them. (See `packages/dedi-client` for the client used by tooling that does want to publish.)

### At verification time

The verifier:

1. Computes the same revocation hash from the credential body using the same JCS + SHA-256 procedure.
2. Queries the issuer's DeDi registry — typically by GETting `credentialStatus.id` (the lookup URL).
3. If the hash is found, the credential is **REVOKED**. If not, it's **VALID** (assuming all other checks pass).

The check lives in `packages/verification/src/checks.ts` (`checkRevocation`).

## DeDi Client

The OpenCred packages include a DeDi HTTP client at `packages/dedi-client`. It provides:

* `DeDiClient` — high-level adapter (revocation, key records, schemas, contexts)
* `DeDiApiClient` — low-level API client
* `DeDiPublishManager` — orchestrator for publishing operations
* `CircuitBreaker`, `withRetry` — resilience helpers
* `DeDiTokenManager` — bearer-token auth flow

Tooling (CLI, scripts) can use these to publish revocation hashes. The Desktop Client embeds the publish manager so users can revoke from the UI.

## BitstringStatusList

OpenCred's verifier also accepts the [W3C Bitstring Status List 1.0](https://www.w3.org/TR/vc-bitstring-status-list/) format. When a credential's `credentialStatus.type` is `BitstringStatusListEntry`, the verifier dispatches to the bitstring check (`checkBitstringStatusList` in `packages/verification/src/checks.ts`) instead of the DeDi hash check.

OpenCred does **not** generate or host bitstring status lists. Issuers who want to use bitstrings can implement that side themselves and embed the appropriate `credentialStatus` block; OpenCred's verifier will honour it.

## Why hash lookup instead of bitstrings?

Bitstring status lists are efficient for very large credential populations (millions of credentials) because the verifier downloads a compact bitstring once and checks any credential locally. They're more complex to operate, however: the issuer must maintain a status list URL, allocate bit positions, manage list rotation, and serve updates.

Hash lookup is the opposite tradeoff: every verification requires a network call to DeDi, but operationally the issuer just publishes hashes when they revoke. For OpenCred's primary user — small to mid-size institutional issuers — hash lookup is the simpler model. Bitstrings remain available as an opt-in for issuers who need them.

## Key revocation vs. per-credential revocation

OpenCred supports two distinct types of revocation that operate at different granularities:

### Per-credential revocation (the `vc-revocation-registry`)

Described in detail in the sections above. The issuer publishes a hash of a specific credential to DeDi. Only that credential is affected; other credentials from the same issuer and same key are unaffected.

**Use this when:** a credential needs to be withdrawn for a reason specific to the holder or the credential's content — a degree was rescinded, an employment credential is no longer accurate, or the holder requests removal.

### Key revocation (the `opencred-key-registry`)

Key revocation operates at the level of a **signing key**, not an individual credential. When a key is compromised, the issuer flips its status to `revoked` in the `opencred-key-registry`. **Every credential that key ever signed is then rejected by DeDi-aware verifiers** with a top-level `REVOKED` outcome, regardless of when those credentials were issued.

**Use this when:** a signing key is compromised. No individual per-credential entries are needed — the key status itself signals to verifiers that nothing the key signed can be trusted.

**API:** `POST /v1/keys/revoke` — see [Docker API Reference → POST /v1/keys/revoke](../docker/api-reference.md#post-v1keysrevoke).

**Important distinction — `rotated` is not `revoked`:**

A key that was cleanly rotated (status `rotated`) is not compromised. Credentials it signed remain valid and verifiers accept them. Only `revoked` triggers the blanket rejection. See [Concepts → DIDs → Per-key registry](dids.md#per-key-registry--the-opencred-key-registry-model) for the full status model.

### The "no DeDi status available" case — credential stays VALID

This is important to understand correctly: **the absence of a key-status check is not a failure.**

Consider a `did:key` credential that has no `credentialStatus` block:

1. The verifier checks the cryptographic signature — passes or fails on its own merits.
2. There is no `credentialStatus.id` URL, so no DeDi namespace can be derived.
3. The key-status check is skipped. The verify response shows the check as "not checked" (or omits it entirely).
4. **The credential is displayed as valid** if the signature check passed.

The same applies when DeDi is temporarily unreachable (outage), or when a lookup returns 404 (no record exists yet for that key). In all these cases the credential's validity rests entirely on its cryptographic signature. DeDi key status is _additive_ — it can only further downgrade a credential that is already cryptographically valid (by finding an explicit `revoked` record), but it never blocks a credential when status is unavailable.

This "degrade open" behavior is intentional. A DeDi outage must never prevent verification of a legitimately-issued credential.

```
Credential with no credentialStatus
  → Signature check: PASS
  → Key status check: SKIPPED (no namespace pointer)
  → Result: VALID   ← correct; DeDi is not consulted

Credential with credentialStatus, DeDi returns 404
  → Signature check: PASS
  → Key status check: NOT FOUND → degrade open
  → Result: VALID   ← correct; absence of a revocation record means not revoked

Credential with credentialStatus, DeDi returns revoked
  → Signature check: PASS (the signature is still mathematically correct)
  → Key status check: REVOKED
  → Result: REVOKED ← correct; the key was compromised
```

## Future Models

The PRD mentions two future revocation models that are **not** currently implemented:

* **Signed Revocation Receipts** — OpenCred returns a signed receipt confirming a hash computation. The issuer presents this receipt to a registry as proof of computation, removing the need for OpenCred to integrate directly with any specific registry.
* **Per-Request Credential Pass-Through** — instead of any persistent registry, the issuer accepts the full credential at revocation-check time and returns a real-time decision. Eliminates the registry entirely but requires the issuer to retain credential copies.

If adopted, these will be specified in dedicated PRD subsections and reflected in the API contract.
