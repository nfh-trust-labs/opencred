# Decentralized Identifiers (DIDs)

A **Decentralized Identifier** (DID) is a globally unique identifier that the issuer controls without needing a central registry. Every credential OpenCred issues identifies the issuer with a DID. When a verifier sees `"issuer": "did:web:university.example"`, it resolves that DID to obtain the public key needed to check the signature.

OpenCred supports three DID methods today: `did:key`, `did:jwk`, and `did:web`. Each makes a different tradeoff between offline verification, key rotation, and infrastructure requirements.

## did:key

`did:key` encodes the public key directly into the DID string using multibase encoding. The verifier extracts the key from the DID itself — no network call is required.

```
did:key:zDnaeXgu1JSV2qzsh7VRdXBfwBTcj4PFXYbkjyvY3RPg6dh3o
```

* **Implementation**: `packages/did/src/did-key.ts` (`DIDKeyResolver`, `deriveDidKeyId`).
* **When to use**: offline-first scenarios, peer-to-peer issuance, ad-hoc credentials, demos and testing. The Desktop Client uses `did:key` by default for the Generated Key flow when no domain is configured.
* **Tradeoffs**: no key rotation. If the key is compromised, every credential signed with it must be revoked individually. The credential is fully self-contained, which makes it the only DID method that supports completely offline verification.

## did:jwk

`did:jwk` encodes a JSON Web Key inside the DID string. Like `did:key`, no resolution call is needed.

```
did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjY3OTAuLi4iLCJ5IjoiOEgyZi4uLiJ9
```

* **Implementation**: `packages/did/src/did-jwk.ts` (`DIDJwkResolver`, `encodeDidJwk`).
* **When to use**: when interoperating with systems that expect a JWK-based key representation. Functionally equivalent to `did:key` for OpenCred's purposes.
* **Tradeoffs**: same as `did:key` — offline-resolvable, no rotation, larger DID string.

## did:web

`did:web` resolves to a DID document hosted at a well-known HTTPS URL on the issuer's own domain.

```
did:web:university.example      → https://university.example/.well-known/did.json
did:web:example.com:students    → https://example.com/students/did.json
did:web:example.com%3A3000      → https://example.com:3000/.well-known/did.json
```

The `:` character separates path segments, and a port is encoded as `%3A`. See `didWebToUrl` in `packages/did/src/did-web.ts`.

* **Implementation**: `packages/did/src/did-web.ts` (`DIDWebResolver`, `encodeDidWeb`, `generateDidWebDocument`).
* **When to use**: institutional issuers (universities, employers, governments) that own a domain and can publish a DID document. This is the default for the Self-Published Keys onboarding path in the Desktop Client.
* **Tradeoffs**: requires the issuer to host an HTTPS endpoint and maintain a TLS certificate. Verification requires network access. The benefit is **key rotation** — the issuer publishes a new DID document and verifiers automatically pick it up.

### How OpenCred resolves did:web safely

`did:web` is a network operation, and any network operation is a candidate for SSRF (Server-Side Request Forgery). The `DIDWebResolver` enforces several defenses:

1. **HTTPS only** — the `did:web` spec requires HTTPS, and OpenCred refuses any other scheme.
2. **No redirects** — `fetch` is called with `redirect: "error"`, so the resolver will not follow a 302 to an internal address.
3. **DNS resolution + private-IP check** — the resolver looks up both A and AAAA records, then rejects the request if **any** resolved IP is private, loopback, link-local, or IPv4-mapped IPv6 in those ranges. The check lives in `packages/shared/src/ssrf.ts` (`isPrivateIP`).
4. **10-second timeout** — `AbortController` cancels the fetch if the server is slow.
5. **Document ID validation** — the resolved document's `id` field MUST equal the requested DID, otherwise resolution fails.

These guarantees are non-negotiable; see the [SSRF invariant](../security/invariants.md#7-didweb-resolution-requires-ssrf-protection) for the rationale.

The resolver also accepts an optional fallback (typically a DeDi-backed DID resolver). The fallback is **only** tried when the primary HTTPS resolution fails — and it is **not** tried on SSRF violations, since those are security boundaries, not transient errors.

### CORD anchoring as supplementary provenance

When an issuer publishes a DID document via DeDi (`POST /v1/keys/publish` on the Docker server, or the Desktop "publish to DeDi" action), the DeDi instance may additionally anchor that record on the [CORD blockchain](https://cord.network/). Subsequent `/v1/keys/resolve` responses then carry an extra `proof` block alongside the DID document, e.g.:

```json
{
  "did": "did:web:university.example",
  "document": { "...": "..." },
  "keyStatus": "current",
  "proof": {
    "type": "DediRecordProof2026",
    "creator_did": "did:web:university.example",
    "namespace_did": "did:web:did.cord.network:university",
    "digest": "0x…",
    "network_genesis": "0x…"
  }
}
```

This anchor is **supplementary provenance**, not VC-signature verification. It tells a verifier "DeDi reports this DID record was anchored on CORD by `creator_did`". The verifier's `registryAnchor` advisory check (`packages/verification/src/checks.ts`) surfaces a UI badge when the proof is present and matches the issuer DID, and surfaces a suspicion badge when the `creator_did` does **not** match — indicating the DID record was anchored by a different party than the credential's issuer. Absence of a proof is benign on DeDi instances that don't anchor; the check degrades open.

The credential's cryptographic signature remains the sole authority on whether the credential itself is valid. CORD anchoring exists so verifiers can independently confirm the *record* (the public key DeDi serves) was published on-chain by the claimed party, in addition to whatever trust they place in DeDi itself. A future iteration will look up the digest on-chain rather than trusting the DeDi-attached proof; today the proof is opaque metadata, and a compromised DeDi could fabricate it.

### Key rotation on DeDi-published DIDs

When an issuer publishes a DID document to DeDi, the record carries a `keyStatus` field that is `"current"` while the key is in active use. When the issuer later generates a new key from the Desktop client, **every previously-published DID for that client is automatically marked rotated** on DeDi (`markDIDRotated`) — the new DID is excluded from the list. See [Desktop → Key Management → Auto-rotation on key generation](../desktop/key-management.md#auto-rotation-on-key-generation) for the desktop side, and `packages/dedi-client/src/publish-manager.ts` for the rotation primitive.

The rotation flag is **advisory**:

- Credentials signed under a rotated key remain **cryptographically valid**. The signature continues to verify against the key the issuer used at signing time, and nothing about the underlying VC has changed.
- Verifier UIs can read `keyStatus` from the resolved DID record (via `/v1/keys/resolve`) and surface a "key rotated" badge so end users know the issuer has since moved to a new key.
- The OpenCred verifier emits this as the `keyRotation` check on the verify response — `passed: false` when DeDi reports rotation, `passed: true` (and silent) otherwise. The headline `valid` boolean is unchanged by rotation.
- The flag is monotone (`current → rotated`, never back) and append-only, so concurrent `markDIDRotated` writes are safe without optimistic locking on the DeDi side. See `packages/dedi-client/src/adapter/types.ts` for the invariant discussion.

### did:web key rotation

`did:web` issuers rotate keys via **`POST /v1/keys/rotate`** without changing the DID. The server appends the new key to `verificationMethod[]`, stamps `supersededAt` on the prior current key (so already-issued credentials continue to verify against it via `kid`), and points `assertionMethod` at the new key. The DID itself stays stable across rotations — that stability is the whole point of paying for did:web hosting.

```
Operator: swap OPENCRED_KEY_PATH, restart container, then:

  curl -X POST http://localhost:3100/v1/keys/rotate \
    -H "Authorization: Bearer $OPENCRED_API_KEY"

  → { rotated: true,
      did: "did:web:issuer.example.org",
      currentKeyId: "did:web:issuer.example.org#key-2",
      superseded: ["did:web:issuer.example.org#key-1"],
      namespace: "issuer.example.org" }
```

**Idempotency**: re-running rotate against a document that already carries the active key returns `{rotated: false, reason: "already-current"}` without writing — safe to retry after a transient network failure.

**Verifier impact**: none. `packages/verification/src/vc-jwt.ts` already iterates `verificationMethod[]` and matches by `kid` from the JWT header, so credentials signed under any prior (now-superseded) key still verify against their original key. The verifier's existing `keyStatus: rotated` badge is unused for did:web — rotation lives inside the document, not on the DID record's status flag.

**`markDIDRotated` semantic split (since #627)**: the desktop-side `markDIDRotated` hook (used by the desktop's key-generate path) is now did:key-only. For did:web, it logs a warn and no-ops at the record level; rotation is the `/v1/keys/rotate` endpoint's job.

**Concurrency**: today's `rotateDIDWeb` is last-writer-wins. Multi-replica deployments running simultaneous rotations against the same DID risk one rotation clobbering the other. DeDi-side optimistic concurrency is the right long-term fix — see [`docs/spikes/spike-619-did-web-rotation.md`](../spikes/spike-619-did-web-rotation.md) §5.

**Out of scope for v1**: KMS-backed signer rotation (KMS public-key extraction is a separate work item — today only software signers expose `publicKeyJwk`), per-key revocation flags distinct from `supersededAt`, and rotation audit log.

### Auto-publishing the issuer DID at startup (opt-in)

Operators can opt into having the container publish its issuer DID to DeDi at startup, instead of running `POST /v1/keys/publish` manually after first boot. Set `OPENCRED_AUTO_PUBLISH_KEY=true` alongside the DeDi configuration. Works for both did:key and did:web. The publish is idempotent (the second boot logs an "already published" skip), and `/v1/health` reports `didAutoPublished: true` once the publish (or idempotent skip) succeeds. The flag fails closed at startup if DeDi is not configured — there is no silent no-op. For did:web specifically, `OPENCRED_DEDI_HOST_DID_DOC=true` is an alias that also triggers the publish path; the two flags are mutually compatible. Default for both is OFF — the explicit-publish flow remains the documented default.

## CompositeDIDResolver

`packages/did/src/composite-resolver.ts` ties the three methods together. The Docker server and Desktop client both use a composite resolver during verification:

```ts
import {
  DIDKeyResolver,
  DIDJwkResolver,
  DIDWebResolver,
  CompositeDIDResolver,
} from "@opencred/did";

const resolver = new CompositeDIDResolver(
  new Map([
    ["key", new DIDKeyResolver()],
    ["jwk", new DIDJwkResolver()],
    ["web", new DIDWebResolver()],
  ]),
);
```

The composite resolver inspects the DID method (`did:<method>:...`) and dispatches to the matching resolver. Adding new methods (e.g., KERI in a future release) only requires registering them on the map.

## Choosing a Method

| Need | Use |
|---|---|
| Fully offline verification | `did:key` or `did:jwk` |
| Key rotation | `did:web` |
| Issuer owns a domain | `did:web` |
| Institutional issuance with TLS-anchored trust | `did:web` |
| Demos, peer-to-peer, field deployment | `did:key` |

The [Trust chains](trust-chains.md) page describes how each method maps to a complete trust chain back to a root.

## Further Reading

* W3C — [DID Core 1.0](https://www.w3.org/TR/did-core/)
* W3C CCG — [did:key Method Spec](https://w3c-ccg.github.io/did-method-key/)
* W3C CCG — [did:web Method Spec](https://w3c-ccg.github.io/did-method-web/)
* W3C CCG — [did:jwk Method Spec](https://github.com/quartzjer/did-jwk/blob/main/spec.md)
