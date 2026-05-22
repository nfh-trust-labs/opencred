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

> **Caveat — did:web rotation is not yet fully wired.** Today's `markDIDRotated` flow is semantically correct for `did:key` (each new key produces a new DID, so the prior DID record is logically retired in its entirety) but wrong for `did:web` (the DID stays stable across rotations; only one of its keys changes). The correct shape is multi-entry `verificationMethod[]` with per-key `supersededAt` metadata, backed by a new `POST /v1/keys/rotate` endpoint. Design recorded in [`docs/spikes/spike-619-did-web-rotation.md`](../spikes/spike-619-did-web-rotation.md); implementation tracked at [issue #619](https://github.com/nfh-trust-labs/opencred/issues/619). Until that lands, **keep did:web issuers on a stable key for the lifetime of the deployment** — swapping `OPENCRED_KEY_PATH` and restarting will produce signatures that nothing in DeDi or `.well-known/did.json` reflects. The verifier already iterates `verificationMethod[]` and matches by `kid`, so the multi-key shape works on the verify side today — the gap is publish-side only.

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
