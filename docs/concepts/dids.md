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
