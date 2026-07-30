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
2. **No redirects** — redirects are never followed; a 3xx surfaces as an error, so the resolver will not follow a 302 to an internal address.
3. **DNS resolution + private-IP check** — the resolver looks up both A and AAAA records, then rejects the request if **any** resolved IP is private, loopback, link-local, or IPv4-mapped IPv6 in those ranges. The check lives in `packages/shared/src/ssrf.ts` (`resolveDnsForSsrf` / `isPrivateIP`).
4. **Connection pinned to the validated IPs** — the actual fetch (`fetchWithPinnedIp` in `packages/shared/src/pinned-fetch.ts`) connects only to the addresses that passed the check; DNS is never re-consulted, which closes the DNS-rebinding TOCTOU window. The URL keeps the hostname so TLS certificate validation still runs against it.
5. **10-second timeout** — `AbortController` cancels the fetch if the server is slow.
6. **Document ID validation** — the resolved document's `id` field MUST equal the requested DID, otherwise resolution fails.

These guarantees are non-negotiable; see the [SSRF invariant](../security/invariants.md#7-didweb-resolution-requires-ssrf-protection) for the rationale.

The resolver also accepts an optional fallback (typically a DeDi-backed DID resolver). The fallback is **only** tried when the primary HTTPS resolution fails — and it is **not** tried on SSRF violations, since those are security boundaries, not transient errors.

### Publishing your did:web DID Document

Once you've decided to issue under `did:web`, you need to make the DID Document resolvable. There are two independent paths — they are NOT alternatives that "fall through" to each other. Generic W3C did:web resolvers walk the canonical HTTPS URL only; DeDi-aware resolvers can use either path.

#### Path A — Self-host on your own domain (canonical did:web)

The standards-compliant way. The DID Document lives at a well-known HTTPS URL on your domain.

```
did:web:issuer.example.com              → https://issuer.example.com/.well-known/did.json
did:web:example.com:tenants:acme        → https://example.com/tenants/acme/did.json
```

Operator workflow:

1. Start the server with `OPENCRED_ISSUER_DID_METHOD=web` and `OPENCRED_ISSUER_DOMAIN=<your-domain>`. No DeDi config is required. `<your-domain>` may include colon-separated path segments to host the document at a sub-path — `acme.com:tenants:hr` becomes `did:web:acme.com:tenants:hr`, served at `https://acme.com/tenants/hr/did.json`.
2. Generate the DID Document using the canonical shape from `generateDidWebDocument` (`packages/did/src/did-web.ts:59`): a `@context` array, the DID as `id`, one `verificationMethod` entry with `type: "JsonWebKey"` and the issuer's `publicKeyJwk`, and the verification-method ID listed under `assertionMethod`, `authentication`, `capabilityInvocation`, and `capabilityDelegation`.
3. Serve that JSON at `https://<your-domain>/.well-known/did.json` (S3, GitHub Pages, nginx, Caddy — any static-JSON-over-HTTPS host works).
4. Verify with `curl -fsSL https://<your-domain>/.well-known/did.json`. The document's `id` MUST equal the requested DID, or OpenCred's verifier (`packages/verification/src/did-web.ts`) will reject it.

Pros: works with any standards-compliant did:web verifier. No DeDi dependency for issuance or verification.

Cons: requires a domain, TLS, and a place to host static JSON. Key rotation means re-publishing the document.

> **SSRF guardrails apply to the verifier side.** OpenCred's did:web resolver enforces HTTPS-only, no redirects, public-IP-only (no private / loopback / link-local / IPv4-mapped IPv6), and a 10-second timeout. CDNs that return a 302 redirect, hosts behind a private IP, or HTTP-only setups will fail resolution. See the [SSRF invariant](../security/invariants.md#7-didweb-resolution-requires-ssrf-protection).

#### Path B — Publish to DeDi's `opencred-key-registry`

Useful when you don't control a domain, you're running a demo/bootcamp, or your verifier audience all uses OpenCred-aware tooling (`@opencred/verify` SDK or the OpenCred verifier).

Operator workflow:

1. Start the server with `OPENCRED_ISSUER_DID_METHOD=web`, `OPENCRED_ISSUER_DOMAIN=<your-domain>`, the DeDi env vars (`OPENCRED_DEDI_BASE_URL`, auth, `OPENCRED_DEDI_NAMESPACE`), AND `OPENCRED_AUTO_PUBLISH_KEY=true` (or the equivalent did:web-only alias `OPENCRED_DEDI_HOST_DID_DOC=true`).
2. The container logs `Issuer DID auto-published to DeDi at startup` on first boot, and `Issuer DID already published to DeDi (idempotent skip)` on subsequent restarts. `/v1/health` reports `didAutoPublished: true`.
3. Alternatively, leave the flag off and call `POST /v1/keys/publish` once — same outcome.
4. Verifiers configured with the same DeDi instance resolve keys via `POST /v1/keys/resolve` (or `GET /v1/keys/resolve?verificationMethod=...` — the CDN-cacheable form).

Pros: zero hosting infrastructure beyond DeDi. Key rotation is `POST /v1/keys/rotate` (read-merge-write on the existing record, `kid` continuity preserved for old credentials — see below).

Cons: **DeDi-hosted did:web documents are NOT reachable at `https://<your-domain>/.well-known/did.json`** unless you ALSO upload them there. Pure W3C did:web resolvers (one not configured with DeDi as a fallback / wired via `createDeDiDIDWebFallback` in `packages/verification/src/did-web.ts`) will get a 404 on the canonical URL. If you need both audiences, follow Path A and Path B in parallel — the two are independent and do not conflict at the issuer side.

#### Choosing between A and B

| Need | Path |
|---|---|
| Production / interop with any W3C did:web verifier | **A** (self-host) |
| You already operate DeDi, your verifiers are OpenCred-aware | **B** (DeDi publish) — easier ops |
| Demo / bootcamp / no domain | **B** (DeDi publish) |
| Maximum reach (DeDi-aware + generic verifiers) | **A + B** in parallel |

The signing path is identical for both — your VC signatures don't change. Only the discovery path for the public key differs.

### CORD anchoring as supplementary provenance

When an issuer publishes a key via DeDi (`POST /v1/keys/publish` on the Docker server, or the Desktop "publish to DeDi" action), the DeDi instance may additionally anchor that key record on the [CORD blockchain](https://cord.network/). Subsequent `/v1/keys/resolve` responses then carry an extra `proof` block on the resolved `KeyRecord`, e.g.:

```json
{
  "keyId": "did:web:university.example#key-0",
  "controllerDid": "did:web:university.example",
  "algorithm": "P-256",
  "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "purpose": ["assertionMethod"],
  "status": "active",
  "proof": {
    "type": "DediRecordProof2026",
    "creator_did": "did:web:university.example",
    "namespace_did": "did:web:did.cord.network:university",
    "digest": "0x…",
    "network_genesis": "0x…"
  }
}
```

The `proof` block sits on the per-key record (the same place an embedded `did.json` snapshot would surface as the optional `document` field). This anchor is **supplementary provenance**, not VC-signature verification. It tells a verifier "DeDi reports this key record was anchored on CORD by `creator_did`". The verifier's `registryAnchor` advisory check (`packages/verification/src/checks.ts`) surfaces a UI badge when the proof is present and matches the issuer DID, and surfaces a suspicion badge when the `creator_did` does **not** match — indicating the key record was anchored by a different party than the credential's issuer. Absence of a proof is benign on DeDi instances that don't anchor; the check degrades open.

The credential's cryptographic signature remains the sole authority on whether the credential itself is valid. CORD anchoring exists so verifiers can independently confirm the *record* (the public key DeDi serves) was published on-chain by the claimed party, in addition to whatever trust they place in DeDi itself. A future iteration will look up the digest on-chain rather than trusting the DeDi-attached proof; today the proof is opaque metadata, and a compromised DeDi could fabricate it.

### Key rotation on DeDi-published keys

When an issuer publishes a key to DeDi via `POST /v1/keys/publish`, the key record carries a `status` field that is `"active"` while the key is in use. When the issuer later rotates to a new key (via `POST /v1/keys/rotate` for did:web, or by generating a new did:key), the old key is flipped to `"rotated"`. See [Desktop → Key Management → Rotating a key](../desktop/key-management.md#rotating-a-key) for the desktop side, and `packages/dedi-client/src/publish-manager.ts` for the rotation primitive.

The `rotated` status is **advisory**:

- Credentials signed under a rotated key remain **cryptographically valid**. The signature continues to verify against the key the issuer used at signing time, and nothing about the underlying VC has changed.
- Verifier UIs can read `status` from the resolved key record (via `POST /v1/keys/resolve`) and surface a "key rotated" badge so end users know the issuer has since moved to a new key.
- The OpenCred verifier emits this as the `keyRotation` check on the verify response — `passed: false` when DeDi reports `rotated`, silent otherwise. The headline `valid` boolean is unchanged by rotation.
- The status transitions monotonically (`active → rotated`, never back). Rotated key records are retained forever in DeDi so historical credentials can always be verified.

### did:web key rotation

`did:web` issuers rotate keys via **`POST /v1/keys/rotate`** without changing the DID. The new key is published to the `opencred-key-registry` at the **next sequential fragment** (`#key-1`, `#key-2`, …) as `active`; the prior key is flipped to `rotated` and kept — at its own distinct fragment — in the regenerated multi-key `did.json`. The DID itself stays stable across rotations — that stability is the whole point of paying for did:web hosting.

Because each rotation gets its own fragment, the rotated key and the new key never collide on an identifier: both remain dereferenceable in the `did.json`, so **credentials signed under the previous did:web key still verify after rotation**. (This closed the earlier `#key-0` collision limitation tracked in [#653](https://github.com/nfh-trust-labs/opencred/issues/653).)

```
Operator: swap OPENCRED_KEY_PATH, restart container, then:

  curl -X POST http://localhost:3100/v1/keys/rotate \
    -H "Authorization: Bearer $OPENCRED_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "newKeyIndex": 2,
      "previousVerificationMethod": "did:web:issuer.example.org#key-1",
      "hostDidDocument": true
    }'

  → { rotated: true,
      did: "did:web:issuer.example.org",
      currentKeyId: "did:web:issuer.example.org#key-2",
      newKeyIndex: 2,
      retired: { changed: true, keyId: "did:web:issuer.example.org#key-1",
                 from: "active", to: "rotated", namespace: "issuer.example.org" },
      didDocument: { id: "did:web:issuer.example.org", verificationMethod: ["…"] },
      didDocumentStored: true }
```

**Verifier impact (did:key)**: none. Credentials signed under any prior (now-rotated) did:key still verify — the old DID is self-describing and the key record is retained in DeDi with `status: "rotated"`. DeDi-aware verifiers surface a `keyRotation` advisory check (headline `valid` is unchanged). **For did:web**: also none — the rotated key keeps its own sequential fragment in the multi-key `did.json`, so credentials signed under it still resolve and verify; a DeDi-aware verifier additionally surfaces the `keyRotation` advisory.

**Desktop key-generate hook**: the desktop's key-generate path flips every previously-published key to `rotated` per-key via `DeDiPublishManager.setKeyStatus(verificationMethod, "rotated")` (it tracks published verification methods in `dediPublishedKeys`). This is the per-key counterpart to the older whole-DID `markDIDRotated` flow, which the per-key registry redesign replaced. Full did:web rotation — appending the new key at the next sequential fragment and regenerating the multi-key `did.json` — is the `/v1/keys/rotate` endpoint's job.

**Concurrency**: today's implementation is last-writer-wins for the DeDi write. Multi-replica deployments running simultaneous rotations against the same DID risk one rotation clobbering the other. DeDi-side optimistic concurrency is the right long-term fix — see [`docs/spikes/spike-619-did-web-rotation.md`](../spikes/spike-619-did-web-rotation.md) §5.

**Out of scope for v1**: rotation audit log. (KMS-backed rotation became possible in #675 — Cloud HSM signers now expose `publicKeyJwk`; note that rotating the KMS key *version* remains a provider-side operation.)

### Auto-publishing the issuer DID at startup (opt-in)

Operators can opt into having the container publish its issuer DID to DeDi at startup, instead of running `POST /v1/keys/publish` manually after first boot. Set `OPENCRED_AUTO_PUBLISH_KEY=true` alongside the DeDi configuration. Works for both did:key and did:web. The publish is idempotent (the second boot logs an "already published" skip), and `/v1/health` reports `didAutoPublished: true` once the publish (or idempotent skip) succeeds. The flag fails closed at startup if DeDi is not configured — there is no silent no-op. For did:web specifically, `OPENCRED_DEDI_HOST_DID_DOC=true` is an alias that also triggers the publish path; the two flags are mutually compatible. Default for both is OFF — the explicit-publish flow remains the documented default.

---

## Per-key registry — the `opencred-key-registry` model

OpenCred uses DeDi's native **one-record-per-key** model to track the lifetime of every signing key an issuer has ever used. This is the authoritative source of truth that a DeDi-aware verifier consults: "is this specific key still valid?"

### One registry per issuer namespace

Each issuer operates within a verified DeDi **namespace** (their domain, e.g. `riverside.edu`). A single key registry lives inside it:

| Registry | Record key | Payload | Role |
|---|---|---|---|
| `opencred-key-registry` | `slug(verificationMethod)` — e.g. `did-web-riverside-edu-key-0` | `{ keyId, controllerDid, algorithm, publicKeyJwk, purpose[], status, document? }` | **Source of truth for "is this key live?"** One record per key. `status` is `active`, `rotated`, or `revoked` — the only mutable field. Old key records are retained forever — historical credentials can still be verified even after the key has been superseded. The optional `document?` is the **immutable `did.json` snapshot** of that key's era (see below). |

There is **no separate `did-documents` registry.** The assembled `did.json` is carried **on each key record** as the optional `document?` field, not in a registry of its own. did:key issuers never store a document — the DID is self-describing.

A per-credential revocation registry (`vc-revocation-registry`) also lives in the namespace — that is documented in [Concepts → Revocation](revocation.md) and is unaffected by this model.

### Key lifecycle — three states

```
generate
   │
   ▼
[active] ──── rotate (clean) ──────► [rotated]   ← kept in did.json; credentials remain VALID
   │
   └──── revoke (compromised) ──────► [revoked]   ← dropped from did.json relationships; ALL credentials REJECTED
```

The status is **monotone** — `active → rotated → revoked`, never backward — which is what makes it safe to advance under DeDi's lock-free `update-record`. `status` is the **only mutable field** on a key record; every other field, including the `document` snapshot, is immutable.

- **`active`** — the key is currently in use for signing. Any signature it produces is valid.
- **`rotated`** — the key was cleanly retired. The issuer generated a new key; no compromise occurred. **Credentials signed by a rotated key remain cryptographically valid and are accepted** by verifiers. For **`did:key`** this is automatic — each new did:key produces an entirely new DID, and the old self-describing DID still resolves the old key. For **`did:web`** the issuer rotates *without changing the DID*: the new key is published at the next sequential fragment (`#key-1`, `#key-2`, …) and both the old and new keys coexist in the multi-key `did.json`, so the old key stays dereferenceable and old credentials still verify. The key record is kept in DeDi forever.
- **`revoked`** — the key was compromised. Every signature it ever produced is now untrustworthy (an attacker could back-date forgeries). Verifiers reject **all** credentials signed by a revoked key with a top-level `REVOKED` outcome. The key is dropped from the `did.json`'s verification relationships (it stays dereferenceable so the verifier returns a precise `REVOKED` rather than "unresolvable").

**Why no timestamps or validity windows?** The two terminal statuses make them unnecessary. For a `rotated` key, every signature is legitimate (there is no forgery to time-bound). For a `revoked` key, no signature can be trusted regardless of date (an attacker can back-date). A validity window would add nothing in either case — and DeDi's native model makes the right call: revocation is the strictly better tool for key compromise.

### did.json snapshot on each key record, and the two-path model

There is no separate document registry. Instead, **each key record can carry the assembled `did.json` as its immutable `document?` snapshot** — frozen at the moment that key was published or rotated. This is what serves standard W3C `did:web` resolvers (those without DeDi awareness) when the issuer's own domain is unreachable. The snapshot follows the multi-key `did.json` rules:

- **Active and rotated keys** stay in `verificationMethod[]` and in their relationships (e.g. `assertionMethod`), so credentials they signed still resolve. Each new sequential fragment (`#key-0`, `#key-1`, …) is a distinct entry — old and new keys coexist.
- **Revoked keys** stay dereferenceable in `verificationMethod[]` but are dropped from every verification relationship. Nothing they signed is accepted as a valid assertion.

Because the snapshot is **per key row and never edited**, each row preserves the exact `did.json` of its era: `#key-0`'s row keeps the document that was current when `#key-0` was published, even after a later rotation added `#key-2`. That gives **permanent historical resolution** — a credential signed by a long-rotated key resolves against the document that was current at signing time.

**Where the `did.json` lives is the issuer's choice.** It is gated by `OPENCRED_DEDI_HOST_DID_DOC`:

- **Unset (default)** — no snapshot is stored on the key records. The issuer hosts the `did.json` themselves at `https://<domain>/.well-known/did.json` (Path A). DeDi-aware verifiers still resolve keys directly from `opencred-key-registry`; standard verifiers use the issuer's domain.
- **Set to `true`** (did:web only) — the `did.json` snapshot is written onto the key record(s) at publish and rotate time (Path B). A DeDi-aware verifier can then project the current document via `resolveDidWebDocument(did)` when the issuer's domain is down: it lists the registry, keeps the records whose `controllerDid` matches and that carry a `document`, and returns the **active** key's snapshot — or, if no key is active, the **highest-indexed (`#key-N`) key's** snapshot. This is wired into the verifier through `createDeDiDIDWebFallback` (`packages/dedi-client/src/adapter/did-web-fallback.ts`) and is only consulted on genuine "canonical endpoint unreachable" errors, never on SSRF rejections.

did:key never stores a `document` — the DID is self-describing, so there is no `did.json` to host or snapshot. The key-registry records exist independently of any `did.json` — a DeDi-aware verifier can verify any credential by looking up `opencred-key-registry` directly, without ever fetching the document.

### Worked example — Riverside University

The following timeline shows how all three statuses play out in a real multi-key scenario. Namespace: `riverside.edu`, with `OPENCRED_DEDI_HOST_DID_DOC=true` so each did:web key record carries its own `did.json` snapshot.

| Time | Event |
|---|---|
| T1 | DID-A = `did:web:riverside.edu`, two keys: `#key-0` (registrar — diplomas/transcripts) and `#key-1` (campus — ID cards). Issue credential **D1** under `#key-0` and **I1** under `#key-1`. Both keys published as `active`. |
| T2 | Normal rotation: new registrar key `#key-2` added, old `#key-0` flipped to `rotated`. Issue **D2** under `#key-2`. |
| T3 | New DID-B = `did:web:riverside.edu:conted` with `#key-0` published. Issue **C1** under DID-B `#key-0`. |
| T4 | Library kiosk issues under `did:key:z6MkLib…` (DID-C). Issue **L1** under DID-C. |
| T5 | **`#key-1` (campus) is compromised.** Flip its status to `revoked`. The current `did.json` drops `#key-1` from its relationships. |

DeDi key-registry state after T5 (one row per key; `document` is the immutable snapshot of that key's era):

```
namespace: riverside.edu
  opencred-key-registry/
    did-web-riverside-edu-key-0        { controllerDid: DID-A, status: rotated, document: <snapshot @T1> }
    did-web-riverside-edu-key-1        { controllerDid: DID-A, status: revoked, document: <snapshot @T1> }
    did-web-riverside-edu-key-2        { controllerDid: DID-A, status: active,  document: <snapshot @T2> }
    did-web-riverside-edu-conted-key-0 { controllerDid: DID-B, status: active,  document: <snapshot @T3> }
    did-key-z6mklib-z6mklib            { controllerDid: DID-C, status: active                            }  # no document — did:key is self-describing
```

Note: record names use `slug(verificationMethod)`, so `did:web:riverside.edu:conted#key-0` and `did:web:riverside.edu#key-0` produce different names — no collision even though both use the fragment `#key-0`. Each `document` snapshot is frozen at publish/rotate time and never edited; only `status` changes. `resolveDidWebDocument(DID-A)` returns `#key-2`'s snapshot (the active key) — the most current view.

Verification outcomes at T5:

| Credential | Key looked up | Status | Outcome |
|---|---|---|---|
| **D1** (signed by `#key-0`, issued T1) | `key-0` | `rotated` | **VALID** — clean rotation; the old key stays dereferenceable in the multi-key `did.json`, so standard and DeDi-aware verifiers both accept it |
| **I1** (signed by `#key-1`, issued T1) | `key-1` | `revoked` | **REVOKED** — compromised key; nothing it signed can be trusted |
| **D2** (signed by `#key-2`, issued T2) | `key-2` | `active` | **VALID** |
| **C1** (signed by DID-B `#key-0`, issued T3) | `did-web-riverside-edu-conted-key-0` | `active` | **VALID** (no collision with DID-A's `#key-0`) |
| **L1** (signed by `did:key:z6MkLib…`, issued T4) | `did-key-z6mklib-z6mklib` | `active` | **VALID** |

### The "no key-status available" case is valid, not a failure

Not every credential comes with a pointer to a DeDi key-status record, and DeDi itself may be temporarily unreachable. OpenCred handles both cases gracefully:

- **A `did:key` credential without `credentialStatus`**: the key-status check is reported as "not checked" in the verify response. The credential's signature is still verified cryptographically, and **the credential is displayed as valid**. The key-status check is additive — it can only _downgrade_ an outcome (when it explicitly finds `revoked`); it never blocks a valid credential when it finds nothing.
- **DeDi outage or a 404 (key record not found)**: same behavior. The credential stands on its cryptographic signature. DeDi status is purely advisory and degrades open on outages.

The `did:key` case: a `did:key` credential is self-describing for the signature (the public key is encoded in the DID string). If the credential has a `credentialStatus.id` URL, the verifier extracts the DeDi namespace from that URL and looks up the key record. If there is no `credentialStatus` at all, no namespace can be derived — the check is skipped, and the credential remains valid.

### Why this is simpler than the old one-record-per-DID model

| Old model | New model |
|---|---|
| One DID record embeds the entire `did.json` + a single `keyStatus` flag | One record per key — each key has its own status, independently revocable |
| Rotating a key required updating the whole DID record (all-or-nothing) | Rotating = publish a new key record + flip the old key's status — atomic and targeted; **old credentials stay valid** because the retired key keeps its own row and `did.json` snapshot |
| Old keys removed from the DID record after rotation (historical credentials stop resolving) | Old key records — and their immutable `document` snapshots — are retained forever, so **historical resolution** works indefinitely against the document that was current at signing time |
| Per-key compromise required a custom workaround | `revoked` status on the single compromised key rejects every credential it signed — **per-key revoke**, no blast radius onto other keys |
| The assembled `did.json` and the key status lived in two different shapes (DID record + a planned `did-documents` registry) | The `did.json` snapshot rides on each key record (`document?`); **one registry, one write path, standards-clean** — DeDi-aware verifiers resolve keys directly, and the per-key snapshots project a valid W3C `did.json` for standard verifiers when the issuer's domain is down |

---

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
