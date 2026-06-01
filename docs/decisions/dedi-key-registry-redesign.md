# DeDi key registry redesign — align with DeDi's native signing-keys model

> **Status: Implemented** — the per-key `opencred-key-registry` model and the four key-management endpoints (`/v1/keys/publish`, `/v1/keys/rotate`, `/v1/keys/revoke`, `/v1/keys/resolve`) are live as of 2026-06-01. Operator docs: [docs/concepts/dids.md](../concepts/dids.md#per-key-registry-the-opencred-key-registry-model), [docs/docker/api-reference.md](../docker/api-reference.md#post-v1keysresolve-per-key-registry), [docs/docker/deployment.md](../docker/deployment.md#key-lifecycle-publish-rotate-revoke).

Status: **Implemented**
Last updated: 2026-05-28 (implemented 2026-06-01)
Supersedes D2 (and informs D1) in [dedi-integration-open-questions.md](./dedi-integration-open-questions.md)

> **Correction note.** An earlier draft of this doc reasoned from a wrong mental model of DeDi (a "shared `public_key_registry` across many issuers," verifier-side namespace config, an enumeration race, thumbprint fragments to dodge it). That was wrong. This rewrite is grounded in the actual DeDi docs (read 2026-05-28). The corrected facts change the conclusion substantially.

---

## 1. How DeDi actually works (the corrected model)

Sources: [dedi-101](https://dedi-global.gitbook.io/docs/dedi.global-developers/dedi-101), [access APIs](https://dedi-global.gitbook.io/docs/dedi.global-developers/standard-apis/access), [domain verification](https://dedi-global.gitbook.io/docs/dedi.global-developers/quickstart/domain-verification-the-bedrock-of-trust-in-dedi), [VC signing keys use case](https://dedi-global.gitbook.io/docs/resources/representative-use-cases/vc-signing-keys-on-dedi), [VC workflows](https://dedi-global.gitbook.io/docs/resources/dedi-in-verifiable-credential-workflows).

- **Hierarchy: Account → Namespace → Registry → Record.**
- **A namespace is a verified domain**, owned by one account (`self_dns` TXT / `self_http` at `/.well-known/dedi-verification.txt` / `request_other_namespace`). After verification you **use your domain as the namespace ID**, and namespaces **resolve under your own domain, not dedi.global**. Re-verified on an interval (default 1 year).
- **A registry** is a schema-typed grouping of records within *your* namespace.
- **A record** has a **unique name within its registry**.
- **Reads are public, no auth** — `lookup` (dereference one record) and `query` (list a registry, paginated/sortable). **Writes require namespace/registry ownership or delegation.**
- **DeDi's canonical signing-keys model is one record per key:** `lookup/{domain}/{signing-keys}/{key-id}` → `{ algorithm, publicKey, purpose, validFrom/validUntil, version history, on-chain proof }`. **Old key records are retained** so "verifiers processing historical data can still resolve the key that was active at any point in time," and resolution works **offline** (issuer infra need not be up).
- **Trust model:** verifiers maintain a list of **trusted namespaces (= issuer domains)**. Resolution coordinates come from the credential/DID; the trust list is a separate, legitimate policy layer — *not* the per-verifier resolution config the earlier draft wrongly assumed.

**Implication for OpenCred:** our current `public_key_registry` (one record per DID holding a full embedded did.json + a single `keyStatus`) is the **divergence** from DeDi-native. Realigning to per-key records gets us per-key purpose/status, permanent historical resolution, and on-chain proof "for free." Revocation already uses DeDi's canonical `tag: "revoke"` shape and `credentialStatus` (no change needed there).

---

## 2. Proposed model — per issuer namespace (= domain)

Registries inside the issuer's own verified namespace `D-domain` (e.g. `riverside.edu`):

| Registry | Record name | Record payload | Role |
|---|---|---|---|
| **`opencred-key-registry`** | `slug(verificationMethod)` = `slug(DID#fragment)` | `{ keyId, controllerDid, algorithm, publicKeyJwk, purpose[], status }` | **Source of truth for "is *this* key valid."** One record per key, **all of the issuer's keys (every DID) in this one registry** (decision, F2). Self-contained → single-lookup verification. Old keys retained forever. No validity-window fields (F1). |
| **`vc-revocation-registry`** | `hash(credential)` | DeDi `tag: "revoke"` → `{ revoked_id, reason? }` | **Per-credential revocation.** Already implemented + aligned. |
| **`did-documents`** *(deferred — F4)* | `slug(DID)` | the assembled W3C did.json for that DID | Only needed to serve standard did:web resolution from DeDi. **Parked** — not on the critical path. |

Key points:
- **One registry, constant name `opencred-key-registry`.** Because the name is fixed, a verifier always knows the registry; it needs only the **namespace** (from the DID host, or from `credentialStatus.id`) and the **record name**, which it derives deterministically from the credential's `proof.verificationMethod`. All of an issuer's DIDs share this one registry.
- **Record name = `slug(verificationMethod)`** — derived from the *full* `DID#fragment`, not the bare fragment, so keys from different DIDs under the same domain (e.g. `did:web:riverside.edu#key-1` vs `…:conted#key-1`) never collide. Collisions are impossible-by-construction and, if a bug ever produced one, DeDi rejects the duplicate name at write time (loud, not silent — F2).
- **`controllerDid` on each key record** links a key to the DID it belongs to — lets a verifier confirm the key is claimed by the credential's DID, and (when F4 is picked up) lets the did.json projection be assembled by querying the registry and filtering on it.
- **`status` ∈ {active, rotated, revoked}** — and that's all the lifecycle metadata needed (no timestamps, no validity windows; see F1). Status changes are **new versions of the same key record** (DeDi records are versioned); a *new key* is a *new record*. Writes are owner-serialized within one namespace, so the multi-writer race that motivated thumbprints in the earlier draft is largely moot — **keep human key-ids (`#key-0`), don't switch to thumbprints** (that change would also break already-issued credentials referencing `#key-0`).
- **Verifier decision logic:** `active` → accept; `rotated` → **accept** (a cleanly-retired key was only ever the issuer's, so every signature under it is legitimate — no forgeries to exclude); `revoked` → **reject all** signatures from the key (compromise: nothing it signed can be trusted). The did.json mirrors this: rotated keys stay in the document, revoked keys are removed.
- **`signing-keys` is the addition; `did-documents` is essentially today's per-DID record kept for standard interop.** The redesign is *"add per-key records alongside the did.json,"* not *"replace the did.json with key rows."* (See Flaw F4 for why the projection has to stay.)

### Two resolution paths

1. **Standard W3C verifier (DeDi-unaware).** Resolves `did:web:riverside.edu` → fetches the did.json (from the issuer's domain, or from the `did-documents` record served under the domain). Sees only what the document expresses. Works, with the temporal caveat (F1).
2. **DeDi-aware verifier.** From `proof.verificationMethod = did:web:riverside.edu#registrar-2024`, derive `lookup(riverside.edu, signing-keys, registrar-2024)` → get key + `validFrom/validUntil` + `status`. Verify signature, then enforce "key valid at the credential's issuance time." Public read, no config beyond a trusted-domain list. Can verify **historical** keys even after they've been pruned from the current did.json.

---

## 3. Worked use cases — "Riverside University" (`riverside.edu`)

Timeline that deliberately mixes *same-DID multi-key*, *rotation*, *multiple DIDs/documents*, *did:key*, and *compromise*.

| t | Event |
|---|---|
| T1 | DID-A = `did:web:riverside.edu`, doc lists `#registrar-2024` (diplomas/transcripts) + `#campus-2024` (ID cards). Issue **D1** (diploma, `#registrar-2024`), **I1** (ID card, `#campus-2024`). |
| T2 | Rotate registrar key → `#registrar-2025` (same DID-A). Issue **D2** (diploma, `#registrar-2025`). |
| T3 | New DID-B = `did:web:riverside.edu:conted`, doc lists `#key-1`. Issue **C1** (certificate, DID-B `#key-1`). |
| T4 | Library kiosk uses DID-C = `did:key:z6MkLib…`. Issue **L1** (library card, DID-C). |
| T5 | `#campus-2024` is **compromised** → revoke. |

DeDi state under namespace `riverside.edu` after T5:

```
opencred-key-registry/        # record name = slug(verificationMethod) = slug(DID#fragment)
  did-web-riverside-edu--registrar-2024   { controllerDid: DID-A, purpose:[assertion], status: rotated }
  did-web-riverside-edu--campus-2024      { controllerDid: DID-A, purpose:[assertion], status: revoked, reason: compromised }
  did-web-riverside-edu--registrar-2025   { controllerDid: DID-A, purpose:[assertion], status: active }
  did-web-riverside-edu-conted--key-1     { controllerDid: DID-B, purpose:[assertion], status: active }   # no collision with DID-A's #key-1
  did-key-z6mklib--z6mklib                { controllerDid: DID-C(did:key), purpose:[assertion], status: active }
vc-revocation-registry/        # only if individual credentials are revoked
did-documents/                 # deferred (F4) — only if serving standard did:web resolution from DeDi
```

### Verifying each credential at T5

| Cred | Standard W3C path | DeDi-aware path | Verdict |
|---|---|---|---|
| **D1** (registrar-2024, issued T1) | registrar-2024 is `rotated` → **kept** in did.json (incl. assertionMethod) → verify ✓ | lookup registrar-2024 → `rotated` → **accept** (cleanly retired, no forgeries) ✓ | **Both ✓** — rotated keys stay valid |
| **I1** (campus-2024, issued T1) | campus-2024 is `revoked` → **removed** from did.json → resolve fails → **reject** ✓ | lookup campus-2024 → `revoked` (compromised) → **reject all** ✓ | **Both ✓** — compromise = remove + revoke |
| **D2** (registrar-2025, issued T2) | in assertionMethod → ✓ | `active` → ✓ | ✓ |
| **C1** (DID-B #key-1, issued T3) | resolve `did:web:riverside.edu:conted` → its own did.json → #key-1 → ✓ (needs DID-B's document served — F4, deferred) | lookup `slug(DID-B#key-1)` = `did-web-riverside-edu-conted--key-1` → active → ✓ (no collision with DID-A's #key-1) | ✓ |
| **L1** (DID-C did:key, issued T4) | derive key from `did:key` string → verify signature ✓ (no DeDi needed) | status check needs the namespace — recovered from the credential's `credentialStatus.id` URL (F3 resolved) → lookup in `opencred-key-registry` → active → ✓ | ✓ |

This single timeline surfaces the flaws below.

---

## 4. Major flaws (with severity)

### F1 — ~~Temporal-validity divergence~~ → **DISSOLVED** (was a rotation/compromise conflation)
*Earlier framing (wrong): "the did.json can't express a validity window, so rotation needs `validFrom/validUntil`."* That was built on conflating two different events. Once `rotated` (cleanly retired, never stolen) and `revoked` (compromised) are **separate states**, no validity window is needed and the plain did.json is sufficient:

- **`rotated`** → the key was only ever the issuer's, so *every* signature under it is legitimate (there are no forgeries to exclude). **Keep it in the did.json; accept.** A timestamp would add nothing — in the clean case there is no adversary to time-bound.
- **`revoked`** → the key is compromised, so *nothing* it signed can be trusted (an attacker can back-date a forgery into any window). **Remove it from the did.json + publish to the revocation registry; reject all.** A timestamp would add nothing — a back-dater defeats it.

So the window is never both useful *and* trustworthy, and DeDi lacking native `validFrom/validUntil` is a **non-issue**: you have revocation, which is the strictly better tool (short validity windows are only a substitute for revocation when you *can't* revoke). **No timestamps in the schema.** This also removes the standard-vs-DeDi divergence entirely — both paths agree (see D1/I1 in the table).

*(Residual, out of scope: to salvage the genuine pre-compromise credentials of a revoked key you'd need an unforgeable per-credential issuance proof — an on-chain anchor at issuance, not the self-asserted `issuanceDate`. DeDi anchors records on-chain, so this is a possible future capability; not relied on today.)*

### F2 — `key-id` uniqueness across multiple DIDs → **DECIDED**
**Decision:** one registry for all OpenCred keys, named **`opencred-key-registry`**, inside the issuer's namespace. Record name = **`slug(verificationMethod)` = `slug(DID#fragment)`**, so keys from different DIDs under the same domain can't collide (the DID is baked into the name). A verifier derives the record name straight from the credential's `proof.verificationMethod`. DeDi's unique-name enforcement is a backstop, not a thing we rely on. (Chose a single fixed-name registry over per-DID registries so the verifier always knows the registry and the lookup needs only namespace + derived record name.)

### F3 — did:key namespace discovery → **RESOLVED** via `credentialStatus.id`
A `did:key` credential is self-describing for the *signature* (verify offline, no DeDi) but the DID carries no pointer to the namespace holding its status. **It doesn't need to:** the credential's `credentialStatus.id` is already `…/lookup/{namespace}/vc-revocation-registry/{hash}`, so the verifier **extracts the namespace from the revocation URL** and looks up the key in that same namespace's `signing-keys` registry. We still publish the did:key's public key to that registry. No DID-level change, no new field. (did:web carries the domain in the DID, so it never had the problem.)

### F4 — Standard resolution still needs an assembled, per-DID did.json → **DEFERRED**
Per-key records alone don't answer "what does `did:web:riverside.edu:conted` resolve to?" for a *standard, DeDi-unaware* verifier — something must serve the grouped did.json. **Parked for now** (not on the critical path): in the common deployments the issuer's own webserver hosts the did.json (website / website+DeDi), and DeDi-aware verification doesn't need it (it looks keys up directly in `opencred-key-registry`). It only bites in a *DeDi-only deployment with a standard verifier*, which we'll address later — via a `did-documents` projection record (rebuildable by querying `opencred-key-registry` and filtering on `controllerDid`) or a DeDi-served did.json (Q2).
**Consequence either way:** the redesign is **additive** (keys + optional document), not a replacement. The durable win stands: the permanent key records outlive any did.json snapshot, so old rotated keys remain resolvable for historical verification.

### F5 — Namespace re-verification lapse *(operational)*
Namespaces re-verify on an interval (default 1 year). If the issuer lets domain verification lapse, verifiers requiring a verified namespace may reject otherwise-valid credentials — even though the keys are fine. Analogous to a did:web domain expiring. **Mitigation:** monitor/renew; allow verifier policy to distinguish "namespace lapsed" from "key invalid."

---

## 5. What the redesign actually buys (vs today's one-record-per-DID)

- **Permanent key history** → a credential signed by a long-rotated key still verifies, because the key record (and its on-chain proof) is retained forever even after the key is pruned from the current did.json snapshot. Directly serves the "issue across many keys/documents over time" use case (D1 above).
- **Per-key `status` (active/rotated/revoked)** → clean rotation keeps old credentials valid; compromise rejects all — no timestamps, no validity windows (F1).
- **Alignment with DeDi's canonical model** → on-chain proof, offline resolution, public reads, and we stop maintaining a bespoke schema DeDi doesn't expect.
- **Clean separation of concerns:** key lifecycle (signing-keys) vs. document resolution (did-documents) vs. per-credential revocation (vc-revocation-registry, unchanged).

## 6. Open questions for the DeDi team

- **Q1.** For multi-DID issuers under one domain-namespace, is **one registry per DID** idiomatic, or should we use a single `signing-keys` registry with namespace-unique key-ids? (Drives F2.)
- **Q2.** Can DeDi serve a DID's assembled did.json as `application/did+json` under the issuer's own verified domain (so standard did:web resolution works in a DeDi-only deployment)? (Drives F4.)
- **Q3.** Recommended pattern for **did:key status discovery** (F3) — is there a convention to bind a did:key to a publishing namespace?
- **Q4.** Confirm: new key = new record; status/validity change = new **version** of the key record; old versions/records remain publicly resolvable forever.
- **Q5.** Migration from our current one-record-per-DID `public_key_registry` to `signing-keys` + `did-documents`. Backfill + dual-read window.
