# DeDi key registry redesign — align with DeDi's native signing-keys model

> **Status: Implemented** — the single per-key `opencred-key-registry` model (with the immutable did.json snapshot carried **on each key record**) and the four key-management endpoints (`/v1/keys/publish`, `/v1/keys/rotate`, `/v1/keys/revoke`, `/v1/keys/resolve`) are live as of 2026-06-01. Operator docs: [docs/concepts/dids.md](../concepts/dids.md#per-key-registry--the-opencred-key-registry-model), [docs/docker/api-reference.md](../docker/api-reference.md#post-v1keysresolve-per-key-registry), [docs/docker/deployment.md](../docker/deployment.md#key-lifecycle-publish-rotate-revoke).

Status: **Implemented**
Last updated: 2026-06-10 (implemented 2026-06-01)
Supersedes D2 (and informs D1) in [dedi-integration-open-questions.md](./dedi-integration-open-questions.md)

> **Correction note.** Two earlier drafts of this doc reasoned from wrong models. The *first* draft assumed a "shared `public_key_registry` across many issuers," verifier-side namespace config, an enumeration race, and thumbprint fragments to dodge it — all wrong. The *second* draft corrected the DeDi facts but landed on a **two-registry** design: an `opencred-key-registry` for the keys plus a separate `did-documents` registry to serve the assembled did.json (with `did-documents` "deferred"). That extra registry was dropped. The implemented design folds the did.json **snapshot onto each key record** as an optional `document?` field. There is **no `did-documents` registry**. This rewrite reflects the implemented design.

---

## 1. How DeDi actually works (the corrected model)

Sources: [dedi-101](https://dedi-global.gitbook.io/docs/dedi.global-developers/dedi-101), [access APIs](https://dedi-global.gitbook.io/docs/dedi.global-developers/standard-apis/access), [domain verification](https://dedi-global.gitbook.io/docs/dedi.global-developers/quickstart/domain-verification-the-bedrock-of-trust-in-dedi), [VC signing keys use case](https://dedi-global.gitbook.io/docs/resources/representative-use-cases/vc-signing-keys-on-dedi), [VC workflows](https://dedi-global.gitbook.io/docs/resources/dedi-in-verifiable-credential-workflows).

- **Hierarchy: Account → Namespace → Registry → Record.**
- **A namespace is a verified domain**, owned by one account (`self_dns` TXT / `self_http` at `/.well-known/dedi-verification.txt` / `request_other_namespace`). After verification you **use your domain as the namespace ID**, and namespaces **resolve under your own domain, not dedi.global**. Re-verified on an interval (default 1 year).
- **A registry** is a schema-typed grouping of records within *your* namespace.
- **A record** has a **unique name within its registry**.
- **Reads are public, no auth** — `lookup` (dereference one record) and `query` (list a registry, paginated/sortable). **Writes require namespace/registry ownership or delegation.**
- **DeDi's canonical signing-keys model is one record per key:** `lookup/{domain}/{signing-keys}/{key-id}` → `{ algorithm, publicKey, purpose, validFrom/validUntil, version history, on-chain proof }`. **Old key records are retained** so "verifiers processing historical data can still resolve the key that was active at any point in time," and resolution works **offline** (issuer infra need not be up).
- **Trust model:** verifiers maintain a list of **trusted namespaces (= issuer domains)**. Resolution coordinates come from the credential/DID; the trust list is a separate, legitimate policy layer — *not* the per-verifier resolution config the earliest draft wrongly assumed.

**Implication for OpenCred:** our original `public_key_registry` (one record per DID holding a full embedded did.json + a single `keyStatus`) was the **divergence** from DeDi-native. Realigning to per-key records gets us per-key purpose/status, permanent historical resolution, and on-chain proof "for free." Revocation already uses DeDi's canonical `tag: "revoke"` shape and `credentialStatus` (no change needed there).

---

## 2. The implemented model — one registry per issuer namespace (= domain)

Registries inside the issuer's own verified namespace `D-domain` (e.g. `riverside.edu`):

| Registry | Record name | Record payload | Role |
|---|---|---|---|
| **`opencred-key-registry`** | `slug(verificationMethod)` = `slug(DID#fragment)` | `{ keyId, controllerDid, algorithm, publicKeyJwk, purpose[], status, document? }` | **Source of truth for "is *this* key valid."** One record per key; **all of the issuer's keys (every DID) in this one registry** (decision, F2). Self-contained → single-lookup verification. Old keys retained forever. No validity-window fields (F1). The optional `document?` carries the **immutable did.json snapshot** of that key's era (F4). |
| **`vc-revocation-registry`** | `hash(credential)` | DeDi `tag: "revoke"` → `{ revoked_id, reason? }` | **Per-credential revocation.** Already implemented + aligned. |

There is **no `did-documents` registry**. The earlier two-registry design (a separate registry holding one assembled did.json per DID) was dropped in favour of putting the snapshot directly on each key record — see F4.

Key points:
- **One registry, constant name `opencred-key-registry`.** Because the name is fixed, a verifier always knows the registry; it needs only the **namespace** (from the DID host, or from `credentialStatus.id`) and the **record name**, which it derives deterministically from the credential's `proof.verificationMethod`. All of an issuer's DIDs share this one registry.
- **Record name = `slug(verificationMethod)`** — derived from the *full* `DID#fragment`, not the bare fragment, so keys from different DIDs under the same domain (e.g. `did:web:riverside.edu#key-1` vs `…:conted#key-1`) never collide. Collisions are impossible-by-construction and, if a bug ever produced one, DeDi rejects the duplicate name at write time (loud, not silent — F2).
- **`controllerDid` on each key record** links a key to the DID it belongs to — lets a verifier confirm the key is claimed by the credential's DID, and lets the did.json projection (`resolveDidWebDocument`) be assembled by querying the registry and filtering on it (F4).
- **`status` ∈ {active, rotated, revoked}** is the **only mutable field** — and that's all the lifecycle metadata needed (no timestamps, no validity windows; see F1). Status changes are **new versions of the same key record** (DeDi records are versioned); a *new key* is a *new record*. Writes are owner-serialized within one namespace, so the multi-writer race that motivated thumbprints in the earliest draft is largely moot — **keep human key-ids (`#key-0`, `#key-1`, …), don't switch to thumbprints**. Every other field — including `document` — is **immutable** for the life of the record; `setKeyStatus` carries it forward unchanged. (An immutable field is safe under DeDi's lock-free `update-record` because every writer writes the same value.)
- **`document?` — the immutable did.json snapshot, on the key record.** When set (did:web issuers who opt into `OPENCRED_DEDI_HOST_DID_DOC=true`), each key record embeds the assembled W3C did.json **as of when that key was published or rotated**. Public material only — assembled through `toPublicJwk`, never a private `d`. did:key omits it (self-describing), and so does a did:web issuer who hosts `.well-known/did.json` on their own domain.
- **Verifier decision logic:** `active` → accept; `rotated` → **accept** (a cleanly-retired key was only ever the issuer's, so every signature under it is legitimate — no forgeries to exclude); `revoked` → **reject all** signatures from the key (compromise: nothing it signed can be trusted). The did.json snapshot mirrors this: rotated keys stay in the document (dereferenceable), revoked keys are dropped from every verification relationship.

### Two resolution paths

1. **Standard W3C verifier (DeDi-unaware).** Resolves `did:web:riverside.edu` → fetches the did.json from the **issuer's own domain** (`/.well-known/did.json`). Sees only what the current document expresses. This is the canonical path and needs no DeDi at all.
2. **DeDi-aware verifier.** From `proof.verificationMethod = did:web:riverside.edu#key-1`, derive `slug(verificationMethod)` → `lookup(riverside.edu, opencred-key-registry, …)` → get key + `status`. Verify the signature, then enforce key status. Public read, no config beyond a trusted-domain list. Can verify **historical** keys even after they've been pruned from the current did.json, because each key record keeps its own snapshot forever.

**did:web fallback resolution.** When the issuer's domain is unreachable, a DeDi-aware verifier projects the did.json from the per-key snapshots via `resolveDidWebDocument(did)` (`packages/dedi-client/src/adapter/client.ts`): it lists `opencred-key-registry`, keeps records whose `controllerDid` matches the DID and that carry a `document`, and returns the **active** key's snapshot — or, when no key is active, the **highest-indexed** (`#key-N`) key's snapshot (the most recent / most complete era). This is wired into `DIDWebResolver` via `createDeDiDIDWebFallback`, and is only consulted on genuine "canonical endpoint unreachable" errors — never on SSRF rejections.

---

## 3. Worked use cases — "Riverside University" (`riverside.edu`)

Timeline that deliberately mixes *same-DID multi-key*, *rotation*, *multiple DIDs/documents*, *did:key*, and *compromise*. Assume `OPENCRED_DEDI_HOST_DID_DOC=true`, so each did:web key record carries its own did.json snapshot.

| t | Event |
|---|---|
| T1 | DID-A = `did:web:riverside.edu`, doc lists `#key-0` (registrar — diplomas/transcripts) + `#key-1` (campus — ID cards). Issue **D1** (diploma, `#key-0`), **I1** (ID card, `#key-1`). |
| T2 | Rotate registrar key → new `#key-2` (same DID-A). Old `#key-0` flips to `rotated`. Issue **D2** (diploma, `#key-2`). |
| T3 | New DID-B = `did:web:riverside.edu:conted`, doc lists `#key-0`. Issue **C1** (certificate, DID-B `#key-0`). |
| T4 | Library kiosk uses DID-C = `did:key:z6MkLib…`. Issue **L1** (library card, DID-C). |
| T5 | `#key-1` (campus) is **compromised** → revoke. |

DeDi state under namespace `riverside.edu` after T5 (one row per key; `document` is the immutable snapshot of that key's era):

```
opencred-key-registry/        # record name = slug(verificationMethod) = slug(DID#fragment)
  did-web-riverside-edu-key-0        { controllerDid: DID-A, status: rotated, document: <snapshot @T1: {#key-0}> }
  did-web-riverside-edu-key-1        { controllerDid: DID-A, status: revoked, document: <snapshot @T1: {#key-0,#key-1}> }
  did-web-riverside-edu-key-2        { controllerDid: DID-A, status: active,  document: <snapshot @T2: {#key-0(rotated),#key-1,#key-2}> }
  did-web-riverside-edu-conted-key-0 { controllerDid: DID-B, status: active,  document: <snapshot @T3: {#key-0}> }   # no collision with DID-A's #key-0
  did-key-z6mklib-z6mklib            { controllerDid: DID-C(did:key), status: active }                                # no document — did:key is self-describing
vc-revocation-registry/        # only if individual credentials are revoked
```

Each row's `document` is **frozen at the moment that key was published/rotated** and never edited afterward — only `status` mutates. So `#key-0`'s snapshot always shows the T1 document even after the T2 rotation added `#key-2`; `#key-2`'s snapshot is the current era. `resolveDidWebDocument(DID-A)` returns `#key-2`'s snapshot (the active key) — the most complete and current view.

### Verifying each credential at T5

| Cred | Standard W3C path (issuer's domain reachable) | DeDi-aware / fallback path | Verdict |
|---|---|---|---|
| **D1** (`#key-0`, issued T1) | `#key-0` is `rotated` → **kept** in current did.json (dereferenceable, still in `assertionMethod`) → verify ✓ | lookup `#key-0` → `rotated` → **accept** (cleanly retired, no forgeries) ✓ | **Both ✓** — rotated keys stay valid |
| **I1** (`#key-1`, issued T1) | `#key-1` is `revoked` → kept dereferenceable but dropped from `assertionMethod` → signature won't validate as an assertion → **reject** ✓ | lookup `#key-1` → `revoked` (compromised) → **reject all** → `REVOKED` ✓ | **Both ✓** — compromise = drop from relationships + revoke |
| **D2** (`#key-2`, issued T2) | in `assertionMethod` → ✓ | `active` → ✓ | ✓ |
| **C1** (DID-B `#key-0`, issued T3) | resolve `did:web:riverside.edu:conted` → its own current did.json → `#key-0` → ✓; if DID-B's domain is unreachable, fallback projects DID-B's snapshot from `did-web-riverside-edu-conted-key-0` | lookup `slug(DID-B#key-0)` = `did-web-riverside-edu-conted-key-0` → active → ✓ (no collision with DID-A's `#key-0`) | ✓ |
| **L1** (DID-C did:key, issued T4) | derive key from `did:key` string → verify signature ✓ (no DeDi, no did.json) | status check needs the namespace — recovered from the credential's `credentialStatus.id` URL (F3) → lookup in `opencred-key-registry` → active → ✓. With no `credentialStatus`, the key-status check is simply "not checked" and the credential stays **VALID** | ✓ |

This single timeline surfaces the flaws below.

---

## 4. Major flaws (with severity)

### F1 — ~~Temporal-validity divergence~~ → **DISSOLVED** (was a rotation/compromise conflation)
*Earlier framing (wrong): "the did.json can't express a validity window, so rotation needs `validFrom/validUntil`."* That was built on conflating two different events. Once `rotated` (cleanly retired, never stolen) and `revoked` (compromised) are **separate states**, no validity window is needed and the plain did.json is sufficient:

- **`rotated`** → the key was only ever the issuer's, so *every* signature under it is legitimate (there are no forgeries to exclude). **Keep it dereferenceable in the did.json; accept.** A timestamp would add nothing — in the clean case there is no adversary to time-bound.
- **`revoked`** → the key is compromised, so *nothing* it signed can be trusted (an attacker can back-date a forgery into any window). **Drop it from the verification relationships + publish to the revocation registry; reject all.** A timestamp would add nothing — a back-dater defeats it.

So the window is never both useful *and* trustworthy, and DeDi lacking native `validFrom/validUntil` is a **non-issue**: you have revocation, which is the strictly better tool (short validity windows are only a substitute for revocation when you *can't* revoke). **No timestamps in the schema.** This also removes the standard-vs-DeDi divergence entirely — both paths agree (see D1/I1 in the table).

*(Residual, out of scope: to salvage the genuine pre-compromise credentials of a revoked key you'd need an unforgeable per-credential issuance proof — an on-chain anchor at issuance, not the self-asserted `issuanceDate`. DeDi anchors records on-chain, so this is a possible future capability; not relied on today.)*

### F2 — `key-id` uniqueness across multiple DIDs → **DECIDED**
**Decision:** one registry for all OpenCred keys, named **`opencred-key-registry`**, inside the issuer's namespace. Record name = **`slug(verificationMethod)` = `slug(DID#fragment)`**, so keys from different DIDs under the same domain can't collide (the DID is baked into the name). A verifier derives the record name straight from the credential's `proof.verificationMethod`. DeDi's unique-name enforcement is a backstop, not a thing we rely on. (Chose a single fixed-name registry over per-DID registries so the verifier always knows the registry and the lookup needs only namespace + derived record name.)

### F3 — did:key namespace discovery → **RESOLVED** via `credentialStatus.id`
A `did:key` credential is self-describing for the *signature* (verify offline, no DeDi) but the DID carries no pointer to the namespace holding its status. **It doesn't need to:** the credential's `credentialStatus.id` is already `…/lookup/{namespace}/vc-revocation-registry/{hash}`, so the verifier **extracts the namespace from the revocation URL** and looks up the key in that same namespace's `opencred-key-registry`. We still publish the did:key's public key to that registry. No DID-level change, no new field. When there is no `credentialStatus` at all, no namespace can be derived — the key-status check is skipped and the credential stays VALID on its signature (graceful pass; see [revocation.md](../concepts/revocation.md#the-no-dedi-status-available-case--credential-stays-valid)). (did:web carries the domain in the DID, so it never had the problem.)

### F4 — Standard resolution still needs an assembled, per-DID did.json → **RESOLVED by the snapshot-on-key-record** (no separate registry)
Per-key records still need to answer "what does `did:web:riverside.edu:conted` resolve to?" for a *standard, DeDi-unaware* verifier when the issuer's own domain is down. The earlier draft parked this behind a deferred `did-documents` registry. **The implemented design removes that registry entirely** and instead carries the assembled did.json **as an immutable `document?` snapshot on each key record**, written at publish/rotate time, gated by `OPENCRED_DEDI_HOST_DID_DOC`:

- **In the common deployments** the issuer's own webserver hosts `.well-known/did.json` (website / website+DeDi), and DeDi-aware verification doesn't need the snapshot at all (it looks keys up directly in `opencred-key-registry`). Those issuers leave `OPENCRED_DEDI_HOST_DID_DOC` unset and the `document` field is absent.
- **For a DeDi-only deployment with a standard verifier**, the per-key snapshots back `resolveDidWebDocument(did)`, wired as the did:web fallback (`createDeDiDIDWebFallback`). It projects the document from the **active** key's snapshot — or the **highest-indexed** key's if none is active. So a single registry serves both keys and the projected document; no second registry, no separate write path to keep in sync.

**Why one snapshot per key row (not one shared document)?** Each row's snapshot is frozen as of that key's era and never edited, which gives **permanent historical resolution for free**: a credential signed by a long-rotated key resolves against the exact did.json that was current when it was signed, and the immutability also keeps the field safe under DeDi's lock-free `update-record` (every writer carries the same value forward — see the concurrency note on `KeyRecord`). **Consequence:** the redesign is still **additive** at the schema level (keys, plus an optional embedded document) but needs only **one registry**.

### F5 — Namespace re-verification lapse *(operational)*
Namespaces re-verify on an interval (default 1 year). If the issuer lets domain verification lapse, verifiers requiring a verified namespace may reject otherwise-valid credentials — even though the keys are fine. Analogous to a did:web domain expiring. **Mitigation:** monitor/renew; allow verifier policy to distinguish "namespace lapsed" from "key invalid."

---

## 5. What the redesign actually buys (vs the original one-record-per-DID)

- **Permanent key history** → a credential signed by a long-rotated key still verifies, because the key record (its `document` snapshot and its on-chain proof) is retained forever even after the key is pruned from the *current* did.json. Directly serves the "issue across many keys/documents over time" use case (D1 above).
- **Per-key `status` (active/rotated/revoked)** → clean rotation keeps old credentials valid; compromise rejects all — no timestamps, no validity windows (F1).
- **One registry, not two** → the did.json snapshot lives on each key record (`document?`) instead of in a separate `did-documents` registry. One write path, one source of truth, and the snapshot is automatically frozen per era.
- **Alignment with DeDi's canonical model** → on-chain proof, offline resolution, public reads, and we stop maintaining a bespoke schema DeDi doesn't expect.
- **Clean separation of concerns:** key lifecycle + its document snapshot (`opencred-key-registry`) vs. per-credential revocation (`vc-revocation-registry`, unchanged).

## 6. Open questions for the DeDi team

- **Q1 (resolved).** For multi-DID issuers under one domain-namespace, a **single `opencred-key-registry`** with `slug(verificationMethod)` record names is the chosen pattern (F2). Confirmation that this is idiomatic on DeDi's side would be welcome.
- **Q2 (resolved in OpenCred).** A DID's assembled did.json is served from the per-key `document` snapshots via `resolveDidWebDocument` (the did:web fallback), gated by `OPENCRED_DEDI_HOST_DID_DOC`. Native DeDi serving of `application/did+json` under the issuer's verified domain would still be a nice-to-have for fully DeDi-unaware resolvers that don't wire the fallback.
- **Q3.** Recommended pattern for **did:key status discovery** (F3) — is there a convention to bind a did:key to a publishing namespace beyond reusing `credentialStatus.id`?
- **Q4.** Confirm: new key = new record; status change = new **version** of the key record; old versions/records (and their `document` snapshots) remain publicly resolvable forever.
- **Q5.** Migration from the original one-record-per-DID `public_key_registry` to `opencred-key-registry`. Backfill + dual-read window.
