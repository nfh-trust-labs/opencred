# Spike 619 — did:web Key Rotation

**Status:** Recommendation
**Parent issue:** [#619 — did:web key rotation design](https://github.com/nfh-trust-labs/opencred/issues/619)
**Followups doc:** [`docs/bootcamp/post-bootcamp-followups.md`](../bootcamp/post-bootcamp-followups.md) §7
**Spike protocol:** `CLAUDE.md` → "Spike Protocol"
**Author:** Spike branch `spike/619-did-web-rotation`
**Date:** 2026-05-22

## TL;DR

**Recommendation:** introduce multi-key DID Documents for `did:web` issuers backed by an opt-in `POST /v1/keys/rotate` endpoint, while leaving `did:key` rotation on its current single-key flag-flip semantics. The change is **publish-side only** — `packages/verification/src/vc-jwt.ts:179-213` already iterates `verificationMethod[]` and matches by `kid`, so the verify path is ready today. Concurrency is handled by last-writer-wins with a warn log on the rotation path; OpenCred operators running a single issuer node (the default) never hit it, and the design surfaces the limitation clearly for operators who run replicas.

**No code lands in this spike PR** — it produces this doc + a follow-up implementation issue. The four-PR sequence outlined in `.claude/plans/write-up-a-plan-misty-tower.md` lands the implementation as a separate PR after #615/#616/#617/#618 ship.

---

## 1. Problem statement

OpenCred's current `markDIDRotated` flow ([`packages/dedi-client/src/adapter/client.ts:345-415`](../../packages/dedi-client/src/adapter/client.ts)) flips an entire DeDi record's `keyStatus: "current" → "rotated"`. That semantic is **correct for `did:key`** — generating a new key produces a *new* DID, so the prior DID record is logically retired in its entirety. The desktop client wires this into key-generation ([`apps/desktop/src/main/ipc-handlers.ts:416-432`](../../apps/desktop/src/main/ipc-handlers.ts)) and a stable invariant holds: one DID per key, status flag captures the lifecycle.

For **`did:web`** the same flow is wrong. The DID is anchored to a domain (`did:web:issuer.example.org`) and stays stable across key rotations — that stability is precisely the feature an operator pays the DNS + hosting cost for. Rotating a key under `did:web` should:

1. Add the new key to `verificationMethod[]`.
2. Keep the **old** key in `verificationMethod[]` so already-issued credentials still verify against their original signing key.
3. Annotate the old key with rotation metadata (`supersededAt`, optionally `revoked: false`) so verifiers and consumers can distinguish current from superseded keys.
4. **Not** flip the parent DID's `keyStatus` flag — the DID itself isn't rotated, only one of its keys is.

Today OpenCred has none of this. A `did:web` operator who swaps their `OPENCRED_KEY_PATH` and restarts the container produces signatures from a new key that nothing in DeDi or `.well-known/did.json` reflects. Existing credentials silently fail verification once the operator updates their hosted DID document; new credentials silently succeed only after the hosted document is updated. **Production `did:web` issuers cannot safely rotate keys with the current code.** That is the gap this spike closes.

---

## 2. What the verify side already supports

Before designing publish-side changes, confirm what the verify side does today so we don't over-build.

**`packages/verification/src/vc-jwt.ts:179-213`** resolves a `did:web` DID to its document, then:

```ts
const vms = resolution.didDocument.verificationMethod;
const targetId = header.kid;
const vm = targetId ? vms.find((m) => m.id === targetId) : vms[0];
```

- The verifier extracts `kid` from the JWT header.
- It searches the `verificationMethod[]` array for a matching `id`.
- Falls back to `vms[0]` when no `kid` is supplied.
- Supports both `publicKeyJwk` and `publicKeyMultibase` encodings (lines 201-207).

The verifier does **not** consult per-key metadata fields (`revoked`, `supersededAt`, `expires`) today. For a v1 rotation flow this is fine — verification correctness only depends on the right key being in the array at the right `id`. Per-key revocation metadata becomes a verifier feature later (see §7 "out of scope" and §9 "open questions").

**Verdict:** the verifier supports multi-key documents out-of-box. This spike's design is publish-side only.

---

## 3. Proposed DID Document shape

OpenCred's `publishDID` currently stores a `{did, document?, keyStatus: "current"}` record in DeDi ([`packages/dedi-client/src/adapter/client.ts:312-332`](../../packages/dedi-client/src/adapter/client.ts)). For `did:web` the `document` field carries a standard W3C DID Document. Today's docs have a single `verificationMethod` entry:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:issuer.example.org",
  "verificationMethod": [
    {
      "id": "did:web:issuer.example.org#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:issuer.example.org",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
    }
  ],
  "assertionMethod": ["did:web:issuer.example.org#key-1"]
}
```

After rotation, the document carries **all keys ever published for this DID**, each with metadata. Example after one rotation:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:issuer.example.org",
  "verificationMethod": [
    {
      "id": "did:web:issuer.example.org#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:issuer.example.org",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
      "supersededAt": "2026-05-22T14:00:00Z"
    },
    {
      "id": "did:web:issuer.example.org#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:web:issuer.example.org",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
    }
  ],
  "assertionMethod": ["did:web:issuer.example.org#key-2"]
}
```

### Field-by-field rationale

| Field | Source | Notes |
|---|---|---|
| `verificationMethod[].id` | URL fragment, unique within the document. **W3C DID Core requires uniqueness.** OpenCred mints fragments as `#key-N` where N is a monotonic counter held in DeDi record metadata. |
| `verificationMethod[].type` | Always `JsonWebKey2020` for OpenCred-published keys (matches what `generateDidWebDocument()` produces today). |
| `verificationMethod[].publicKeyJwk` | The P-256/Ed25519 JWK extracted from the new signer at rotation time. Same encoding as the initial publish. |
| `verificationMethod[].supersededAt` | **ISO 8601 timestamp** marking when this key was superseded. Set when a rotation pushes a new key in. Absent on the current key. Non-standard W3C field — see "spec compliance" below. |
| `verificationMethod[].revoked` | Optional boolean. **Not set by rotation** (a rotated key is still cryptographically valid for old credentials; it's just no longer the active signing key). Reserved for a future "revoke a compromised key" flow that's deliberately out of scope here. |
| `assertionMethod[]` | Points at the **current** key only. Verifiers that walk `assertionMethod[]` (rather than searching `verificationMethod[]` by kid) automatically pick up the new key for incoming credentials. |

### Spec compliance — `supersededAt`

The W3C DID Core spec doesn't define `supersededAt`. Per the spec, `verificationMethod` entries MAY carry arbitrary additional properties — they just won't be honoured by spec-only resolvers. `supersededAt` is informational metadata for human operators and DeDi-aware tooling; verification correctness is independent of it (verifier picks the key by `kid`, not by `supersededAt`).

Two existing conventions in the wild:
- **W3C VC Status List 2021** uses `revoked: true` for revoked credentials. Borrowing `revoked` for keys would conflate "key is no longer signing" with "key was compromised."
- **DIF Sidetree** carries `expires` and `revealValue`. We don't need either for this v1 — `supersededAt` keeps semantics narrow.

We could canonicalise `supersededAt` under an OpenCred-namespaced property (`opencred:supersededAt`) to keep the document strictly spec-pure. Pulling this thread loses ergonomics — operators reading the JSON would have to know the namespace. **Recommendation: emit bare `supersededAt`** and document it in `docs/concepts/`.

---

## 4. New endpoint: `POST /v1/keys/rotate`

### Request

```http
POST /v1/keys/rotate
Authorization: Bearer <OPENCRED_API_KEY>
Content-Type: application/json

{
  "namespace": "issuer.example.org"   // optional, defaults to OPENCRED_DEDI_NAMESPACE
}
```

### Behaviour

Same pattern as `/v1/keys/publish` but **read-merge-write** instead of insert:

1. Resolve the issuer's current DID from the loaded signer (`getActiveSigner()`).
2. Verify the configured `OPENCRED_ISSUER_DID_METHOD === "web"`. For `did:key`, return `400 KEY_METHOD_MISMATCH` with a hint pointing the operator at the existing key-generation flow (which produces a new DID, not a rotation).
3. `dediClient.resolveDID(did, namespace)` to fetch the existing document.
4. Compute the next fragment counter (`#key-N+1`) by scanning the existing `verificationMethod[]` IDs.
5. Build the new VM entry from the loaded signer's `publicKeyJwk`.
6. Mark each prior VM entry without `supersededAt` as superseded **now** (idempotent — re-running rotate on a still-current key is a no-op if the active key matches the latest VM entry).
7. Replace `assertionMethod` to point at the new VM only.
8. Write the merged document back via `dediClient.api.updateRecord(ns, PUBLIC_KEY_REGISTRY, recordName, { did, document })`.
9. Return `200 { rotated: true, did, currentKeyId, superseded: [...] }`.

### Error cases

| Status | Code | Cause |
|---|---|---|
| 400 | `KEY_METHOD_MISMATCH` | Issuer DID method is `key`, not `web`. Hint: regenerate the key (new DID), not rotate. |
| 404 | `DID_NOT_PUBLISHED` | DeDi has no record for this DID. Caller must call `/v1/keys/publish` first. |
| 503 | `DEDI_NOT_CONFIGURED` | DeDi env vars not set. |
| 502 | `DEDI_CLIENT_ERROR` | Any other DeDi failure (network, auth, registry shape). |

### Idempotency

Calling rotate twice in a row with the **same loaded signer** is a no-op after the first call:

- Step 4 finds the same `#key-N+1` fragment already in `verificationMethod[]`.
- Step 6 skips marking it superseded (it's already the current key — no `supersededAt`).
- Steps 7-8 write the same payload.

This matters for operator ergonomics (re-running after a transient network failure is safe) but also for the concurrency story below.

---

## 5. Concurrency: races and how we handle them

Today's `markDIDRotated` ([`adapter/client.ts:358-371`](../../packages/dedi-client/src/adapter/client.ts)) relies on two structural invariants for race-safety:

1. **Monotonicity** — the `keyStatus` flip is one-way (`current → rotated`).
2. **Identical payloads** — concurrent callers send the same merged document (because the flip is the only change).

Multi-key rotation **breaks both**:

1. Two rotations in quick succession produce different `verificationMethod` arrays (new key A vs new key B, each with their own `#key-N+1` fragment).
2. The read-merge-write window between `resolveDID` (step 3) and `updateRecord` (step 8) is racy.

### Options considered

| Option | Pros | Cons |
|---|---|---|
| **(a) DeDi-side optimistic concurrency** (If-Match header, version stamp) | Lossless; safe under arbitrary concurrency | DeDi has no such mechanism today (see [`adapter/client.ts:358-371`](../../packages/dedi-client/src/adapter/client.ts) comments). Requires DeDi roadmap input. |
| **(b) Last-writer-wins with warn logs** | Zero new infra; matches today's de facto behaviour for the simpler `markDIDRotated` case | Lossy — one rotation can clobber the other under simultaneous calls. Acceptable only when concurrent rotations are rare (single-issuer-node default). |
| **(c) Serialized rotations via a process-local lock** | Safe within a single OpenCred process | Doesn't help with multi-replica deployments, which are exactly the case where this matters. |

**Recommendation: (b) last-writer-wins with warn logs.** Concrete rationale:

- The **default deployment** is a single OpenCred container with one signing key — rotation is an operator-initiated event, not concurrent.
- Multi-replica deployments (`OPENCRED_BATCH_DISPATCH=queue` + horizontal scaling) are the only case where two rotations could fire simultaneously. Operators running that topology already understand they need external coordination for control-plane operations.
- The warn log surfaces the loss when it happens: "Rotation completed but the previous resolved document had N keys, the final document has N+1 — possible concurrent rotation."
- This unblocks v1. Option (a) becomes the right answer once DeDi exposes optimistic concurrency — track separately.

The implementation issue MUST call this out under "Risks" so the rollout knows the limit.

---

## 6. `markDIDRotated` semantic split

After this lands, `markDIDRotated` behaves differently per DID method:

| DID method | Today | After this spike |
|---|---|---|
| `did:key` | Flips entire DID record's `keyStatus` to `"rotated"`. Desktop's key-generation hook calls this for every prior DID owned by the client. | **Unchanged.** A new did:key key = a new DID, so flipping the OLD did:key's `keyStatus` remains the right action. |
| `did:web` | Same `keyStatus` flip on the entire DID record. **Wrong** — the DID isn't rotated, only one of its keys is. | **No-op at the DID-record level.** Rotation is recorded inside `document.verificationMethod[]` instead. The DID record's `keyStatus` field stays `"current"` for the lifetime of the DID. |

The adapter implementation:

```ts
async markDIDRotated(did: string, namespace?: string): Promise<DIDRecord> {
  // did:key keeps existing semantics — the entire record's keyStatus flips.
  if (did.startsWith("did:key:")) {
    return this.flipKeyStatusToRotated(did, namespace);
  }
  // did:web: rotation lives inside verificationMethod[]. The whole-record
  // status flip would be wrong (the DID isn't rotated, just one of its
  // keys). Callers who want did:web rotation must use the new /v1/keys/rotate
  // endpoint or call dediClient.rotateDIDWeb(did, newKey).
  if (did.startsWith("did:web:")) {
    this.logger.warn(
      { did },
      "markDIDRotated called for did:web — semantics differ; use rotateDIDWeb instead. " +
        "No-op at the DID record level.",
    );
    return this.resolveDID(did, namespace);
  }
  // Future-proof: unknown methods get the conservative whole-record flip.
  return this.flipKeyStatusToRotated(did, namespace);
}
```

The desktop key-generation hook ([`ipc-handlers.ts:416-432`](../../apps/desktop/src/main/ipc-handlers.ts)) keeps calling `markDIDRotated` unchanged — for did:key DIDs it flips correctly; for did:web DIDs it no-ops (correct), and the new rotation endpoint takes over.

---

## 7. Migration

**No data migration required.**

- Existing DeDi did:web records with a single `verificationMethod` entry remain valid. The verifier's fallback (`vms[0]` when no `kid` matches) handles them today.
- The first call to `/v1/keys/rotate` for a given DID overwrites the existing single-entry document with the multi-entry shape. Old credentials signed under that first key continue to verify because the entry stays in the document (now annotated with `supersededAt`).
- did:key records are completely untouched.

**Doc backfill:** `docs/bootcamp/local-docker.md` §7d should add a short caveat after this lands:

> Heads-up: under `OPENCRED_ISSUER_DID_METHOD=web`, rotate keys via `POST /v1/keys/rotate` rather than swapping `OPENCRED_KEY_PATH` and restarting. The rotate endpoint preserves the old key in the DID Document so already-issued credentials keep verifying.

That callout lands as part of the impl PR's doc updates.

---

## 8. Out of scope for this spike

The followup issues for each of these will be tracked separately.

- **KMS-backed key rotation orchestration.** When the signer is AWS KMS / Azure Key Vault / GCP Cloud KMS, rotating means rotating the KMS key version, which has its own provider-specific dance. The new `/v1/keys/rotate` endpoint assumes file-based or HSM-backed signers that expose `signer.publicKeyJwk` directly. KMS key-version rotation is its own PR.
- **Per-key revocation** (`revoked: true` semantics distinct from `supersededAt`). Use case: an issuer discovers a key was compromised and wants past credentials signed by that key to fail verification. This is **harder** because today's verifier doesn't consult `revoked` flags, and it changes the credential-validity contract. Park.
- **Rotation audit log.** Today DeDi stores only the latest document; the per-rotation history is implicit in the `supersededAt` timestamps. A real audit log would write rotation events to a separate registry. Park until an operator asks.
- **Multi-region replicated rotations.** Out of scope; relies on DeDi-side concurrency support (option (a) in §5).

---

## 9. Open questions for the impl PR

1. **`#key-N` vs `#key-<thumbprint>`** for the fragment scheme? Counter is simpler and reads better; thumbprint is collision-free across rotations and re-publishes. Recommendation: counter for v1, document the limitation.
2. **Cap on the number of historic keys?** A long-lived issuer might accumulate dozens. Some DeDi backends may have a payload-size cap. Recommendation: no cap in v1, monitor wire sizes, add a configurable `OPENCRED_DIDWEB_MAX_HISTORY_KEYS` if needed.
3. **Should `/v1/keys/rotate` accept an explicit new key in the body?** Today it reads from `getActiveSigner()` — the operator has already swapped `OPENCRED_KEY_PATH` and restarted. Accepting an inline JWK lets callers rotate without restarting. Recommendation: skip for v1; the restart-then-rotate flow is the standard operator pattern and accepting inline keys widens the attack surface.

---

## 10. Verification (after the impl PR lands)

The impl PR's PR-test plan should cover:

- [ ] `/v1/keys/rotate` returns 200 with the new multi-key document for did:web.
- [ ] Returns 400 KEY_METHOD_MISMATCH for did:key issuers.
- [ ] Returns 404 DID_NOT_PUBLISHED when the DID has no DeDi record yet.
- [ ] Returns 503 when DeDi isn't configured.
- [ ] After rotate, `resolveDID()` returns a document with both old and new keys; old key has `supersededAt`, new key doesn't.
- [ ] After rotate, an old credential signed by the prior key still verifies (verifier picks key by `kid`).
- [ ] After rotate, a fresh credential signed by the new key verifies.
- [ ] `markDIDRotated("did:web:...")` is now a no-op at the record level + logs a warn.
- [ ] `markDIDRotated("did:key:...")` still flips `keyStatus` as before (regression guard).
- [ ] Two near-simultaneous rotations on the same DID land last-writer-wins + warn log (race regression guard).

---

## 11. Implementation issue

After this PR merges:

1. File a follow-up GitHub issue titled "Implement did:web multi-key rotation (per docs/spikes/spike-619-did-web-rotation.md)".
2. Label: `phase-7`, plus a new `did-web-rotation` label.
3. Checklist:
   - [ ] New `POST /v1/keys/rotate` route handler.
   - [ ] New `dediClient.rotateDIDWeb(did, newKey, namespace?)` adapter method.
   - [ ] Split `markDIDRotated` per DID method.
   - [ ] Surface `signer.publicKeyJwk` on the Signer interface if it isn't already (sub-task of PR 4 too).
   - [ ] Tests covering the verification matrix in §10.
   - [ ] Doc callout in `docs/bootcamp/local-docker.md` §7d.
   - [ ] Mark §7 in `docs/bootcamp/post-bootcamp-followups.md` as Implemented (link to PR).

The plan in `.claude/plans/write-up-a-plan-misty-tower.md` (PR 5) treats this spike as the deliverable; the implementation issue is the actual production change.
