# DeDi integration — decisions + implementation

Status: **Implemented** — landed across PRs [#558](https://github.com/nfh-trust-labs/opencred/pull/558), [#557](https://github.com/nfh-trust-labs/opencred/pull/557), [#561](https://github.com/nfh-trust-labs/opencred/pull/561), [#562](https://github.com/nfh-trust-labs/opencred/pull/562).
Last updated: 2026-05-20.

Three architectural questions surfaced while diffing our DeDi client against the real DeDi API (Postman collection on `develop`, accessed 2026-05-19) and the canonical schemas at `dedi.global`. This doc records the decisions and the implementation that followed.

---

## Decisions

### D1. Tag vs. custom schema, per registry

| Registry | Approach | Rationale |
|---|---|---|
| `vc-revocation-registry` | **DeDi `tag: "revoke"`** | Canonical schema fits cleanly; we get tag-based discovery for free |
| `public_key_registry` | **Custom schema** (we own it) | DeDi's `public_key` schema doesn't fit DID Documents; we want full control of the shape |
| `schema_registry` | Custom (unchanged) | No canonical `schema` tag exists |
| `context_registry` | `tag: "custom"` (unchanged) | JSON-LD contexts are dynamic — already free-form |

Tag casing fix: [`DeDiRegistryTag`](../../packages/dedi-client/src/api/types.ts) was capitalized (`"Revoke"`, `"Public_key"`); the Postman uses lowercase (`"revoke"`, `"public_key"`, `"membership"`). Switched to lowercase in #558.

### D2. Public-key model — full DID Document, our schema

We store the DID Document as the source of truth (one record per DID, not per stable issuer). DID-method-specific notes:
- `did:web`: `document` field carries the full W3C DID Document (the registry acts as a cache for the domain-hosted doc).
- `did:key`: `document` field omitted entirely (the DID is self-describing — verifier derives the document from the DID string via the did:key resolution algorithm).

Key rotation is signalled by a single `keyStatus` field on the record, flipped from `"current"` to `"rotated"` via `update-record`. No `supersededBy` chain, no metadata, no `resolvedAt`.

### D3. Record state — manage independently of DeDi

Confirmed in Postman: DeDi has **no per-record `revoke-record` / `suspend-record` / `reinstate-record` endpoints**. Only:
- `POST /dedi/{ns}/{reg}/inactivate-registry` / `…/reactivate-registry` (registry-level)
- `DELETE /dedi/{ns}/{reg}/delete-records` + `POST /dedi/restore/records` (soft delete with restore)

Our prior calls hit routes that didn't exist. **Decision: drop them** (landed in #557). OpenCred manages credential revocation and key rotation independently of DeDi's record `state` field:

- **Revocation** = "a record exists in the Revoke registry with this VC hash." That's it. No per-record state transitions.
- **Key rotation** = `keyStatus: "rotated"` on the DID record (flipped via DeDi's `update-record`).

DeDi's envelope `state` (`live` / `suspended` / `revoked` / `expired`) is ignored for OpenCred semantics.

---

## Final schemas

### `vc-revocation-registry` — DeDi `tag: "revoke"`

No schema body from us; DeDi enforces its canonical [revoke.json](https://dedi.global/revoke.json):

```json
{
  "$id": "https://dedi.global/revoke.json",
  "type": "object",
  "properties": {
    "revoked_id": { "type": "string", "description": "VC hash" },
    "reason":     { "type": "string", "description": "Optional reason" }
  },
  "required": ["revoked_id"]
}
```

Wire payload: `{ "revoked_id": "<vc-hash>", "reason": "key-compromise" }`. Record existence ⇒ revoked.

### `public_key_registry` — custom schema (we pass this)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "description": "OpenCred DID Document registry",
  "properties": {
    "did":       { "type": "string", "pattern": "^did:" },
    "document":  { "type": "object", "description": "W3C DID Document. Omit for did:key — verifier derives from DID." },
    "keyStatus": { "type": "string", "enum": ["current", "rotated"] }
  },
  "required": ["did", "keyStatus"],
  "additionalProperties": false
}
```

Two wire shapes:

```jsonc
// did:web
{ "did": "did:web:issuer.example", "document": { ... }, "keyStatus": "current" }

// did:key
{ "did": "did:key:z6Mk…", "keyStatus": "current" }
```

Record name: DID with colons replaced by dashes (existing convention in [`didToRecordName`](../../packages/dedi-client/src/adapter/client.ts)).

App-level invariant (not in schema): publishing a `did:web` record without a `document` is a bug — `publishDID` rejects it before calling DeDi.

---

## Implementation — what shipped

The plan landed as four sequenced PRs against `new-opencred-dev`:

| PR | Title | Scope |
|---|---|---|
| [#558](https://github.com/nfh-trust-labs/opencred/pull/558) | `fix(dedi-client): correct response envelope parsing for real DeDi API` | Wire-format fixes: `DeDiRecord<T>` shape, `data.details`, lowercase tags, bulk-upload form fields, search response. |
| [#557](https://github.com/nfh-trust-labs/opencred/pull/557) | `refactor(dedi-client): drop unused record-state endpoints` | Deleted `revokeRecord`, `suspendRecord`, `reinstateRecord`, `changeRecordState` — DeDi has no such routes. |
| [#561](https://github.com/nfh-trust-labs/opencred/pull/561) | `feat(dedi-client): migrate revocation registry to DeDi canonical revoke tag` | `tag: "revoke"`, payload `{ revoked_id, reason? }`, record-existence semantics. |
| [#562](https://github.com/nfh-trust-labs/opencred/pull/562) | `feat(dedi-client,verification,desktop): simplify DID record + add keyStatus rotation flag` | `DIDRecord = { did, document?, keyStatus }`; `markDIDRotated`; verifier UI collapses attribution → `current` / `rotated` / `unknown`. |

Breaking changes documented:
- `/v1/keys/resolve` response shape changed to `{ did, document?, keyStatus }`. Downstream consumers that read `resolvedAt` / `metadata` / `supersededBy` must update. ([keys.ts route JSDoc](../../apps/server/src/routes/keys.ts).)

---

## Follow-ups (deferred)

- **Surface the `proof` block on `DIDRecord` / `SchemaRecord`** so verifiers can use the CORD blockchain anchor for cryptographic verification. Spawned as a separate task — see GitHub Issues.
- **Capture `reason` in the desktop revocation UI.** The dedi-client and server route already accept it; UI plumbing is still pass-through.
- **Multi-user safety for `markDIDRotated`.** The read-merge-write helper is racy under concurrent rotations from multiple desktops; an `If-Match`/version check on `update-record` would close the window. Track with DeDi team. _(Superseded by D4 below — `markDIDRotated` was replaced by the per-key `setKeyStatus` in the per-key-registry redesign; the same concurrency question now lives there.)_
- **Confirm DeDi's JSON Schema validator** (draft-07, Ajv strict mode?) so we can trust the optional-`document` design for did:key without surprises.

---

## D4. `setKeyStatus` optimistic concurrency (issue [#659](https://github.com/nfh-trust-labs/opencred/issues/659))

The per-key-registry redesign replaced the per-DID `markDIDRotated` with [`setKeyStatus(verificationMethod, status, ns)`](../../packages/dedi-client/src/adapter/client.ts), which advances a key's lifecycle (`active → rotated → revoked`) via DeDi's `update-record`. `update-record` carries **no conditional-update parameter** — no `If-Match`, no ETag, no `version` CAS — so the write is a blind, last-writer-wins overwrite of the whole payload.

**Why it's safe today.** `status` is the *only* mutable field, and it advances monotonically. Every writer reads-then-advances; the rank guard refuses any backward move (`revoked → rotated` is a no-op); `revoked` is terminal. So concurrent writers converge on the highest rank any writer requested. The wire envelope's `version` field exists (`DeDiRecord.version`, a string) but the adapter did not previously read it.

**The real hazard — a future schema extension.** Adding any *other* mutable field that can diverge between writers (e.g. a `revokedAt` timestamp, or the `reason` field from the revocation-reason work, [#658](https://github.com/nfh-trust-labs/opencred/issues/658)) silently reintroduces the lost-update race, because the whole payload is overwritten last-writer-wins. Nothing structural prevents that — it relied on a contributor reading the type JSDoc.

**Decision — Option C now, Option A when DeDi supports it.**

- **Now (shipped with #659):**
  - `resolveKey` extracts `version` from the DeDi envelope and logs it at `debug` (no behavior change) so the adapter is positioned to adopt a conditional update later.
  - A load-bearing comment + `TODO(#659)` sits at the `setKeyStatus` `updateRecord` call documenting the monotone invariant and forbidding new mutable fields.
  - A unit test pins the `update-record` payload to exactly the six fields (`keyId`, `controllerDid`, `algorithm`, `publicKeyJwk`, `purpose`, `status`); a second test asserts concurrent rotate-then-revoke converges on `revoked`.
- **Later (Option A):** once DeDi exposes a `version`/ETag conditional `update-record`, pass the read `version` as an If-Match precondition; on a stale-write rejection, re-read and retry. This closes the window for any future divergent field.

**DeDi-team ask:** does `update-record` support (or can it add) a conditional update keyed on the record `version` / an ETag, so a stale write is rejected rather than silently clobbering? Until then, **no mutable `KeyRecord` field beyond `status` may be added** — if `KeyRecord.reason` (#658 Phase B) lands, that PR must address concurrency first.
