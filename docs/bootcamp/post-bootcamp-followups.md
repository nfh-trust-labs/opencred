# Post-Bootcamp Follow-ups

Issues and gaps surfaced while dry-running the Local-Docker bootcamp on 2026-05-21. Fix order is roughly priority-descending. None of these block the bootcamp itself once the new image is published; they are the cleanup pass to make the published `:latest` actually match what `docs/bootcamp/` claims.

## 1. Cut a new release with the dedi-client revoke/publish fix

**Status**: code is on `main` (commit `34c830d3` — `fix(dedi-client): chain publish-records + use lookup for revocation queries (#612)`); not yet in any published image.

**Symptom**: image tag `:latest` resolves to `v1.4.1` (2026-05-15). On that image, both `POST /v1/credentials/revoke` and `POST /v1/keys/publish` hit DeDi with the `?publish=true` shortcut, which returns 201 but leaves the record in DRAFT. The OpenCred dedi-client then asserts `record_name` on a response shape that does not carry it and returns:

```
{ "error": { "code": "DEDI_CLIENT_ERROR",
             "message": "DeDi API publishRecord data response missing required field: record_name" } }
```

Retries return DeDi 409 `"duplicate record name"` because the DRAFT record blocks re-creation but never becomes visible to `lookup/`. This is exactly issue #610.

**Action**: tag and publish `v1.4.2` (or whatever the next semver is) so the published image actually carries the fix. Until then, the bootcamp §7c (revocation) and §7d (DID publish/resolve) sections only work for users who build from source.

## 2. Postman collection — Issue → Revoke threading

**Gap**: `POST /v1/credentials/revocation-hash` is the only path that auto-saves `lastRevocationHash`, and its body is a hardcoded sample VC, so the click-chain `Issue → Revoke` does not work as documented.

**Better fix (no extra call needed)**: when `revocationRegistryUrl` is set on the issue request, the server embeds the hash as the last URL segment of `credential.credentialStatus.id` (apps/server/src/routes/credentials.ts:477-499). Postman's post-test script on the issue requests can extract it directly:

```
const m = /([a-f0-9]{64})$/.exec(body?.credential?.credentialStatus?.id ?? "");
if (m) pm.collectionVariables.set("lastRevocationHash", m[1]);
```

**Action**:
- Add the extractor above to every `POST /v1/credentials/issue (*)` post-test script that uses `revocationRegistryUrl` (today: only the electricity request; after this fix this becomes the recommended way to demo revoke).
- Also save the full VC envelope into a new `lastCredentialObject` collection variable so the existing `/v1/credentials/revocation-hash` request can be pre-request-script-threaded (same pattern as `/v1/credentials/package` already uses) for non-OpenCred VCs.
- Update `/v1/credentials/revoke` description to say "use `{{lastRevocationHash}}` — already populated by the issue request when `revocationRegistryUrl` is set, no separate hash call needed."

## 3. Postman collection — DID publish + resolve

**Gap**: the Postman collection has zero requests for the §7d DID-publish/resolve flow. The bootcamp doc shows shell-only examples; Postman users have no Send-button path.

**Action**: add a new section **"Key publish / resolve (DeDi)"** with:

- `POST /v1/keys/publish (did:key, auto from {{issuerDid}})` — pre-request script builds `{"did": "{{issuerDid}}"}` body. For did:key the server drops the document anyway, so a minimal body works.
- `POST /v1/keys/resolve (auto from {{issuerDid}})` — `{"did": "{{issuerDid}}"}` body.
- Optionally: `POST /v1/keys/publish (did:web fresh)` that builds `did:web:bootcamp-<timestamp>.example.org` with the issuer's real P-256 public key (pulled from `GET /v1/keys`), so the publish is guaranteed-fresh (no 409) for live demos.

Save the published DID to a new `lastPublishedDid` collection variable so the resolve request can be wired to either `{{issuerDid}}` or `{{lastPublishedDid}}`.

## 4. Bootcamp doc — clarify when publish actually happens

**Gap**: `docs/bootcamp/local-docker.md` §7d describes the publish/resolve endpoints but does not make explicit that **the issuer's DID is not auto-published at container startup**. Startup only runs `ensureRegistries()`, which creates the empty registries; the DID stays out of DeDi until `POST /v1/keys/publish` is called. The §4 log line `Issuer identity configured` is purely an in-memory configuration message — easy to misread as "and also published it."

**Action**: add a callout under §4 (right after the `/v1/health` block) and again under §7d:

> **Heads-up — the issuer's DID is not published to DeDi automatically.** Container startup creates the four empty registries (`vc-revocation-registry`, `public_key_registry`, `schema_registry`, `context_registry`) and loads your signing key into memory, but it does not write your DID into `public_key_registry`. To make verifiers discover your public key via DeDi, you have to explicitly call `POST /v1/keys/publish`. Until then, `/v1/keys/resolve` returns 404.

## 5. Bootcamp doc — clarify 409 semantics for revoke + publish

**Gap**: §7c and §7d do not explain that running the same revoke/publish twice (across container restarts, prior bootcamp runs, etc.) will return DeDi 409, which propagates out of OpenCred as `DEDI_CLIENT_ERROR: DeDi API error: 409`. First-time attendees hit this and assume something is broken.

**Action**: add a row to the §8 troubleshooting table:

| Symptom | Likely cause | Fix |
|---|---|---|
| `POST /v1/credentials/revoke` returns `409 "duplicate record name"` | The hash you are trying to publish is already revoked in `vc-revocation-registry` (typical after re-running the bootcamp without re-issuing) | Issue a NEW credential with `revocationRegistryUrl` set — each issue mints a fresh `urn:uuid:` → fresh hash → no collision. To confirm the prior revoke actually landed, hit `/v1/credentials/revocation-status` with the existing hash. |
| `POST /v1/keys/publish` returns `409 "duplicate record name"` | This DID was already published in a prior run (record_name = DID) | Either run `/v1/keys/resolve` instead (the previous publish landed; the resolve is the demo), or publish a fresh `did:web:<unique>` you have not used before. |

## 6. (Decision needed) Make `/v1/credentials/revoke` and `/v1/keys/publish` idempotent

**Open question — needs a decision, not a code change yet.**

Today both endpoints surface DeDi 409 as `DEDI_CLIENT_ERROR: 409`. The semantic "this hash/DID is already in the registry" arguably means the operation already succeeded earlier, so 409 could be treated as success (200 with a hint like `{"alreadyRevoked": true}` / `{"alreadyPublished": true}`).

**For**:
- Idempotent ops are easier to retry; bootcamp demos would be more forgiving.
- The end state DeDi reaches is identical whether the call succeeded for the first time or was a no-op.

**Against**:
- Hides accidental hash collisions (two different VCs that share a hash would silently overwrite — though that is a SHA-256 collision, not actually a concern).
- Hides operational mistakes — e.g. publishing the wrong DID twice gets silently masked.
- Changes the contract of a security-sensitive endpoint without a migration path.

**Proposed**: keep strict 409 behavior on both endpoints. Add a clear hint in the error response that points users to the status/resolve endpoint instead:

```
{ "error": {
    "code": "DEDI_RECORD_EXISTS",
    "message": "This hash is already in the revocation registry",
    "hint": "Use POST /v1/credentials/revocation-status to confirm the prior revoke landed",
    "statusCode": 409
}}
```

Same shape for publish. This preserves the audit signal while making the error self-describing.

**Action**: file an issue, gather input before implementing.

## 7. Key rotation under did:web is not fully wired

**Status**: significant gap, needs design before code.

**Today's behavior**:

- **did:key**: rotation = generating a new key, which produces a new DID. Old credentials remain cryptographically valid against the old did:key forever. The desktop's `markDIDRotated` hook correctly flips the OLD did:key record's `keyStatus` to `"rotated"` in DeDi when a new key is generated. Server (Docker) has no rotation hook at all — operators just restart with a new `OPENCRED_KEY_PATH`, but for did:key that means a different issuer DID, so consumers need to know that.

- **did:web**: rotation = the DID stays the same (`did:web:your-domain`), but the public key inside the DID Document changes. **OpenCred has no flow that updates the DID document on key change.** The `markDIDRotated` desktop hook flips the entire did:web record to `"rotated"`, which is wrong semantics — the DID isn't rotated, just one of its keys is. The right thing is to update the DID document's `verificationMethod` to add the new key and mark the prior key as superseded, leaving the DID itself stable.

**What did:web rotation should look like** (proposed):

1. A new endpoint `POST /v1/keys/rotate` (Docker) or IPC `KEY_ROTATE` (Desktop) that:
   - Loads the new key (file swap on Docker, generate on Desktop)
   - Reads the existing DID document (from `.well-known/did.json` or DeDi)
   - Produces an updated document with the new key appended to `verificationMethod`, the old key kept and tagged with rotation metadata (`revoked: false, supersededAt: <timestamp>`) so already-issued credentials still verify
   - Re-publishes the updated document (`.well-known/did.json` re-host is operator's job; DeDi-hosted is handled via DeDi `update-record`)
2. Verifier behaviour stays unchanged — `verificationMethod` is plural by design; verifiers pick the right key by `kid`.
3. The `markDIDRotated` DeDi flag becomes did:key-only. For did:web, the DID record's `details` carries the multi-key document and there's no top-level `keyStatus: "rotated"` flip on a per-DID basis (each key inside the document has its own lifecycle).

**Why this matters for operators**:

- An issuer using did:web is signing up for a long-lived public identity. Forcing them to generate a new DID every time they rotate would defeat the point of did:web (key rotation under a stable identity is exactly the feature they're paying the DNS/hosting cost for).
- Today, if a Docker operator running did:web swaps their key file and restarts, every new credential's signature will fail to verify against the still-published OLD public key — silent breakage until someone tries to verify.

**Action**:

1. File a design issue under `phase-3` or a new `did-web-rotation` label — explicitly call out the multi-key DID Document shape, the rotation endpoint, and the DeDi record migration story.
2. Decide whether the existing `dediPublishedDIDs` list (desktop) carries forward, or whether did:web rotation becomes a fundamentally different code path from did:key rotation.
3. Pull `markDIDRotated` semantics apart: did:key keeps current "rotated entire record" semantics; did:web introduces per-key rotation inside the document.
4. Until this lands, **document the constraint**: in `docs/bootcamp/local-docker.md` §7d and in the deployment doc, say "did:web key rotation requires manually republishing the DID document; OpenCred does not handle this today."

## 8. (Decision needed) Auto-publish the issuer DID at first boot (opt-in)

**Open question — almost certainly NOT a default.**

Today users have to remember to call `/v1/keys/publish` once after first container boot. An optional env var like `OPENCRED_AUTO_PUBLISH_KEY=true` could trigger `dediClient.publishDID(getActiveKey().did, getActiveKey().didDocument)` from the startup hook, making the DID resolvable via DeDi immediately.

**Against making this default**:
- Side effects in startup hooks are nasty to reason about — current `ensureRegistries()` is idempotent; auto-publish writes business data and is harder to roll back.
- It mints a DeDi record on every fresh deploy, polluting the registry with throwaway DIDs from test/staging environments.
- For `did:web` issuers, the DID document needs to be assembled at startup, which adds another failure mode.

**Action**: park this until someone hits the friction in production. The current explicit-publish flow is the right default; we just need to make it more discoverable (see §4 + §3 above).

---

## Quick reference — which issues are blocked on which fix

| Fix | Unblocks |
|---|---|
| §1 publish v1.4.2 image | §7c (revoke) + §7d (publish/resolve) actually working from `:latest` |
| §2 Postman post-script | Click-through Issue → Revoke demo |
| §3 Postman publish/resolve requests | Click-through DID publish demo |
| §4 doc callout | Stops users assuming startup auto-publishes |
| §5 doc 409 troubleshooting | Reduces support pings |
| §6 (decision) | Future ergonomic improvement; not blocking |
| §7 did:web rotation | Production did:web is unsafe to operate until this is addressed |
| §8 (decision) | Future opt-in feature; not blocking |
