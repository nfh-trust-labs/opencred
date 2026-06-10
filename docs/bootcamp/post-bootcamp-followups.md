# Post-Bootcamp Follow-ups

Issues and gaps surfaced while dry-running the Local-Docker bootcamp on
2026-05-21. None of these block the bootcamp itself once the new image is
published; they were the cleanup pass to make the published `:latest`
actually match what `docs/bootcamp/` claims.

**Status as of 2026-05-26:** §2–§9 all landed (or filed for follow-up
where the spike-protocol applies). §1 (release ops) is owned outside
this doc.

| § | Item | Status |
|---|---|---|
| 1 | Cut release with dedi-client revoke/publish fix | Owned by release flow (not closed by this doc) |
| 2 | Postman — Issue → Revoke threading | ✅ **Implemented** in [PR #621](https://github.com/nfh-trust-labs/opencred/pull/621) |
| 3 | Postman — DID publish + resolve | ✅ **Implemented** in [PR #621](https://github.com/nfh-trust-labs/opencred/pull/621) |
| 4 | Bootcamp doc — clarify when publish happens | ✅ **Implemented** in [PR #623](https://github.com/nfh-trust-labs/opencred/pull/623) |
| 5 | Bootcamp doc — 409 troubleshooting rows | ✅ **Implemented** in [PR #623](https://github.com/nfh-trust-labs/opencred/pull/623) |
| 6 | Better 409 → `DEDI_RECORD_EXISTS` error | ✅ **Implemented** in [PR #620](https://github.com/nfh-trust-labs/opencred/pull/620) |
| 7 | did:web key rotation | ✅ **Implemented** in [PR #628](https://github.com/nfh-trust-labs/opencred/pull/628) (design spike [PR #622](https://github.com/nfh-trust-labs/opencred/pull/622); closes [issue #627](https://github.com/nfh-trust-labs/opencred/issues/627); released in v1.6.0) |
| 8 | Opt-in startup auto-publish | ✅ **Implemented** in [PR #624](https://github.com/nfh-trust-labs/opencred/pull/624) (released in v1.6.0) |
| 9 | did:web JWT `kid` correctness (signer VM ID matches published DID Document) | ✅ **Implemented** in [PR #634](https://github.com/nfh-trust-labs/opencred/pull/634) (closes [#632](https://github.com/nfh-trust-labs/opencred/issues/632); released in v1.6.1) |

---

## 1. Cut a new release with the dedi-client revoke/publish fix

**Status**: code is on `main` (commit `34c830d3` — `fix(dedi-client): chain publish-records + use lookup for revocation queries (#612)`); release-please cuts the next published image.

**Symptom**: image tag `:latest` resolves to `v1.4.1` (2026-05-15). On that image, both `POST /v1/credentials/revoke` and `POST /v1/keys/publish` hit DeDi with the `?publish=true` shortcut, which returns 201 but leaves the record in DRAFT. The OpenCred dedi-client then asserts `record_name` on a response shape that does not carry it and returns:

```
{ "error": { "code": "DEDI_CLIENT_ERROR",
             "message": "DeDi API publishRecord data response missing required field: record_name" } }
```

Retries return DeDi 409 `"duplicate record name"` because the DRAFT record blocks re-creation but never becomes visible to `lookup/`. This is exactly issue #610.

**Action**: tag and publish `v1.4.2` (or whatever the next semver is) so the published image actually carries the fix. Until then, the bootcamp §7c (revocation) and §7d (DID publish/resolve) sections only work for users who build from source.

## 2. Postman collection — Issue → Revoke threading ✅

**Status**: **Implemented** in [PR #621](https://github.com/nfh-trust-labs/opencred/pull/621).

**Gap**: `POST /v1/credentials/revocation-hash` was the only path that auto-saved `lastRevocationHash`, and its body was a hardcoded sample VC, so the click-chain `Issue → Revoke` did not work as documented.

**Better fix (no extra call needed)**: when `revocationRegistryUrl` is set on the issue request, the server embeds the hash as the last URL segment of `credential.credentialStatus.id` (apps/server/src/routes/credentials.ts:477-499). Postman's post-test script on the issue requests extracts it directly:

```
const m = /([a-f0-9]{64})$/.exec(body?.credential?.credentialStatus?.id ?? "");
if (m) pm.collectionVariables.set("lastRevocationHash", m[1]);
```

**Landed**:
- Extractor added to every `POST /v1/credentials/issue (*)` post-test script.
- Full VC envelope also saved into `lastFullCredential` (existing variable — reused, not a new one).
- `/v1/credentials/revoke` request description updated to point at `{{lastRevocationHash}}` and clarify no separate hash call is needed.

## 3. Postman collection — DID publish + resolve ✅

**Status**: **Implemented** in [PR #621](https://github.com/nfh-trust-labs/opencred/pull/621). Includes the server-side schema relaxation (`document` is now optional on `/v1/keys/publish`).

**Gap**: the Postman collection had zero requests for the §7d DID-publish/resolve flow. Bootcamp doc showed shell-only examples; Postman users had no Send-button path.

**Landed**: new top-level section **"Public-key registry (DeDi)"** with:

- `POST /v1/keys/publish (did:key, auto from {{issuerDid}})` — minimal body, the adapter drops the document for did:key.
- `POST /v1/keys/resolve (auto from {{issuerDid}})`.
- `POST /v1/keys/publish (did:web fresh, advanced)` — pre-request script builds `did:web:bootcamp-<timestamp>.example.org` and assembles a document from the live `/v1/keys` output. Useful for guaranteed-fresh demo publishes that won't 409.

Published DID saved to new `lastPublishedDid` collection variable. Also: the server-side Zod schema on `POST /v1/keys/publish` was relaxed (`document` is now optional) so did:key callers don't need to send a placeholder document — the adapter still enforces "did:web requires a document".

## 4. Bootcamp doc — clarify when publish actually happens ✅

**Status**: **Implemented** in [PR #623](https://github.com/nfh-trust-labs/opencred/pull/623). Behavior subsequently changed by [PR #624](https://github.com/nfh-trust-labs/opencred/pull/624) — see note below.

**Gap (at the time)**: `docs/bootcamp/local-docker.md` §7d described the publish/resolve endpoints but did not make explicit that **the issuer's DID was not auto-published at container startup**. Startup only ran `ensureRegistries()`. The §4 log line `Issuer identity configured` was purely an in-memory configuration message — easy to misread as "and also published it."

**Landed**: callouts added under §4 (right after the `/v1/health` block) and again under §7d.

**Note**: after PR #624 landed, an operator who explicitly sets `OPENCRED_AUTO_PUBLISH_KEY=true` (or `OPENCRED_DEDI_HOST_DID_DOC=true` for did:web) **does** get auto-publish at startup. The callouts still apply for the default (flag off) case. PR #624 also fixed the latent `OPENCRED_DEDI_HOST_DID_DOC=true` no-op that the bootcamp surfaced on 2026-05-21 — that flag now publishes at startup (for did:web) instead of silently doing nothing.

## 5. Bootcamp doc — clarify 409 semantics for revoke + publish ✅

**Status**: **Implemented** in [PR #623](https://github.com/nfh-trust-labs/opencred/pull/623). The error code referenced is `DEDI_RECORD_EXISTS` from PR #620 (§6 below).

**Gap (at the time)**: §7c and §7d did not explain that running the same revoke/publish twice (across container restarts, prior bootcamp runs, etc.) returns DeDi 409, which surfaced as the generic `DEDI_CLIENT_ERROR: DeDi API error: 409`. First-time attendees hit this and assumed something was broken.

**Landed**: two rows added to the §8 troubleshooting table — one for revoke, one for publish — both referencing the new `DEDI_RECORD_EXISTS` code and pointing at the response `hint` field for the resolution path. A version-stamp note under the table clarifies that older server builds surface the same 409 as the generic `DEDI_CLIENT_ERROR`.

## 6. Better DeDi 409 — `DEDI_RECORD_EXISTS` ✅

**Status**: **Implemented** in [PR #620](https://github.com/nfh-trust-labs/opencred/pull/620).

**Original framing** (decision needed): treat DeDi 409 as success-with-hint, or keep strict 409 with a better error code? Resolved in favour of strict 409 + typed error class — preserves audit signal while making the response self-describing.

**Landed**:
- New `DeDiRecordExistsError` class in `@opencred/shared` (code `DEDI_RECORD_EXISTS`, status 409, `hint` field).
- `dedi-client` adapter rewraps 409 "duplicate record name" responses on both `publishRevocationHash` and `publishDID`, matching DeDi's response body via robust regex (`/duplicate.*record/i` OR `/record.*already.*exists/i` on `message`, `data`, or the stringified body).
- Response shape:
  ```json
  { "error": {
      "code": "DEDI_RECORD_EXISTS",
      "message": "This hash is already in the revocation registry",
      "hint": "Use POST /v1/credentials/revocation-status to confirm the prior revoke landed",
      "statusCode": 409
  }}
  ```
- Same shape for the publish path (with a hint pointing at `/v1/keys/resolve`).

## 7. Key rotation under did:web ✅

**Status**: **Implemented** in [PR #628](https://github.com/nfh-trust-labs/opencred/pull/628), released in v1.6.0. Design spike merged via [PR #622](https://github.com/nfh-trust-labs/opencred/pull/622) (`docs/spikes/spike-619-did-web-rotation.md`); production code closes [issue #627](https://github.com/nfh-trust-labs/opencred/issues/627).

> **Superseded by #670** (per-key registry redesign, PR #671). The original #628 implementation rotated keys *inside* a single per-DID `public_key_registry` record by stamping `supersededAt` on `verificationMethod[]` entries. OpenCred now stores **one record per key** in `opencred-key-registry`: rotation writes a new key record and marks the prior key's record `status: "rotated"` (terminal states are `"active" | "rotated" | "revoked"`). The did.json is an immutable snapshot embedded on each key record, not a mutable document being read-merge-written. The bullets below are retained as the historical #628 record; for the current model see [`docs/decisions/dedi-key-registry-redesign.md`](../decisions/dedi-key-registry-redesign.md).

**Landed (#628; mechanics superseded by #670 — see note above)**:

- New `POST /v1/keys/rotate` endpoint. Reads the active signer, validates the DID is `did:web:`, pulls `publicKeyJwk` from signer metadata, and calls the adapter. Under the current (#670) model the body is `{ newKeyIndex, currentDidDocument?, hostDidDocument? }` and the response is `{ rotated, did, currentKeyId, newKeyIndex, retired, didDocument, didDocumentStored }` (`retired` is the old key's `SetKeyStatusResult`).
- *(Original #628)* `DeDiClient.rotateDIDWeb(did, newKeyJwk, namespace?)` adapter method — read-merge-write against the existing `public_key_registry` record, appending a new VM entry and stamping `supersededAt` on prior entries. **Replaced by #670**: rotation now writes a fresh per-key record into `opencred-key-registry` and sets the prior key's record `status: "rotated"`; old keys are retained as their own records rather than carried as superseded entries inside one document.
- **Idempotent short-circuit**: re-running rotate when the active signer's key is already the current one issues no DeDi write.
- *(Original #628)* `markDIDRotated` semantic split. **Replaced by #670**: `markDIDRotated` is gone; key lifecycle is advanced per-key via `setKeyStatus(verificationMethod, status, ns)` (`active → rotated → revoked`).
- **Read-only gating**: free — `/v1/keys/` is already in `WRITE_PREFIXES`, so a read-tier replica returns `403 READ_ONLY_MODE` automatically.
- **Verifier impact: none** — `packages/verification/src/vc-jwt.ts:179-213` already iterates `verificationMethod[]` and matches by `kid` from the JWT header, so credentials signed under any prior (now-rotated) key still verify.

**Out of scope (filed for separate follow-ups, still parked)**:

- KMS-backed key rotation orchestration. Today only software signers expose `publicKeyJwk`; hardware-token / KMS public-key extraction is its own work item.
- Per-key revocation. Under #670 this is the key record's `status: "revoked"` lifecycle state (set via `POST /v1/keys/revoke`), distinct from credential revocation in `vc-revocation-registry`.
- Rotation audit log.
- DeDi-side optimistic concurrency. The per-key `setKeyStatus` write is still **last-writer-wins** — `update-record` carries no `If-Match`/`version` CAS, so simultaneous lifecycle writes against the same key can race. The right fix is DeDi exposing an `If-Match`-style primitive; raised separately with the DeDi team (see D4 in `docs/decisions/dedi-integration-open-questions.md`).

**Doc surface**: `docs/concepts/dids.md` carries the operator-facing "did:web key rotation" section; `docs/bootcamp/local-docker.md` §7d describes the rotate flow alongside publish/resolve.

## 8. Opt-in startup auto-publish ✅

**Status**: **Implemented** in [PR #624](https://github.com/nfh-trust-labs/opencred/pull/624). Default is OFF.

**Original framing** (decision needed): make auto-publish default? Resolved as **opt-in only**. Default explicit-publish flow is preserved.

**Landed**:
- New `OPENCRED_AUTO_PUBLISH_KEY=true` env var (default false) that publishes the issuer DID to DeDi at startup. Works for both did:key and did:web.
- Cross-field validation: setting the flag without `OPENCRED_DEDI_BASE_URL` throws at startup (fails closed — without this, the flag silently no-ops, which was the exact failure mode it was created to prevent).
- Architecture: `apps/server/src/auto-publish.ts` carries `runAutoPublishIfEnabled(config, dediClient, signer, logger)` returning a discriminated `AutoPublishResult` (disabled, no-signer, no-jwk, published, already-published, publish-failed). Idempotent: treats `DeDiRecordExistsError` as success.
- Server startup never blocks on DeDi failure (warn-logged, continues).
- `/v1/health` payload extended with `didAutoPublished: boolean` so operators can verify at a glance.
- **Side-effect fix**: the longstanding `OPENCRED_DEDI_HOST_DID_DOC=true` no-op is now wired up. That flag has been in the config since v1.3 but never actually published anything at startup; it now does (for did:web).

**Follow-up parked**: KMS-backed signer auto-publish is not in scope — today `signer.publicKeyJwk` is only exposed by the software-signer path. Hardware-token / KMS public-key extraction is its own future PR.

## 9. did:web JWT `kid` correctness ✅

**Status**: **Implemented** in [PR #634](https://github.com/nfh-trust-labs/opencred/pull/634), released in v1.6.1. Closes [issue #632](https://github.com/nfh-trust-labs/opencred/issues/632).

**Gap (at the time)**: when `OPENCRED_ISSUER_DID_METHOD=web` was set alongside `OPENCRED_ISSUER_DOMAIN=<domain>`, the signing path still used the key-derived `did:key:…` verification-method ID for the loaded signer. JWTs were emitted with `kid: did:key:…#…` headers, but the published DID Document (whether self-hosted at `.well-known/did.json` or in DeDi) only contained the `did:web:<domain>#key-0` verification method. Verifiers walked `verificationMethod[]` by `kid` (per `packages/verification/src/vc-jwt.ts:179-213`) and found no match → every did:web-issued credential failed verification with `UNRESOLVABLE`.

**Landed**: when `method=web` + `OPENCRED_ISSUER_DOMAIN` are set, the loaded signer's `id` is now overridden to `did:web:<domain>#key-0`. JWT `kid` headers match the published DID Document. did:web verification end-to-end works for the first time.

**Doc surface**: documented as current behaviour in `docs/bootcamp/local-docker.md` §7d.i (Path A / Path B walkthrough) and `docs/concepts/dids.md` (did:web publishing section).

---

## Quick reference — which issues are blocked on which fix

| Fix | Unblocks |
|---|---|
| §1 publish v1.4.2 image | §7c (revoke) + §7d (publish/resolve) actually working from `:latest` |
| §2 Postman post-script ✅ | Click-through Issue → Revoke demo |
| §3 Postman publish/resolve ✅ | Click-through DID publish demo |
| §4 doc callout ✅ | Stops users assuming startup auto-publishes |
| §5 doc 409 troubleshooting ✅ | Reduces support pings |
| §6 DEDI_RECORD_EXISTS ✅ | Self-describing 409s |
| §7 did:web rotation ✅ | Production did:web operators can rotate keys in-place via `POST /v1/keys/rotate` (kid continuity preserved for old credentials) |
| §8 auto-publish opt-in ✅ | First-boot ergonomics for operators who opt in |
| §9 did:web JWT kid correctness ✅ | did:web-issued JWTs now carry a `kid` matching the published DID Document — verifiers stop returning `UNRESOLVABLE` |
