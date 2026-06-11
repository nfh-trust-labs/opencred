# Plan: Full credential matrix, issuable & verifiable, with DeDi key management — Desktop + Docker

**Status**: Draft (2026-06-10)
**Goal**: Every *valid* permutation of {proof format × signing algorithm × key source × DID method / issuer type × export format} can be **issued** and **verified**, with the complete DeDi key lifecycle (publish → rotate → revoke, plus per-credential revocation) working and provable, on **both** the Desktop Client and the Docker image.

Derived from the 2026-06-10 production-readiness audit. Issues already fixed on `feat/dedi-per-key-registry` (envelope verification, SDK structured failures, best-effort did.json, 429 retry, etc.) are out of scope here; this plan covers the **remaining** identified issues plus the matrix-proof work.

---

## 1. The target matrix (acceptance criteria)

### Dimensions

| Dimension | Values |
|---|---|
| Proof format | `vc-jwt`, `data-integrity`, `sd-jwt-vc` |
| Signing algorithm | P-256, P-384, Ed25519, RSA-2048/3072/4096 |
| Key source (Desktop) | software file (PEM/PFX/JWK), macOS Keychain, Windows CNG, PKCS#11 token |
| Key source (Docker) | software file, PKCS#11, AWS KMS, Azure Key Vault, GCP Cloud KMS |
| Issuer type / DID | `did:key`, self-published `did:web`, DSC-backed (`x5c` chain → CSCA anchor) |
| Export format | JSON envelope, compact token, PixelPass QR, PDF, json-compact |
| Verifier | verify-sdk (offline), verify-sdk (DeDi-configured), server `/v1/credentials/verify`, desktop Verify tab |
| Key lifecycle state | active, rotated, key-revoked, credential-revoked, DeDi-hosted multi-key did.json |

### Exclusions — invalid by design (documented, not fixed)

| Combination | Why |
|---|---|
| RSA × `data-integrity` | Rejected at issuance by design; `ecdsa-rdfc-2019` / `eddsa` suites only. RSA issuers use `vc-jwt` (PS256) or `sd-jwt-vc`. |
| `did:key` in-place rotation | A new key derives a new `did:key` by definition. The matrix instead tests the **regenerate** flow + old-key revocation. |
| OS cert store on Docker / Cloud HSM on Desktop | Platform-inapplicable (existing key-source matrix). |
| Local/loopback DeDi endpoint | SSRF guard refuses private IPs **by design**; E2E uses a real staging namespace (§3.2). |

### Definition of done for the goal

A single matrix report (CI artifact) showing, for every valid cell: issue ✅, verify ✅ on all four verifiers, and the five lifecycle states behaving exactly as specified — on both platforms.

---

## 2. Phase A — Close functional blockers

These block matrix cells outright; nothing in Phase B can prove cells these gate.

### A1. Cloud HSM signers must surface `publicKeyJwk` (#635) — **the biggest blocker**

`/v1/keys/publish` and `/v1/keys/rotate` return 400 for KMS-backed signers because `signer.metadata.publicKeyJwk` is unset — so **no DeDi key management at all for Cloud HSM issuers**, which the goal requires on Docker.

- The AWS (`GetPublicKeyCommand`), GCP (`getPublicKey`), and Azure signers already fetch the public key at construction (for fingerprint/DID derivation). Convert the SPKI/DER to JWK (`createPublicKey(...).export({format:"jwk"})`) and set it on `SignerMetadata.publicKeyJwk`.
- Remove the KMS guard clauses in `apps/server/src/routes/keys.ts` (publish + rotate) once metadata is populated; update the two VALIDATION_ERROR messages and `docs/docker/deployment.md`/api-reference accordingly.
- Files: `apps/server/src/signing/cloud-hsm/{aws-kms,azure-kv,gcp-kms}-signer.ts`, `routes/keys.ts`, tests in `apps/server/src/__tests__/`.

### A2. Desktop hardware-key parity check

Confirm PKCS#11 and OS-cert-store signers populate `loadedPublicKeyJwks` (or `signer.metadata.publicKeyJwk`) so `handleDeDiPublishKey` works for hardware-backed keys, not just software keys. Add an integration test per provider (mock native addon). Files: `apps/desktop/src/main/ipc-handlers.ts`, `packages/signing`.

### A3. Key-status write race mitigation (deferred item from decisions doc)

Read-modify-write in `dedi-client` `setKeyStatus` can lose updates across concurrent writers.
- Client-side now: per-verification-method in-process mutex in the adapter (serialises desktop UI double-clicks and server concurrent requests on one instance).
- Protocol fix: adopt DeDi record `version` as a compare-and-swap token on `update-record` if/when the API honours it — **raise with the DeDi team** (the user operates DeDi; this is actionable).
- Document residual multi-instance risk in `docs/concepts/`.

### A4. Algorithm coverage consistency audit (issuance ↔ verification)

Every algorithm the issuers can sign with must be in the verifiers' allowlists with a test:
- Missing today (audit findings): **RSA (PS256) + x5c DSC chain** regression test; P-384 DSC; Ed25519 `data-integrity` end-to-end through verify-sdk.
- Verify `ALLOWED_ALGORITHMS` in `vc-jwt.ts` / `jws-proof.ts` / `sd-jwt-vc.ts` cover ES256/ES384/EdDSA/PS256 consistently; add what's missing.

### A5. Small known gaps (each ≤ half-day)

| Item | Where |
|---|---|
| Revocation **reason** plumbed through desktop revoke UI (client+server already accept it) | `apps/desktop` renderer + IPC |
| `DeDiConfigSetResponse.error` field when `ensureRegistries` fails (UI can't distinguish today) | `ipc-handlers.ts`, renderer |
| Validate did.json document shape before `publishDidDocument` (desktop fallback path) | `ipc-handlers.ts` |
| Honour `Retry-After` on 429 (extend `DeDiClientError` with response headers; use in `withRetry`) | `packages/shared/errors.ts`, `dedi-client/retry.ts` |

---

## 3. Phase B — The matrix E2E harness (the proof)

### B1. Harness architecture

One parameterised runner, two execution backends:

- **Docker backend**: drives the built image over HTTP (the pattern validated live on 2026-06-10: run container with key mounted → `/v1/credentials/issue` → verify via SDK/`/verify` → `/v1/keys/*` lifecycle). Key sources: software key per algorithm; Cloud HSM cells run against real KMS test keys when env credentials are present, else skipped-with-reason.
- **Desktop backend**: drives `ipc-handlers` in-process (the existing `ipc-handlers-integration.test.ts` harness) — covers the desktop code path without GUI automation. A separate packaged-app boot smoke covers the GUI shell (C5).

Location: top-level `e2e/` workspace package (`@opencred/e2e-matrix`), excluded from the PR-gate test run.

### B2. DeDi for E2E — real staging namespace, SSRF intact

- No localhost bypass (SSRF guard is a security invariant). Use a dedicated staging namespace on a real DeDi instance — config via `OPENCRED_E2E_DEDI_BASE_URL` / `_NAMESPACE` / `_API_KEY` env.
- Each run uses a fresh run-scoped registry-record prefix (timestamped) so runs don't collide; a teardown step soft-deletes run records.
- Cells requiring DeDi auto-skip (with explicit "skipped: no DeDi staging configured" in the report) when env is absent — offline cells still prove out everywhere.

### B3. Lifecycle scenario template (run per valid cell)

1. **Publish** active key → DeDi record `active`; hosted did.json contains the key.
2. **Issue** credentials A, B → all four verifiers: VALID (revocation row present and passing).
3. **Rotate** → new key `active`, old `rotated`, did.json carries both; A/B still VALID with rotated attribution; new credential C VALID.
4. **Revoke credential** B → B REVOKED everywhere; A, C VALID.
5. **Revoke old key** → A REVOKED (key compromise semantics); C VALID; did.json drops the revoked key.
6. **Outage behaviour**: with DeDi unreachable → revocation check fails closed (UNRESOLVABLE), key-status degrades to "not checked"; with DeDi unconfigured → non-failing "NOT checked" row.

### B4. Export-format round-trips (per cell)

JSON envelope → verify; compact token → verify; PixelPass QR encode→decode→verify; PDF package→`verify.pdf()`; tampered variant of each → INVALID with the right check row (`envelope-consistency` for envelopes).

### B5. Edge-case battery (shared across cells)

Expired / not-yet-valid / oversized (>1 MiB) / null-byte DIDs / percent-encoded `did:web` port / dual revocation (credentialStatus + BitstringStatusList) / unknown JSON-LD context (must fail closed via bundled loader).

### B6. CI wiring

Nightly `e2e-matrix.yml` workflow (Docker backend always; DeDi cells when secrets configured; Cloud HSM cells when cloud creds configured). Produces the matrix report artifact (§1 DoD). PR gate unchanged.

---

## 4. Phase C — Remaining hardening & parity

| Item | Notes |
|---|---|
| C1. Health endpoint optional `dediHealthy` reachability probe | non-blocking field; informs alerting |
| C2. DeDi pagination metadata on `queryRecords`/`search` | or document "not paginated" explicitly |
| C3. Batch `interrupted` status surfaced distinctly from `failed` | operator can decide to re-run |
| C4. Bundled-schema auto-publish to DeDi (#109) | startup behaviour behind `OPENCRED_DEDI_PUBLISH_BUNDLED` |
| C5. Packaged desktop (electron-builder) boot smoke in CI | proves the **production renderer** path (`loadFile`), which `electron .` dev launches don't |
| C6. verify-sdk npm publish pipeline | LICENSE now exists; add release job to `opencred-releases` sync + bundle-size note in README |

---

## 5. Phase D — Documentation & project hygiene

- D1. Publish the **support matrix table** (§1, including exclusions and why) in `docs/` — it is the user-facing contract.
- D2. Key-source × lifecycle capability matrix (Desktop vs Docker) — updated after A1/A2 unlock KMS/hardware lifecycle.
- D3. Per CLAUDE.md protocol: fold this plan into `implementation-plan.md`, then create GitHub issues (one per A/B/C item, phase-labelled), feature branches off `new-opencred-dev`, one PR per issue.

---

## 6. Sequencing & dependencies

```
A1 (KMS JWK) ──┐
A2 (HW parity) ─┤
A4 (algo audit) ┼──► B1–B6 (matrix harness proves everything)
A3, A5 (indep.) ┘          │
C1–C6 (parallel, independent)
D1–D2 after B report exists; D3 first (issues drive the work)
```

Rough effort: A ≈ 4–6 dev-days (A1 is ~2), B ≈ 6–8 dev-days (harness + report), C ≈ 3–4, D ≈ 1–2.

**Recommended order**: D3 (file issues) → A1 → A4 → A2 → B harness skeleton with software-key cells → A3/A5 in parallel → full B matrix → C → D1/D2.
