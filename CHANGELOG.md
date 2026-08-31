# Changelog

All notable changes to OpenCred are documented here. Format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [1.11.0](https://github.com/nfh-trust-labs/opencred/compare/v1.10.0...v1.11.0) (2026-08-31)


### Features

* add jws-2020 (JsonWebSignature2020) proof format ([#752](https://github.com/nfh-trust-labs/opencred/issues/752)) ([52693a9](https://github.com/nfh-trust-labs/opencred/commit/52693a9917f2997ae11c50f2404fdcd6c3ebb70f))
* **vc-core,schema-engine:** bundle hosted IES ElectricityCredential v1.2 context ([#755](https://github.com/nfh-trust-labs/opencred/issues/755)) ([2a33125](https://github.com/nfh-trust-labs/opencred/commit/2a33125eac38aadb14e292e79ceb3f893a6dcf38))


### Bug Fixes

* **ci:** grant packages:write so the chained docker.yml can start ([#754](https://github.com/nfh-trust-labs/opencred/issues/754)) ([5bb0c38](https://github.com/nfh-trust-labs/opencred/commit/5bb0c380070e95a8d38cc1e3dd1b0ffcbab860f3))
* **ci:** resolve the release tag correctly when chained from release-please ([#748](https://github.com/nfh-trust-labs/opencred/issues/748)) ([9fee54c](https://github.com/nfh-trust-labs/opencred/commit/9fee54c737c809d7429499b2dc97ea8949f04855))

## [1.10.0](https://github.com/nfh-trust-labs/opencred/compare/v1.9.1...v1.10.0) (2026-08-03)


### Features

* **dedi-client,shared:** serialise per-key status writes + honour Retry-After on 429 ([#687](https://github.com/nfh-trust-labs/opencred/issues/687)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **desktop:** app icon + Muesli-style DMG so the OpenCred logo ships ([#647](https://github.com/nfh-trust-labs/opencred/issues/647)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **desktop:** bundle brand fonts + macOS hiddenInset title bar ([#648](https://github.com/nfh-trust-labs/opencred/issues/648)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **desktop:** sequential #key-N did:web rotation (closes [#662](https://github.com/nfh-trust-labs/opencred/issues/662)) ([#665](https://github.com/nfh-trust-labs/opencred/issues/665)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **did,server:** stateless sequential #key-N did:web rotation (closes [#653](https://github.com/nfh-trust-labs/opencred/issues/653)) ([#663](https://github.com/nfh-trust-labs/opencred/issues/663)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **e2e:** credential-matrix harness — every valid cell issued + verified against the Docker image ([#685](https://github.com/nfh-trust-labs/opencred/issues/685)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* embed did.json snapshot on each key record, drop did-documents registry ([#671](https://github.com/nfh-trust-labs/opencred/issues/671)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **packaging:** drop OPENCRED1: prefix from QR payloads for MOSIP/Inji interop ([#645](https://github.com/nfh-trust-labs/opencred/issues/645)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690)), closes [#644](https://github.com/nfh-trust-labs/opencred/issues/644)
* relicense under MIT and prepare the repo for open-sourcing ([#735](https://github.com/nfh-trust-labs/opencred/issues/735)) ([ddb0493](https://github.com/nfh-trust-labs/opencred/commit/ddb04931c93830a2de4c4091088bc9e8da928e8d))
* **schema-engine:** embed IES ElectricityCredential v1.2 + MeterDataCredential v0.6 ([#698](https://github.com/nfh-trust-labs/opencred/issues/698)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690)), closes [#696](https://github.com/nfh-trust-labs/opencred/issues/696)
* **server,signing:** Cloud HSM signers surface publicKeyJwk — unblocks DeDi key lifecycle for KMS ([#683](https://github.com/nfh-trust-labs/opencred/issues/683)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690)), closes [#675](https://github.com/nfh-trust-labs/opencred/issues/675)
* **server:** GET /v1/keys/did-document for Path A self-hosters ([#643](https://github.com/nfh-trust-labs/opencred/issues/643)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **signing:** PKCS[#11](https://github.com/nfh-trust-labs/opencred/issues/11) and OS-cert signers surface publicKeyJwk ([#688](https://github.com/nfh-trust-labs/opencred/issues/688)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690)), closes [#676](https://github.com/nfh-trust-labs/opencred/issues/676)
* **verification,desktop:** surface revocation reason in verifier UI ([#658](https://github.com/nfh-trust-labs/opencred/issues/658) Phase A) ([#667](https://github.com/nfh-trust-labs/opencred/issues/667)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))


### Bug Fixes

* **ci:** bound CI job runtime + stop 100k-row batch test starving the event loop ([#690](https://github.com/nfh-trust-labs/opencred/issues/690)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690)), closes [#693](https://github.com/nfh-trust-labs/opencred/issues/693)
* **dedi-client,server:** repair did:web→DeDi resolution + rotation doc-landing (found via live DeDi) ([#692](https://github.com/nfh-trust-labs/opencred/issues/692)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **dedi-client:** document + harden setKeyStatus optimistic concurrency ([#666](https://github.com/nfh-trust-labs/opencred/issues/666)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **desktop:** rebuild native addons per target arch + fail builds on .node arch mismatch ([#699](https://github.com/nfh-trust-labs/opencred/issues/699)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690)), closes [#641](https://github.com/nfh-trust-labs/opencred/issues/641) [#642](https://github.com/nfh-trust-labs/opencred/issues/642)
* **desktop:** restore package.json dependencies stripped by accident in [#703](https://github.com/nfh-trust-labs/opencred/issues/703) ([#704](https://github.com/nfh-trust-labs/opencred/issues/704)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **desktop:** route did:web rotate IPC through rotateDIDWeb ([#631](https://github.com/nfh-trust-labs/opencred/issues/631)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* production-readiness hardening — vc-jwt envelope verification, SDK totality, RSA boot, retry/shutdown fixes ([#684](https://github.com/nfh-trust-labs/opencred/issues/684)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **security:** close DNS-rebinding TOCTOU in all SSRF-checked fetches ([#742](https://github.com/nfh-trust-labs/opencred/issues/742)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **security:** pin resolved IPs for webhook delivery and DeDi API fetches ([#746](https://github.com/nfh-trust-labs/opencred/issues/746)) ([55e0b0f](https://github.com/nfh-trust-labs/opencred/commit/55e0b0f7ae5b5963e57cf621f250b52f62523c53))
* **server:** rename unused `key` param in auto-publish test mocks ([#655](https://github.com/nfh-trust-labs/opencred/issues/655)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **signing,server:** override signer VM ID to did:web when method=web ([#632](https://github.com/nfh-trust-labs/opencred/issues/632)) ([#634](https://github.com/nfh-trust-labs/opencred/issues/634)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))
* **templates:** escape and validate all SVG renderer interpolations (security HIGH-3) ([#743](https://github.com/nfh-trust-labs/opencred/issues/743)) ([04ab49e](https://github.com/nfh-trust-labs/opencred/commit/04ab49ee1a95a7c848dc751f1f988ad3f7b9dd76))
* **verification:** algorithm coverage — PS256 vc-jwt allowlist + RSA/P-384/Ed25519 round-trip tests ([#686](https://github.com/nfh-trust-labs/opencred/issues/686)) ([b63a248](https://github.com/nfh-trust-labs/opencred/commit/b63a24863da94a1abf54a6587340e169b37c6690))

## [1.9.1](https://github.com/nfh-trust-labs/opencred/compare/v1.9.0...v1.9.1) (2026-07-03)

### Bug Fixes

- **packaging:** render nested `credentialSubject` objects and arrays in the PDF certificate. The "Credential Details" section recursed only one level and stringified anything deeper, so fields two or more levels deep (e.g. a utility credential's `customerProfile.idRef` or `customerDetails.installationAddress.country`) rendered as `[object Object]`. It now flattens the whole subject tree into indented rows and paginates instead of overflowing the page. Shared generator, so both the Desktop app and the Docker server are fixed ([#725](https://github.com/nfh-trust-labs/opencred/pull/725)) ([306c826](https://github.com/nfh-trust-labs/opencred/commit/306c826b))

### Build System

- **schema-engine:** re-pin `opencred-vc-schemas` to pick up the additive OpenBadges v3 context update (`endorsementJwt`, `jti`) that upstream changed in place — it had been hard-failing the pinned-hash check and blocking every build. Keep `vc-core`'s bundled-context commit SHA in sync so data-integrity credentials for built-in schemas resolve their context, guarded by a new sync test ([#726](https://github.com/nfh-trust-labs/opencred/pull/726)) ([37186f1](https://github.com/nfh-trust-labs/opencred/commit/37186f12))

## [1.9.0](https://github.com/nfh-trust-labs/opencred/compare/v1.8.0...v1.9.0) (2026-06-23)

### Features

- **revocation:** asynchronous, self-healing credential revocation. DeDi anchors revocation records to CORD, where both write steps (`save-record-as-draft`, `publish-records`) can exceed the client's hard 10s per-request ceiling — so a synchronous `POST /v1/credentials/revoke` could 504 under load ([opencred-releases#11](https://github.com/nfh-trust-labs/opencred-releases/issues/11)). The endpoint now attempts the publish synchronously (`200`, or `409` if already revoked) and, on a CORD timeout, accepts the revoke (`202` `{"status":"pending"}`) and completes the idempotent, self-healing publish in the background until the record is LIVE; clients confirm via `POST /v1/credentials/revocation-status`. The dedi-client publish is self-healing (on a duplicate, it looks the record up and advances a stranded draft to LIVE). Backward-compatible: fast revokes still return `200`, already-revoked still `409`. Validated live against api.dedi.global ([#718](https://github.com/nfh-trust-labs/opencred/issues/718)) ([0d157c5](https://github.com/nfh-trust-labs/opencred/commit/0d157c5b))

## [1.8.0](https://github.com/nfh-trust-labs/opencred/compare/v1.7.1...v1.8.0) (2026-06-15)

### Features

- **server:** make the DeDi resolver's retry count configurable via `OPENCRED_DEDI_MAX_RETRIES` (0–5, default 2; wired into both the HTTP API and CLI verify paths). The per-request DeDi timeout stays hard-capped at 10s (security invariant) — raise retries, not the timeout, to ride out a brief DeDi outage ([#711](https://github.com/nfh-trust-labs/opencred/issues/711)) ([72bfaeb](https://github.com/nfh-trust-labs/opencred/commit/72bfaeb6))

### Bug Fixes

- **did:** preserve path-separator colons in `encodeDidWeb` so did:web issuers hosting their `did.json` at a sub-path verify correctly. Only a numeric host:port colon is percent-encoded now; path-segment colons are kept, restoring the inverse relationship with `didWebToUrl`. Fixes `UNRESOLVABLE` for `OPENCRED_ISSUER_DOMAIN` values like `host:path:segment` ([#709](https://github.com/nfh-trust-labs/opencred/issues/709)) ([af3451e](https://github.com/nfh-trust-labs/opencred/commit/af3451e7))

### Documentation

- document `OPENCRED_DEDI_MAX_RETRIES` and did:web sub-path support across the deployment guides and the `@opencred/verify` SDK README ([#713](https://github.com/nfh-trust-labs/opencred/issues/713)) ([12b1469](https://github.com/nfh-trust-labs/opencred/commit/12b14694))

## [1.7.1](https://github.com/nfh-trust-labs/opencred/compare/v1.7.0...v1.7.1) (2026-06-13)

### Bug Fixes

- **desktop:** restore package.json dependencies stripped by accident in [#703](https://github.com/nfh-trust-labs/opencred/issues/703) ([#704](https://github.com/nfh-trust-labs/opencred/issues/704)) ([d8c5c15](https://github.com/nfh-trust-labs/opencred/commit/d8c5c158)) — branch-only breakage, no released artifact was affected

### Chores

- **schema-engine:** point IES schema provenance at canonical published URLs (schema.beckn.io / india-energy-stack.github.io) — surfaced via `GET /v1/schemas` `source.upstreamUrl` ([#705](https://github.com/nfh-trust-labs/opencred/issues/705)) ([9c92c4d](https://github.com/nfh-trust-labs/opencred/commit/9c92c4d8))

### Documentation

- schema-library docs reflect the 36 bundled schemas incl. IES; `electricity/v1` category corrected to `utility`; per-arch native rebuild documented ([#701](https://github.com/nfh-trust-labs/opencred/issues/701), [#702](https://github.com/nfh-trust-labs/opencred/issues/702), [#703](https://github.com/nfh-trust-labs/opencred/issues/703))

## [1.7.0](https://github.com/nfh-trust-labs/opencred/compare/v1.6.1...v1.7.0) (2026-06-12)


### Features

* DeDi per-key registry (active/rotated/revoked) — verification + docker + desktop ([#652](https://github.com/nfh-trust-labs/opencred/issues/652)) ([255a002](https://github.com/nfh-trust-labs/opencred/commit/255a00283c341eafd4eafbabe20359608ed9a0fc))
* **schema-engine:** embed IES ElectricityCredential v1.2 + MeterDataCredential v0.6 ([#698](https://github.com/nfh-trust-labs/opencred/issues/698)) ([c638991](https://github.com/nfh-trust-labs/opencred/commit/c638991b)), closes [#696](https://github.com/nfh-trust-labs/opencred/issues/696)
* **dedi-client,shared:** serialise per-key status writes + honour Retry-After on 429 ([#687](https://github.com/nfh-trust-labs/opencred/issues/687)) ([677952c](https://github.com/nfh-trust-labs/opencred/commit/677952cd4ffda27983dc2ca2adb98f7570a374c9))
* **desktop:** app icon + Muesli-style DMG so the OpenCred logo ships ([#647](https://github.com/nfh-trust-labs/opencred/issues/647)) ([d0cd3d4](https://github.com/nfh-trust-labs/opencred/commit/d0cd3d4a7a3e44275f99e077b085e4081c4a8e1a))
* **desktop:** bundle brand fonts + macOS hiddenInset title bar ([#648](https://github.com/nfh-trust-labs/opencred/issues/648)) ([c57039d](https://github.com/nfh-trust-labs/opencred/commit/c57039d930c8c3db2b3c50fb24392ca214bcfaa2))
* **desktop:** sequential #key-N did:web rotation (closes [#662](https://github.com/nfh-trust-labs/opencred/issues/662)) ([#665](https://github.com/nfh-trust-labs/opencred/issues/665)) ([c08d1e6](https://github.com/nfh-trust-labs/opencred/commit/c08d1e6dcc2ad9e5e0b2fae261203168c5a5d2ef))
* **did,server:** stateless sequential #key-N did:web rotation (closes [#653](https://github.com/nfh-trust-labs/opencred/issues/653)) ([#663](https://github.com/nfh-trust-labs/opencred/issues/663)) ([041f1e2](https://github.com/nfh-trust-labs/opencred/commit/041f1e2316c1eaa0f8daa25785d7a2854e03c786))
* **e2e:** credential-matrix harness — every valid cell issued + verified against the Docker image ([#685](https://github.com/nfh-trust-labs/opencred/issues/685)) ([4c9aa61](https://github.com/nfh-trust-labs/opencred/commit/4c9aa6195660ed48e8e81699cb53cb50b4b0b637))
* embed did.json snapshot on each key record, drop did-documents registry ([#671](https://github.com/nfh-trust-labs/opencred/issues/671)) ([541e07e](https://github.com/nfh-trust-labs/opencred/commit/541e07eb09d234184fb3f741875fa04e47f76142))
* **packaging:** drop OPENCRED1: prefix from QR payloads for MOSIP/Inji interop ([#645](https://github.com/nfh-trust-labs/opencred/issues/645)) ([7d3624e](https://github.com/nfh-trust-labs/opencred/commit/7d3624e12d5865af2fa2505407aadf43c125823a)), closes [#644](https://github.com/nfh-trust-labs/opencred/issues/644)
* **packaging:** shared @opencred/packaging + redesigned PDF certificate ([#650](https://github.com/nfh-trust-labs/opencred/issues/650)) ([78a68cb](https://github.com/nfh-trust-labs/opencred/commit/78a68cbe14c74f9cc6724d1d61eb4e4604d09012))
* **server,signing:** Cloud HSM signers surface publicKeyJwk — unblocks DeDi key lifecycle for KMS ([#683](https://github.com/nfh-trust-labs/opencred/issues/683)) ([b47505e](https://github.com/nfh-trust-labs/opencred/commit/b47505e9281d32be54b2fe4993a735b79cdfdc4b)), closes [#675](https://github.com/nfh-trust-labs/opencred/issues/675)
* **server:** GET /v1/keys/did-document for Path A self-hosters ([#643](https://github.com/nfh-trust-labs/opencred/issues/643)) ([d39b356](https://github.com/nfh-trust-labs/opencred/commit/d39b3565941f4b61eca2c254e9abd6966223bebf))
* **signing:** PKCS[#11](https://github.com/nfh-trust-labs/opencred/issues/11) and OS-cert signers surface publicKeyJwk ([#688](https://github.com/nfh-trust-labs/opencred/issues/688)) ([826257e](https://github.com/nfh-trust-labs/opencred/commit/826257e83a663b976905537b3e6edfcc93c2fad0)), closes [#676](https://github.com/nfh-trust-labs/opencred/issues/676)
* **verification,desktop:** surface revocation reason in verifier UI ([#658](https://github.com/nfh-trust-labs/opencred/issues/658) Phase A) ([#667](https://github.com/nfh-trust-labs/opencred/issues/667)) ([ce642b6](https://github.com/nfh-trust-labs/opencred/commit/ce642b6ca73f6f0113270559013b612cc8a3619c))


### Bug Fixes

* **ci:** bound CI job runtime + stop 100k-row batch test starving the event loop ([#690](https://github.com/nfh-trust-labs/opencred/issues/690)) ([f834388](https://github.com/nfh-trust-labs/opencred/commit/f8343881))
* **dedi-client,server:** repair did:web→DeDi resolution + rotation doc-landing (found via live DeDi) ([#692](https://github.com/nfh-trust-labs/opencred/issues/692)) ([07fd953](https://github.com/nfh-trust-labs/opencred/commit/07fd953d9456170a9f1f5d962c11414100536f7a))
* **desktop:** rebuild native addons per target arch + fail builds on .node arch mismatch ([#699](https://github.com/nfh-trust-labs/opencred/issues/699)) ([5feb4fb](https://github.com/nfh-trust-labs/opencred/commit/5feb4fb1)), closes [#641](https://github.com/nfh-trust-labs/opencred/issues/641) [#642](https://github.com/nfh-trust-labs/opencred/issues/642)
* **dedi-client:** document + harden setKeyStatus optimistic concurrency ([#666](https://github.com/nfh-trust-labs/opencred/issues/666)) ([7bee27e](https://github.com/nfh-trust-labs/opencred/commit/7bee27e264b1e1d69f5d9d55e0657da71fe5fb44))
* **packaging,server:** PDF Digital Signature section renders JWT proof metadata ([#693](https://github.com/nfh-trust-labs/opencred/issues/693)) ([#694](https://github.com/nfh-trust-labs/opencred/issues/694)) ([7841286](https://github.com/nfh-trust-labs/opencred/commit/78412866054de001ffd12d685824f4ed45bc89bd))
* production-readiness hardening — vc-jwt envelope verification, SDK totality, RSA boot, retry/shutdown fixes ([#684](https://github.com/nfh-trust-labs/opencred/issues/684)) ([669aed6](https://github.com/nfh-trust-labs/opencred/commit/669aed6e314b05f820d8f1c729e54b93908dbe19))
* **server:** rename unused `key` param in auto-publish test mocks ([#655](https://github.com/nfh-trust-labs/opencred/issues/655)) ([346cbd4](https://github.com/nfh-trust-labs/opencred/commit/346cbd4fd05add8447c306b7f0c633914f500498))
* **verification:** algorithm coverage — PS256 vc-jwt allowlist + RSA/P-384/Ed25519 round-trip tests ([#686](https://github.com/nfh-trust-labs/opencred/issues/686)) ([932fe8c](https://github.com/nfh-trust-labs/opencred/commit/932fe8c8c4592a4bea367022de760e5acdb7db4e))


### Chores

* **schema-engine:** retry transient fetch failures at build time, fall back to prior embed offline ([#695](https://github.com/nfh-trust-labs/opencred/issues/695)) ([8c7e85a](https://github.com/nfh-trust-labs/opencred/commit/8c7e85af))

## [1.6.1](https://github.com/nfh-trust-labs/opencred/compare/v1.6.0...v1.6.1) (2026-05-26)


### Bug Fixes

* **signing,server:** override signer VM ID to did:web when method=web ([#632](https://github.com/nfh-trust-labs/opencred/issues/632)) ([#634](https://github.com/nfh-trust-labs/opencred/issues/634)) ([6becfbe](https://github.com/nfh-trust-labs/opencred/commit/6becfbe7b2b32d5ccfbc48d30a83d452b5e440cd))

## [1.6.0](https://github.com/nfh-trust-labs/opencred/compare/v1.5.0...v1.6.0) (2026-05-25)


### Features

* **dedi-client:** surface DeDi 409 as DEDI_RECORD_EXISTS with hint ([#620](https://github.com/nfh-trust-labs/opencred/issues/620)) ([b0203be](https://github.com/nfh-trust-labs/opencred/commit/b0203bed15bb0641b26b4dbf4103a5526fe64868))
* did:web multi-key rotation (POST /v1/keys/rotate) ([#628](https://github.com/nfh-trust-labs/opencred/issues/628)) ([73dcba8](https://github.com/nfh-trust-labs/opencred/commit/73dcba8174696736a611dcbb7fdbcec6d355b9b9))
* **server,bootcamp:** Postman click-through for Issue-&gt;Revoke + Key publish/resolve ([#621](https://github.com/nfh-trust-labs/opencred/issues/621)) ([da32b84](https://github.com/nfh-trust-labs/opencred/commit/da32b848fe2138ac9c8c6a274bec9d94bdeecb4e)), closes [#616](https://github.com/nfh-trust-labs/opencred/issues/616)
* **server:** startup auto-publish issuer DID + fix HOST_DID_DOC no-op ([#624](https://github.com/nfh-trust-labs/opencred/issues/624)) ([f863391](https://github.com/nfh-trust-labs/opencred/commit/f863391d14aa9811570e191e3d699ee8a4bb5d63))


### Bug Fixes

* **ci:** drop committed node_modules symlink ([#606](https://github.com/nfh-trust-labs/opencred/issues/606)) ([3acc64e](https://github.com/nfh-trust-labs/opencred/commit/3acc64e7d9b6a0529db789a0a2dc437268cd5552))
* **ci:** drop orphan opencred-website gitlink ([#603](https://github.com/nfh-trust-labs/opencred/issues/603)) ([810a0e4](https://github.com/nfh-trust-labs/opencred/commit/810a0e46ee17805a466daffbc3afb5daaa297cb5)), closes [#601](https://github.com/nfh-trust-labs/opencred/issues/601)
* **dedi-client:** chain publish-records + use lookup for revocation queries ([#612](https://github.com/nfh-trust-labs/opencred/issues/612)) ([34c830d](https://github.com/nfh-trust-labs/opencred/commit/34c830d3a0a3e70023f0958ac4c02d3781d2fc8a))
* **dedi-client:** use case-sensitive Revoke tag + inline schema for context ([#611](https://github.com/nfh-trust-labs/opencred/issues/611)) ([c73ee0d](https://github.com/nfh-trust-labs/opencred/commit/c73ee0d3c977323e7f301de9d1e450d438e01645))
* **desktop:** route did:web rotate IPC through rotateDIDWeb ([#631](https://github.com/nfh-trust-labs/opencred/issues/631)) ([1450e9d](https://github.com/nfh-trust-labs/opencred/commit/1450e9dbb9cadbdcec38761d4b64db6513f4c934))

## [1.5.0](https://github.com/nfh-trust-labs/opencred/compare/v1.4.1...v1.5.0) (2026-05-20)


### Features

* add did:key as a first-class issuer option alongside did:web ([44421de](https://github.com/nfh-trust-labs/opencred/commit/44421de54c11107bc7d7222c6c8ef3ec2a6efc7f))
* **batch-core,server:** add maxRecordBytes cap to streaming CSV parser ([#578](https://github.com/nfh-trust-labs/opencred/issues/578)) ([#592](https://github.com/nfh-trust-labs/opencred/issues/592)) ([acadacb](https://github.com/nfh-trust-labs/opencred/commit/acadacb94bf81ce4533257724da438726e356825))
* **dedi-client,verification,desktop:** simplify DID record + add keyStatus rotation flag ([#562](https://github.com/nfh-trust-labs/opencred/issues/562)) ([59fbb53](https://github.com/nfh-trust-labs/opencred/commit/59fbb530227f9545cf8ee7eff9151742cc481418))
* **dedi-client,verification,desktop:** surface DeDi CORD anchor proof block ([#565](https://github.com/nfh-trust-labs/opencred/issues/565)) ([6c19824](https://github.com/nfh-trust-labs/opencred/commit/6c19824a6e84ea0d9e238f85fcb839f728c48d74))
* **dedi-client:** migrate revocation registry to DeDi canonical revoke tag ([#561](https://github.com/nfh-trust-labs/opencred/issues/561)) ([41879df](https://github.com/nfh-trust-labs/opencred/commit/41879df0e372f556228af8bdec2f7d658e1d0566))
* **desktop:** add did:key option to Self-Published Keys wizard ([ad875be](https://github.com/nfh-trust-labs/opencred/commit/ad875be5c58cf00758151b706fceee0e75612e2c))
* **desktop:** capture optional reason when revoking a credential ([#564](https://github.com/nfh-trust-labs/opencred/issues/564)) ([7533e2c](https://github.com/nfh-trust-labs/opencred/commit/7533e2cd522d91e4c85d5d7c666c97f0d5decf3d))
* **did,server:** foundation for did:key as a first-class issuer option ([37d5275](https://github.com/nfh-trust-labs/opencred/commit/37d5275eaab3021029b10b69c5ca3311327a21f1))
* **schema-engine:** accept YAML files for locally-defined schemas ([#553](https://github.com/nfh-trust-labs/opencred/issues/553)) ([19e2efe](https://github.com/nfh-trust-labs/opencred/commit/19e2efee28cf1391b478c6384b25cb71cce20954)), closes [#552](https://github.com/nfh-trust-labs/opencred/issues/552)
* **schema-engine:** point electricity/v1 schema $id at canonical Beckn URL ([#570](https://github.com/nfh-trust-labs/opencred/issues/570)) ([a936c76](https://github.com/nfh-trust-labs/opencred/commit/a936c76729aa617b682ac4f3924dbc1f1f8dcb9c))
* **server,batch:** streaming CSV parser ([#446](https://github.com/nfh-trust-labs/opencred/issues/446)) ([#577](https://github.com/nfh-trust-labs/opencred/issues/577)) ([04560f3](https://github.com/nfh-trust-labs/opencred/commit/04560f33c3a8c597c20e11abbaa933af381d31fc))
* **server,crypto,signing:** cache DID doc + hoist proof-config canon ([#446](https://github.com/nfh-trust-labs/opencred/issues/446)) ([#572](https://github.com/nfh-trust-labs/opencred/issues/572)) ([204815e](https://github.com/nfh-trust-labs/opencred/commit/204815ef453aa2edf5a35bd077f9f32b4f6a2a18)), closes [#571](https://github.com/nfh-trust-labs/opencred/issues/571)
* **server,signing:** wire signer DID cache into issuance + verification ([#573](https://github.com/nfh-trust-labs/opencred/issues/573)) ([#593](https://github.com/nfh-trust-labs/opencred/issues/593)) ([5d324eb](https://github.com/nfh-trust-labs/opencred/commit/5d324eb4c8bc2915614270acb7a60a8d8e77ce67))
* **server:** BullMQ worker process + queue dispatch ([#446](https://github.com/nfh-trust-labs/opencred/issues/446) Tier 3 [#8](https://github.com/nfh-trust-labs/opencred/issues/8)) ([#594](https://github.com/nfh-trust-labs/opencred/issues/594)) ([ceb50fa](https://github.com/nfh-trust-labs/opencred/commit/ceb50fa62d14eb3b29ef050946d66d95b7aa56ab))
* **server:** cache headers + read-only mode for verify-split ([#446](https://github.com/nfh-trust-labs/opencred/issues/446)) ([#585](https://github.com/nfh-trust-labs/opencred/issues/585)) ([7aa1b12](https://github.com/nfh-trust-labs/opencred/commit/7aa1b12f99ce1358ee98608767e0ebdd71b9637d))
* **server:** consume request body directly into streaming CSV parser ([#580](https://github.com/nfh-trust-labs/opencred/issues/580)) ([#595](https://github.com/nfh-trust-labs/opencred/issues/595)) ([7597ca4](https://github.com/nfh-trust-labs/opencred/commit/7597ca439d7ae956fdf13e5622f83af16c720751))
* **server:** multi-replica coordination + horizontal-scale docs ([#446](https://github.com/nfh-trust-labs/opencred/issues/446)) ([#591](https://github.com/nfh-trust-labs/opencred/issues/591)) ([f3f6bbd](https://github.com/nfh-trust-labs/opencred/commit/f3f6bbd5793c26a05d180e18c1bf667df81ad03a))
* **server:** OTel critical-path spans for batch/signer/verify/DeDi ([#446](https://github.com/nfh-trust-labs/opencred/issues/446)) ([#587](https://github.com/nfh-trust-labs/opencred/issues/587)) ([3d10645](https://github.com/nfh-trust-labs/opencred/commit/3d1064525e519bad1dcbd0cc6cac2718f15217ba))
* **server:** stateless jobs store with Redis adapter ([#446](https://github.com/nfh-trust-labs/opencred/issues/446)) ([#575](https://github.com/nfh-trust-labs/opencred/issues/575)) ([c6a296c](https://github.com/nfh-trust-labs/opencred/commit/c6a296cd68154686bb404a8fde666bb746a1e809))
* **server:** tier-1 scale wins — batch worker pool + per-route rate limiter ([#569](https://github.com/nfh-trust-labs/opencred/issues/569)) ([0c9d56e](https://github.com/nfh-trust-labs/opencred/commit/0c9d56e618e8b0cff79d02dc31bb2f65a170e8c5))
* **verification,desktop,server:** surface issuer attribution + key supersession ([e89993a](https://github.com/nfh-trust-labs/opencred/commit/e89993afae7db8323cf3b3d72d762f8e0356140b))
* **verify-sdk:** add @opencred/verify v0.1.0 SDK package ([#542](https://github.com/nfh-trust-labs/opencred/issues/542)) ([1d8d809](https://github.com/nfh-trust-labs/opencred/commit/1d8d8097185138af9099acebc490771f2b0462ef))


### Bug Fixes

* **dedi-client:** correct response envelope parsing for real DeDi API ([#558](https://github.com/nfh-trust-labs/opencred/issues/558)) ([2b08073](https://github.com/nfh-trust-labs/opencred/commit/2b08073b899cf86b80c0036096fcbf6c4fc6301d)), closes [#556](https://github.com/nfh-trust-labs/opencred/issues/556)
* **dedi-client:** make markDIDRotated idempotent under concurrent writes ([#566](https://github.com/nfh-trust-labs/opencred/issues/566)) ([558c0d0](https://github.com/nfh-trust-labs/opencred/commit/558c0d0e1efdb5147880074eef1e5f15fb4a78c3))
* **dedi-client:** prevent duplicate namespace creation on retry ([#546](https://github.com/nfh-trust-labs/opencred/issues/546)) ([#550](https://github.com/nfh-trust-labs/opencred/issues/550)) ([e93ac75](https://github.com/nfh-trust-labs/opencred/commit/e93ac753a115095bde5ff3f9e2c6f393d94d4712))
* **desktop,ci:** bypass @electron/rebuild dep-tree walk that hangs on Windows ([#567](https://github.com/nfh-trust-labs/opencred/issues/567)) ([0b9edc0](https://github.com/nfh-trust-labs/opencred/commit/0b9edc0ff188c41071294fc1a591ef00a854b645))
* **desktop:** make buildDidKeyDocument produce a real did:key document ([0bc0e9d](https://github.com/nfh-trust-labs/opencred/commit/0bc0e9d501cfdbdce1ab0c5c0f5be68daf3c2287))
* **desktop:** publish DeDi attribution record under canonical issuer DID ([a1ad908](https://github.com/nfh-trust-labs/opencred/commit/a1ad908935e4791ecfd0671c4e3e78cd325b1a48))
* **desktop:** refuse to overwrite stale package.json.bak on build:dist ([#549](https://github.com/nfh-trust-labs/opencred/issues/549)) ([c7a62e6](https://github.com/nfh-trust-labs/opencred/commit/c7a62e6db96958f012191354ddc3276bb16222a2))
* **desktop:** restore package.json after build:dist completes ([#544](https://github.com/nfh-trust-labs/opencred/issues/544)) ([31e4072](https://github.com/nfh-trust-labs/opencred/commit/31e40728568367114968e512b19fcf96bd25302f))
* **desktop:** wire missing Back buttons across the onboarding flow ([#547](https://github.com/nfh-trust-labs/opencred/issues/547)) ([#551](https://github.com/nfh-trust-labs/opencred/issues/551)) ([aa1234a](https://github.com/nfh-trust-labs/opencred/commit/aa1234afb065e9404d964e27ebedd570cbdfd12f))
* **did,verification:** unblock CI on feat/did-key-option ([801fb13](https://github.com/nfh-trust-labs/opencred/commit/801fb13fdaf3b78f070e554d7a2f8ddf43f573fb))
* **server:** address PR 1 review findings — CLI fallback, DeDi-hosted boot probe, JSDoc ([f2918a5](https://github.com/nfh-trust-labs/opencred/commit/f2918a515e4b5c987cd3fb39471fac61758671d8))
* **server:** align POST resolve cache + multi-colon DID test + normalize prefixes ([#586](https://github.com/nfh-trust-labs/opencred/issues/586)) ([#589](https://github.com/nfh-trust-labs/opencred/issues/589)) ([5921a38](https://github.com/nfh-trust-labs/opencred/commit/5921a38e414fa4730cd5a1497f1c0cf7dc377442))
* **verification:** use DeDiClientError.statusCode to detect 404, not message substring ([05c9d7f](https://github.com/nfh-trust-labs/opencred/commit/05c9d7fca320995a8c9f06479e46648155dc8c31))

## [1.4.1](https://github.com/nfh-trust-labs/opencred/compare/v1.4.0...v1.4.1) (2026-05-15)


### Bug Fixes

* **deps:** bump protobufjs override to ^7.5.6 for CVE-2026-44289..44293 ([#539](https://github.com/nfh-trust-labs/opencred/issues/539)) ([9a97d7e](https://github.com/nfh-trust-labs/opencred/commit/9a97d7e42633a76d01fc167acba00c7007472b40))

## [1.4.0](https://github.com/nfh-trust-labs/opencred/compare/v1.3.0...v1.4.0) (2026-05-14)


### Features

* **verification:** DeDi as a did:web discovery layer ([#530](https://github.com/nfh-trust-labs/opencred/issues/530)) ([7f6ce2f](https://github.com/nfh-trust-labs/opencred/commit/7f6ce2fc3aa0503ff676ec35f5dd25b79d71ca91))


### Bug Fixes

* **ci:** declare tag input on desktop-release workflow_call ([#535](https://github.com/nfh-trust-labs/opencred/issues/535)) ([795ff19](https://github.com/nfh-trust-labs/opencred/commit/795ff1971aab06d608de49bc07d86ba942deb840))
* **server:** derive canonical credentialStatus.id from configured DeDi namespace ([#528](https://github.com/nfh-trust-labs/opencred/issues/528)) ([#534](https://github.com/nfh-trust-labs/opencred/issues/534)) ([366c67a](https://github.com/nfh-trust-labs/opencred/commit/366c67a53d4a5256841427acd51bc4518f2071f9))


### Reverts

* **ci:** roll back release-please chaining into desktop-release/docker ([#537](https://github.com/nfh-trust-labs/opencred/issues/537)) ([a4995cc](https://github.com/nfh-trust-labs/opencred/commit/a4995cce40b27f88e3ef2bc9dd3b5688bc8fee47))

## [1.3.0](https://github.com/nfh-trust-labs/opencred/compare/v1.2.0...v1.3.0) (2026-05-09)


### Features

* **verification:** accept PDF as a verification input ([#526](https://github.com/nfh-trust-labs/opencred/issues/526)) ([2a90150](https://github.com/nfh-trust-labs/opencred/commit/2a90150cffdd26d8cefea561c2ad4c44b92d3663))


### Bug Fixes

* **ci:** smoke-test bind-mount UID mismatch (chmod 600 -&gt; 644) ([#521](https://github.com/nfh-trust-labs/opencred/issues/521)) ([6daa27f](https://github.com/nfh-trust-labs/opencred/commit/6daa27f74f9152f707b3b144bf73c7f40c2a7673))
* **desktop:** include .deb in linux release artefacts ([#523](https://github.com/nfh-trust-labs/opencred/issues/523)) ([35709fb](https://github.com/nfh-trust-labs/opencred/commit/35709fb3a6a14619eeb1a66cab32029064801e59))
* **release:** drop component prefix from release-please tags ([#519](https://github.com/nfh-trust-labs/opencred/issues/519)) ([9f506f9](https://github.com/nfh-trust-labs/opencred/commit/9f506f92d02991e39e78508c8aa6c7d0a912550c))

## [1.2.0](https://github.com/nfh-trust-labs/opencred/compare/opencred-v1.1.0...opencred-v1.2.0) (2026-05-05)


### Features

* Add core review and security audit reports ([1da6352](https://github.com/nfh-trust-labs/opencred/commit/1da63528aaf1667aad9cb770ebc6008e1fda79c3))
* add Ed25519 signing algorithm support ([#195](https://github.com/nfh-trust-labs/opencred/issues/195)) ([c835c2c](https://github.com/nfh-trust-labs/opencred/commit/c835c2c4638a4f5d2ed2458d395f940bf59ac9f6))
* add EdDSA Data Integrity cryptosuite (eddsa-rdfc-2022) ([#198](https://github.com/nfh-trust-labs/opencred/issues/198)) ([b86aef8](https://github.com/nfh-trust-labs/opencred/commit/b86aef8b785cb7d78b967bf193b1be4e8cc5cc12))
* add SD-JWT VC signing with selective disclosure ([#196](https://github.com/nfh-trust-labs/opencred/issues/196)) ([a7de097](https://github.com/nfh-trust-labs/opencred/commit/a7de097003c278d1b96894b6347a87d96978baed))
* add VC-JWT signing for delegated and interface signing ([#197](https://github.com/nfh-trust-labs/opencred/issues/197)) ([374ef90](https://github.com/nfh-trust-labs/opencred/commit/374ef90ce2e5176d30bae2669cb48da5848c4100))
* **api:** add attestation challenge and verification endpoints ([36e82dd](https://github.com/nfh-trust-labs/opencred/commit/36e82dde76bd6b524cb0cce946221f4a77f7fb16))
* **api:** add batch processing engine + API endpoints ([#78](https://github.com/nfh-trust-labs/opencred/issues/78)) ([82bff4a](https://github.com/nfh-trust-labs/opencred/commit/82bff4ad6d00076a7cb1f194dbd2816adfb158c2)), closes [#31](https://github.com/nfh-trust-labs/opencred/issues/31)
* **api:** add CA API adapter interface for Type C onboarding ([#75](https://github.com/nfh-trust-labs/opencred/issues/75)) ([85f4029](https://github.com/nfh-trust-labs/opencred/commit/85f40297427bcf5b3238663eb2c6f82961ddb67c))
* **api:** add credential revocation endpoint ([#52](https://github.com/nfh-trust-labs/opencred/issues/52)) ([209c7c2](https://github.com/nfh-trust-labs/opencred/commit/209c7c2ab795eb49bb7e75710c74b8a3f59f81c9))
* **api:** add CSV upload support for batch issuance ([#80](https://github.com/nfh-trust-labs/opencred/issues/80)) ([72965d7](https://github.com/nfh-trust-labs/opencred/commit/72965d7e3230ac09741570bc78c857dabf88e87b))
* **api:** add delegated issuance endpoint — POST /credentials/issue-delegated ([75ccbb3](https://github.com/nfh-trust-labs/opencred/commit/75ccbb351372019e6d4e8b664f0e96028688a751))
* **api:** add domain ownership verification — DNS TXT + HTTP challenge ([#76](https://github.com/nfh-trust-labs/opencred/issues/76)) ([3fc5fcc](https://github.com/nfh-trust-labs/opencred/commit/3fc5fcc84cef2d8b7e6b743efd3d805ef3a1283b)), closes [#28](https://github.com/nfh-trust-labs/opencred/issues/28)
* **api:** add Interface Signing endpoints — POST /credentials/build + /credentials/package ([#56](https://github.com/nfh-trust-labs/opencred/issues/56)) ([29b4c81](https://github.com/nfh-trust-labs/opencred/commit/29b4c810fb6028e467a71f6d43ea1729b6c616af))
* **api:** add QR code and PDF output format generation ([#81](https://github.com/nfh-trust-labs/opencred/issues/81)) ([6966401](https://github.com/nfh-trust-labs/opencred/commit/6966401a0bd85a1d5a53eeaaa6458174eb66ff0d)), closes [#34](https://github.com/nfh-trust-labs/opencred/issues/34)
* **api:** add Type A DSC onboarding endpoint — POST /onboarding/type-a ([#55](https://github.com/nfh-trust-labs/opencred/issues/55)) ([4a07f0c](https://github.com/nfh-trust-labs/opencred/commit/4a07f0c5602c744eccaf4b887e65b7a7c4385b5d))
* **api:** add Type B onboarding — SSL cert extraction + namespace creation ([#77](https://github.com/nfh-trust-labs/opencred/issues/77)) ([0ba4fa1](https://github.com/nfh-trust-labs/opencred/commit/0ba4fa1f8d3d7ab83190e0bbf7d49855235dd85d))
* **api:** add Type D onboarding — POST /onboarding/business-vc ([226e189](https://github.com/nfh-trust-labs/opencred/commit/226e189963cb23b78fb48d3f90d6195b559cb867))
* **api:** add verification endpoint with DSC/CSCA chain validation ([#58](https://github.com/nfh-trust-labs/opencred/issues/58)) ([3b06679](https://github.com/nfh-trust-labs/opencred/commit/3b066791fa63463ba7e370d63b21925e7b36e1a3)), closes [#20](https://github.com/nfh-trust-labs/opencred/issues/20)
* **api:** implement GET /schemas endpoint and close Phase 3 gaps ([fbd5352](https://github.com/nfh-trust-labs/opencred/commit/fbd5352efce6d10653805b6561bd8e8866275619))
* **api:** scaffold Hono app with middleware, error handling, and health check ([#51](https://github.com/nfh-trust-labs/opencred/issues/51)) ([1a19248](https://github.com/nfh-trust-labs/opencred/commit/1a19248d431f24345202feafc9f2bed21c118bab))
* **browser-extension:** wire up signing bridge for Railway deployment ([#209](https://github.com/nfh-trust-labs/opencred/issues/209)) ([36a20de](https://github.com/nfh-trust-labs/opencred/commit/36a20de91504cbe24261bd547ee1ce747000c2e4))
* **ca-adapter:** add CertificateAuthorityAdapter extension point for Phase 3 ([#217](https://github.com/nfh-trust-labs/opencred/issues/217)) ([5afa69a](https://github.com/nfh-trust-labs/opencred/commit/5afa69afd08622b35a4ea6a29e9d07b8f812095c))
* **ci:** add Docker build, push, and image scanning pipeline ([#92](https://github.com/nfh-trust-labs/opencred/issues/92)) ([f705bcf](https://github.com/nfh-trust-labs/opencred/commit/f705bcf0349cdb75c7a3da17fb178a9880f8470b))
* complete OpenCred-Attested onboarding flow ([#264](https://github.com/nfh-trust-labs/opencred/issues/264)) ([342a535](https://github.com/nfh-trust-labs/opencred/commit/342a5356b9e05e347ae18d708d6e5f0e012c11f9))
* **crypto:** add SigningKeyProvider for delegated signing ([d054ecd](https://github.com/nfh-trust-labs/opencred/commit/d054ecd6b5a8496942fc21fcaf35e0da5fd369bf)), closes [#24](https://github.com/nfh-trust-labs/opencred/issues/24)
* **dedi-client:** add operational logging via injectable logger ([#122](https://github.com/nfh-trust-labs/opencred/issues/122)) ([f0874a6](https://github.com/nfh-trust-labs/opencred/commit/f0874a65d3ed88467ae166c362141690788da711)), closes [#116](https://github.com/nfh-trust-labs/opencred/issues/116)
* **dedi-client:** add operational logging via injectable logger ([#377](https://github.com/nfh-trust-labs/opencred/issues/377)) ([2155eb8](https://github.com/nfh-trust-labs/opencred/commit/2155eb8fd731bbd69fefa218b0f6ddc75683e64a)), closes [#116](https://github.com/nfh-trust-labs/opencred/issues/116)
* **dedi-client:** rewrite for DeDi OpenAPI v2 namespace/registry/record model ([#112](https://github.com/nfh-trust-labs/opencred/issues/112)) ([b4d805b](https://github.com/nfh-trust-labs/opencred/commit/b4d805b9412d99d6e46b61b9c4be206409014917))
* **delegation:** implement delegation certificate management ([3ae4142](https://github.com/nfh-trust-labs/opencred/commit/3ae4142b86748b559bf47ac06ca8b7bd46854c0c))
* **deploy:** add GCP Cloud Run and VM systemd deployment configs ([#94](https://github.com/nfh-trust-labs/opencred/issues/94)) ([fa8a842](https://github.com/nfh-trust-labs/opencred/commit/fa8a8425e1dde52b6e08854c072c071aa385bdf3))
* **desktop,verification:** PixelPass QR/PDF export and x509 chain validation ([0b9854a](https://github.com/nfh-trust-labs/opencred/commit/0b9854ae89439865b733521eeb844bfc71639315))
* **desktop:** add app logo and branding assets ([#360](https://github.com/nfh-trust-labs/opencred/issues/360)) ([2ed603e](https://github.com/nfh-trust-labs/opencred/commit/2ed603e213761cad423088ddd97d78a8f3e262d9)), closes [#303](https://github.com/nfh-trust-labs/opencred/issues/303)
* **desktop:** add attestation store, IPC channels, and proof embedding ([91867ab](https://github.com/nfh-trust-labs/opencred/commit/91867ab8a88bf4cacb152c08004c69789fc9ea71))
* **desktop:** add bulk CSV issuance with offline packaging and ZIP export ([#86](https://github.com/nfh-trust-labs/opencred/issues/86)) ([bc588cf](https://github.com/nfh-trust-labs/opencred/commit/bc588cf4535d74ebfacceaacd164ba9c5cc99b7e))
* **desktop:** add code signing and release workflow ([#223](https://github.com/nfh-trust-labs/opencred/issues/223)) ([#227](https://github.com/nfh-trust-labs/opencred/issues/227)) ([316dad3](https://github.com/nfh-trust-labs/opencred/commit/316dad346cea5301ceda6568436f4f3edb37d16c))
* **desktop:** add credential template rendering and export ([79a1a7a](https://github.com/nfh-trust-labs/opencred/commit/79a1a7a91caf2d285e91fe857a545a6fd23ded19))
* **desktop:** add distribution hardening with code signing, auto-update, and CI/CD ([#88](https://github.com/nfh-trust-labs/opencred/issues/88)) ([b43bd9d](https://github.com/nfh-trust-labs/opencred/commit/b43bd9db484d67996012e8f5a0e37efa734adab8))
* **desktop:** add DSC import module with PFX/PEM parsing ([6cec0a9](https://github.com/nfh-trust-labs/opencred/commit/6cec0a994b9c9934892508d39cdec2915dde72f0))
* **desktop:** add Electron app scaffold with IPC bridge and shared component structure ([#84](https://github.com/nfh-trust-labs/opencred/issues/84)) ([abb7de0](https://github.com/nfh-trust-labs/opencred/commit/abb7de0686616c2b2318ea24c788d0b5053234bd))
* **desktop:** add issuer branding settings (color, logo, display name) ([#367](https://github.com/nfh-trust-labs/opencred/issues/367)) ([c18afdf](https://github.com/nfh-trust-labs/opencred/commit/c18afdf11c0f66cb3e9c837a4cbea9ea06c59f5c))
* **desktop:** add local signing engine, offline VC lifecycle, and packaging ([#85](https://github.com/nfh-trust-labs/opencred/issues/85)) ([a4007a7](https://github.com/nfh-trust-labs/opencred/commit/a4007a7f53c2e4fda6d64aff3f104c03cf200b36))
* **desktop:** add OS certificate store signing with platform abstraction ([#89](https://github.com/nfh-trust-labs/opencred/issues/89)) ([3301da0](https://github.com/nfh-trust-labs/opencred/commit/3301da09ef2687c86d316b159dfd8eb7488c6f17))
* **desktop:** add PKCS[#11](https://github.com/nfh-trust-labs/opencred/issues/11) hardware token signing support ([#87](https://github.com/nfh-trust-labs/opencred/issues/87)) ([bd073dd](https://github.com/nfh-trust-labs/opencred/commit/bd073dd6aeaa0dd3378eef9dc02b7cffe4f0e98b)), closes [#39](https://github.com/nfh-trust-labs/opencred/issues/39)
* **desktop:** add QR code scanning to VerifyPage ([#370](https://github.com/nfh-trust-labs/opencred/issues/370)) ([a578a32](https://github.com/nfh-trust-labs/opencred/commit/a578a32382bb7f64f213b00e88e30a7e434bea30))
* **desktop:** add Quick Start onboarding UI (Workflow 3) ([f88791b](https://github.com/nfh-trust-labs/opencred/commit/f88791b500ac56d89198c45a436798bebe3f8163))
* **desktop:** auto-reload persisted signing keys on startup ([#273](https://github.com/nfh-trust-labs/opencred/issues/273)) ([3d5baf2](https://github.com/nfh-trust-labs/opencred/commit/3d5baf2d5d807ddc2390e26932125f562bedff59))
* **desktop:** DeDi onboarding wizard + key rotation + E2E tests ([#280](https://github.com/nfh-trust-labs/opencred/issues/280)) ([9694f16](https://github.com/nfh-trust-labs/opencred/commit/9694f16e889bef1938e09723d88c01de8848eb35))
* **desktop:** enforce batch row limit of 1000 rows ([#226](https://github.com/nfh-trust-labs/opencred/issues/226)) ([dd591c1](https://github.com/nfh-trust-labs/opencred/commit/dd591c12d1092ff0f801cd544517b8ff6daaf076))
* **desktop:** integrate DeDi client for revocation publishing ([#222](https://github.com/nfh-trust-labs/opencred/issues/222)) ([#228](https://github.com/nfh-trust-labs/opencred/issues/228)) ([e2e4c50](https://github.com/nfh-trust-labs/opencred/commit/e2e4c506a2d388a0bed1a5bf4b3244c73175f4de))
* **desktop:** persistent logging, bug reporting, update UI, and release automation ([#261](https://github.com/nfh-trust-labs/opencred/issues/261)) ([08a6bea](https://github.com/nfh-trust-labs/opencred/commit/08a6bea62704fcd76e022e23187d8fd860aada0b))
* **desktop:** Phase 5 UI redesign + More Options + custom schema management ([#242](https://github.com/nfh-trust-labs/opencred/issues/242)) ([ad8f67a](https://github.com/nfh-trust-labs/opencred/commit/ad8f67a269bf88178326523eaa8423be4e3553e7))
* **desktop:** rebuild UI with onboarding wizard and tabbed layout ([95aa74d](https://github.com/nfh-trust-labs/opencred/commit/95aa74d4615ae6e4d747b89d9c47259e183ddddd))
* **desktop:** redesign onboarding with 3-path flow ([#234](https://github.com/nfh-trust-labs/opencred/issues/234)) ([fa8969f](https://github.com/nfh-trust-labs/opencred/commit/fa8969f19e55f92c2a752527d8e7ac700712739a))
* **desktop:** remaining UX improvements — verify, history, batch, settings ([#290](https://github.com/nfh-trust-labs/opencred/issues/290)) ([b8e8118](https://github.com/nfh-trust-labs/opencred/commit/b8e811849a5a846015972efe197ac9d046df550d))
* **desktop:** UX improvements — hints, progress indicator, simplified flows ([#288](https://github.com/nfh-trust-labs/opencred/issues/288)) ([2bb6b64](https://github.com/nfh-trust-labs/opencred/commit/2bb6b64ef3b37dbb29533dd106d2557b94eb3bb1))
* **desktop:** wire all signing key sources and add key generation ([186fe23](https://github.com/nfh-trust-labs/opencred/commit/186fe2367e07dc4db0342a1256ee02ae4d50d207))
* **desktop:** wire customization into PDF generator and expand branding UI ([#398](https://github.com/nfh-trust-labs/opencred/issues/398)) ([ef5d785](https://github.com/nfh-trust-labs/opencred/commit/ef5d7859ca922c13bf7aae3f140b32e3ad8dd41c))
* **desktop:** wire Google Docs-style home screen and top bar navigation ([#258](https://github.com/nfh-trust-labs/opencred/issues/258)) ([6fd1052](https://github.com/nfh-trust-labs/opencred/commit/6fd1052f6264c8a9550fd7331fd9613208a22b78))
* **desktop:** wire KeyManagement UI into SettingsPage ([#219](https://github.com/nfh-trust-labs/opencred/issues/219)) ([e5d8c94](https://github.com/nfh-trust-labs/opencred/commit/e5d8c9488382a84acd16de54ad7a7ccf0a8197cc))
* **desktop:** wire persistent logging across main process ([#272](https://github.com/nfh-trust-labs/opencred/issues/272)) ([d64f312](https://github.com/nfh-trust-labs/opencred/commit/d64f312f56a34c75929a1758157ae49a9b8c4882))
* **docker:** add container security hardening and E2E smoke tests ([#93](https://github.com/nfh-trust-labs/opencred/issues/93)) ([9458eb3](https://github.com/nfh-trust-labs/opencred/commit/9458eb335767ffb5f264cb278331a9005a34d6a9))
* **docker:** add Docker Compose orchestration for local dev and production ([#91](https://github.com/nfh-trust-labs/opencred/issues/91)) ([c0b2940](https://github.com/nfh-trust-labs/opencred/commit/c0b29404327ff151881e2aa93a67d1d74ce17252))
* **docker:** add multi-stage Docker images for API and Web UI ([#90](https://github.com/nfh-trust-labs/opencred/issues/90)) ([a99fcf1](https://github.com/nfh-trust-labs/opencred/commit/a99fcf1b4f8cdde1e904a7fa3d6601c85ed58392))
* **domain-verification:** add domain ownership verification package ([#215](https://github.com/nfh-trust-labs/opencred/issues/215)) ([0084ffd](https://github.com/nfh-trust-labs/opencred/commit/0084ffda07dc68f256de21f6d353285a5181fb88))
* **infra:** scaffold pnpm monorepo with workspaces, tsconfig, vitest, and CI ([4400921](https://github.com/nfh-trust-labs/opencred/commit/4400921af0a321357ac0fe494c1afce34679ced6))
* **infra:** scaffold pnpm monorepo with workspaces, tsconfig, vitest, and CI ([518cc3b](https://github.com/nfh-trust-labs/opencred/commit/518cc3ba30f37b036a7e76f7febc4254fdd51777)), closes [#4](https://github.com/nfh-trust-labs/opencred/issues/4)
* **infra:** update Docker infrastructure and add production signing key config ([8f7a2a1](https://github.com/nfh-trust-labs/opencred/commit/8f7a2a1e62b91ae0912cc7b39afdf28fa068af84))
* JSON-LD context management + schema UX for verifiable credentials ([#286](https://github.com/nfh-trust-labs/opencred/issues/286)) ([721b3e2](https://github.com/nfh-trust-labs/opencred/commit/721b3e20f76b037458d7b8aa1f4907b2fd12e603))
* multi-algorithm signing with PFX/PEM import and VC-JOSE-COSE JWS proofs ([15871fa](https://github.com/nfh-trust-labs/opencred/commit/15871fa2b464c0f9a84f2cf82ddee48fef762ab7))
* multi-proof format selection with API and web UI wiring ([#199](https://github.com/nfh-trust-labs/opencred/issues/199)) ([258edae](https://github.com/nfh-trust-labs/opencred/commit/258edae1b6c054b1c614e955ca9db0aa2cf99fe3))
* native OS certificate store addons for macOS, Windows, and Linux ([#200](https://github.com/nfh-trust-labs/opencred/issues/200)) ([8a73019](https://github.com/nfh-trust-labs/opencred/commit/8a73019b9c21688604c52ea341562041bbdeec2e))
* Phase 0 core foundation packages ([#9](https://github.com/nfh-trust-labs/opencred/issues/9)-[#15](https://github.com/nfh-trust-labs/opencred/issues/15)) ([3511d84](https://github.com/nfh-trust-labs/opencred/commit/3511d845772724da9a5dfd568c64e3bd1475ab0b))
* Phase 0 foundation reset — DSC-first rebuild ([b40132d](https://github.com/nfh-trust-labs/opencred/commit/b40132de3432c04cd9f01083db5307c763827e66))
* **release:** publish docker image and desktop installers via public mirror ([#514](https://github.com/nfh-trust-labs/opencred/issues/514)) ([6d07f8d](https://github.com/nfh-trust-labs/opencred/commit/6d07f8d610e04a674ebb1e40b2ff24699912f827))
* **schema-engine:** add education schema, categories, and schema audit ([#375](https://github.com/nfh-trust-labs/opencred/issues/375)) ([6f1dfef](https://github.com/nfh-trust-labs/opencred/commit/6f1dfefc0b03fe7a601c99eddf9caf1f4996868a)), closes [#109](https://github.com/nfh-trust-labs/opencred/issues/109)
* **schema-engine:** add schema versioning and update delivery mechanism ([#374](https://github.com/nfh-trust-labs/opencred/issues/374)) ([3dfb5aa](https://github.com/nfh-trust-labs/opencred/commit/3dfb5aac48e29965ec045ebd43f9e1a492305402))
* **schema-engine:** add schema versioning and update mechanism ([#229](https://github.com/nfh-trust-labs/opencred/issues/229)) ([ddcd7d9](https://github.com/nfh-trust-labs/opencred/commit/ddcd7d90086a63db072712ca3da5e5e40a4f357c))
* **schema-engine:** support dynamic schema generation from issuer-defined fields ([#372](https://github.com/nfh-trust-labs/opencred/issues/372)) ([ab114d9](https://github.com/nfh-trust-labs/opencred/commit/ab114d9f23df6b64935f692baf64038218cf9e7f))
* **schema-library:** v1 curated catalogue with build-time bundling ([#345](https://github.com/nfh-trust-labs/opencred/issues/345)) ([1b14737](https://github.com/nfh-trust-labs/opencred/commit/1b147374ceadb1e2e48f4e5e633e163417c5dcfa))
* Self-Published Keys (did:web) + DeDi integration ([#274](https://github.com/nfh-trust-labs/opencred/issues/274)) ([5889d59](https://github.com/nfh-trust-labs/opencred/commit/5889d592b31fcf05738cfed295aa100636b37456))
* **server:** /v1 API surface, /v1/keys endpoint, smoke tests ([#307](https://github.com/nfh-trust-labs/opencred/issues/307)) ([dfb8265](https://github.com/nfh-trust-labs/opencred/commit/dfb826519bc5202614e6d04a3686fd1bd28b034a))
* **server:** accept issuer branding in API endpoints ([#368](https://github.com/nfh-trust-labs/opencred/issues/368)) ([773664c](https://github.com/nfh-trust-labs/opencred/commit/773664c65a7bfa0370a5cb9de635f0ec2edc3137))
* **server:** accept multi-format credentials in verify endpoint ([#369](https://github.com/nfh-trust-labs/opencred/issues/369)) ([8e98034](https://github.com/nfh-trust-labs/opencred/commit/8e98034439ddadc6d59c0b84b072e6941880822c)), closes [#237](https://github.com/nfh-trust-labs/opencred/issues/237)
* **server:** add application metrics, tracing, and alerting ([#373](https://github.com/nfh-trust-labs/opencred/issues/373)) ([b759237](https://github.com/nfh-trust-labs/opencred/commit/b7592372bf47d4006cff210a92f59a99ce8e7a55))
* **server:** add config validate subcommand, --version, and improved help text ([#358](https://github.com/nfh-trust-labs/opencred/issues/358)) ([0c817be](https://github.com/nfh-trust-labs/opencred/commit/0c817be6ec42458a0665109e7ce7986bfb8783c8))
* **server:** add credential packaging endpoint (PDF, QR, JSON) ([e08e90b](https://github.com/nfh-trust-labs/opencred/commit/e08e90b275eae92a4417ce0543b0b826c1151003))
* **server:** add webhook callback for batch completion ([#371](https://github.com/nfh-trust-labs/opencred/issues/371)) ([5ad7d0c](https://github.com/nfh-trust-labs/opencred/commit/5ad7d0cbe4a7160a90825f2784d3554337707556))
* **server:** Cloud HSM signing adapters and CLI mode ([#255](https://github.com/nfh-trust-labs/opencred/issues/255)) ([e187b62](https://github.com/nfh-trust-labs/opencred/commit/e187b627701c02e593810eaf89d4652a8e77792f))
* **server:** inline custom JSON Schema + DeDi public-key registry routes ([#506](https://github.com/nfh-trust-labs/opencred/issues/506)) ([0bb5aec](https://github.com/nfh-trust-labs/opencred/commit/0bb5aeccfc46acb9899255ab60f26a926c6aa2ae))
* **server:** integrate DeDi client for revocation checking and publishing ([#396](https://github.com/nfh-trust-labs/opencred/issues/396)) ([d4b4b83](https://github.com/nfh-trust-labs/opencred/commit/d4b4b83b08b2d85fef651a0acfee1ab790482943))
* **server:** log verification detail + full Error in error-handler ([#491](https://github.com/nfh-trust-labs/opencred/issues/491)) ([323a7c2](https://github.com/nfh-trust-labs/opencred/commit/323a7c28c3bccca8a57674d9d427591a69670109))
* **server:** POST /v1/dedi/namespace/ensure for runtime registry creation ([#509](https://github.com/nfh-trust-labs/opencred/issues/509)) ([54e5175](https://github.com/nfh-trust-labs/opencred/commit/54e517572b752996f596c5d5313aa2e0bfe1798f)), closes [#507](https://github.com/nfh-trust-labs/opencred/issues/507)
* **server:** scaffold Hono server with all Phase 6 endpoints ([#253](https://github.com/nfh-trust-labs/opencred/issues/253)) ([85a2796](https://github.com/nfh-trust-labs/opencred/commit/85a27962bc44ff691d57a0aae17fb94bea2e3334))
* **shared:** canonicalJsonSha256 for cross-repo hash consistency ([#342](https://github.com/nfh-trust-labs/opencred/issues/342)) ([d684691](https://github.com/nfh-trust-labs/opencred/commit/d68469137a6280a6552a778ca17277931ccee91d))
* **signing,desktop:** route PKCS[#11](https://github.com/nfh-trust-labs/opencred/issues/11) warnings through the structured logger ([#494](https://github.com/nfh-trust-labs/opencred/issues/494)) ([0f27e5b](https://github.com/nfh-trust-labs/opencred/commit/0f27e5bf20423bdbd724f0fd9fdef7d2520bbe0a))
* **templates,api:** add per-schema SVG templates and cross-interface integration tests ([0ff1e73](https://github.com/nfh-trust-labs/opencred/commit/0ff1e73abf279049158130f72d2d4b7ef380b2a0))
* **templates:** expand credential customization with colors, logo sizing, footer, and seal ([#397](https://github.com/nfh-trust-labs/opencred/issues/397)) ([eac6767](https://github.com/nfh-trust-labs/opencred/commit/eac676796d7504dfde27c454363c8536e1e215e3))
* **verification:** add business VC verification module for OpenCred-Attested auth ([#216](https://github.com/nfh-trust-labs/opencred/issues/216)) ([878d381](https://github.com/nfh-trust-labs/opencred/commit/878d3813fed0b8051840dc657964b8781a93764a))
* **verification:** add CscaTrustStore class for CSCA root certificate validation ([#364](https://github.com/nfh-trust-labs/opencred/issues/364)) ([7d10478](https://github.com/nfh-trust-labs/opencred/commit/7d10478b16a08da5f2dfdeb4e4abab6814ff0946)), closes [#316](https://github.com/nfh-trust-labs/opencred/issues/316)
* **verification:** add delegation chain validation and DELEGATION_INVALID result code ([c5da410](https://github.com/nfh-trust-labs/opencred/commit/c5da410b9f9f282ebb6a7aa21a56f9414ce94d0d))
* **verification:** harden attestation chain validation for Phase 3 ([#218](https://github.com/nfh-trust-labs/opencred/issues/218)) ([494d8c7](https://github.com/nfh-trust-labs/opencred/commit/494d8c79fd6dac2a8f2a69ddbff5766519e4acbe))
* **verification:** multi-format verification engine ([#53](https://github.com/nfh-trust-labs/opencred/issues/53)) ([8668e85](https://github.com/nfh-trust-labs/opencred/commit/8668e85ab2b3fd007c76ea69120148aeec5ba743))
* web signing, deployment fixes, and Railway support ([#194](https://github.com/nfh-trust-labs/opencred/issues/194)) ([8c3b2eb](https://github.com/nfh-trust-labs/opencred/commit/8c3b2eb212dcf746aa28b8b8bf017f9ef6925d5c))
* web UI signing via browser extension and native messaging ([f557b74](https://github.com/nfh-trust-labs/opencred/commit/f557b741ad33e4f3b84f98ba8a9e67be07b18295))
* **web:** add credential builder and verifier UI ([#57](https://github.com/nfh-trust-labs/opencred/issues/57)) ([2326519](https://github.com/nfh-trust-labs/opencred/commit/2326519cfffab5ae174996aafa7e5ca39336c1ec))
* **web:** add full Web UI feature set — delegated, revoke, batch, onboarding ([#82](https://github.com/nfh-trust-labs/opencred/issues/82)) ([4c8eb72](https://github.com/nfh-trust-labs/opencred/commit/4c8eb72b49ec0b03d7b10f845829ef4a8af126f7)), closes [#33](https://github.com/nfh-trust-labs/opencred/issues/33)
* **web:** add PDF download with QR code for issued credentials ([#212](https://github.com/nfh-trust-labs/opencred/issues/212)) ([7c27381](https://github.com/nfh-trust-labs/opencred/commit/7c273818903dab103f7069ab5c3c2fb2a9f9d791))


### Bug Fixes

* address low-severity code-review findings ([#157](https://github.com/nfh-trust-labs/opencred/issues/157), [#160](https://github.com/nfh-trust-labs/opencred/issues/160), [#161](https://github.com/nfh-trust-labs/opencred/issues/161)) ([#395](https://github.com/nfh-trust-labs/opencred/issues/395)) ([2097350](https://github.com/nfh-trust-labs/opencred/commit/20973503ebaf1a3afbfbad2962563bd390e33de7))
* address remaining low-severity issues across codebase ([13e8624](https://github.com/nfh-trust-labs/opencred/commit/13e8624e2e67cd88421ae366af9556879f6a6642))
* **api:** add cryptographic signature verification to DSC chain validation ([29e59a3](https://github.com/nfh-trust-labs/opencred/commit/29e59a3da8268261f252b1b30600b66c24ebda7a))
* **api:** add tsx as devDependency for dev server ([9fb1e24](https://github.com/nfh-trust-labs/opencred/commit/9fb1e24ef69656f4b4026602fb9e44143289165f))
* **api:** align API routes with PRD and add health readiness tests ([02c06d9](https://github.com/nfh-trust-labs/opencred/commit/02c06d957694b6d8f830740c30c8458de7af3ed2))
* **api:** harden rate limiting and body size enforcement ([d42051f](https://github.com/nfh-trust-labs/opencred/commit/d42051f0f62d107ae30efeb21e6e4e04a177f020))
* **api:** return 400 for malformed JSON request bodies ([#201](https://github.com/nfh-trust-labs/opencred/issues/201)) ([e7d6e93](https://github.com/nfh-trust-labs/opencred/commit/e7d6e935d9809eb5b0e631018d5957961b1fbc5b))
* **api:** return 501 for unconfigured delegated signing + bind IPv6 for Railway ([507c338](https://github.com/nfh-trust-labs/opencred/commit/507c3389102dff53420b2d9eb75a0927f2312939))
* **api:** return JSON 404 for unknown routes and 405 for wrong methods ([#205](https://github.com/nfh-trust-labs/opencred/issues/205)) ([002bd7a](https://github.com/nfh-trust-labs/opencred/commit/002bd7adf352f9e2ac9f19f1c3c0ab5aca3ccacd))
* **api:** use did:jwk for verificationMethod instead of issuer DID ([8323719](https://github.com/nfh-trust-labs/opencred/commit/83237191f36f00b2449a9882e4fcae6afbf186ae))
* **build:** force node-gyp &gt;=10 to fix native addon rebuild on Node 20 ([#404](https://github.com/nfh-trust-labs/opencred/issues/404)) ([fd8a528](https://github.com/nfh-trust-labs/opencred/commit/fd8a52839ab98885244cdffb9a820f1b7c34bf9e))
* **build:** force node-gyp &gt;=10 to fix native addon rebuild on Node 20 ([#404](https://github.com/nfh-trust-labs/opencred/issues/404)) ([#405](https://github.com/nfh-trust-labs/opencred/issues/405)) ([94e3305](https://github.com/nfh-trust-labs/opencred/commit/94e33052bd092e7cf8d750738f459e2191ad25d9))
* **build:** upgrade electron-rebuild toolchain to work with Node 20+ ([#411](https://github.com/nfh-trust-labs/opencred/issues/411)) ([2aec32e](https://github.com/nfh-trust-labs/opencred/commit/2aec32e9a518bdc48758ddc4550fce172a2e003a))
* **build:** upgrade electron-rebuild toolchain to work with Node 20+ ([#411](https://github.com/nfh-trust-labs/opencred/issues/411)) ([#412](https://github.com/nfh-trust-labs/opencred/issues/412)) ([f46e250](https://github.com/nfh-trust-labs/opencred/commit/f46e250cca6d4cd8788918bcbc39c8e7a8d7a354))
* **ci:** add 10-minute timeout to rebuild:native step ([#409](https://github.com/nfh-trust-labs/opencred/issues/409)) ([aab3dd0](https://github.com/nfh-trust-labs/opencred/commit/aab3dd02ef05623569adfa7bc2f9d3e2ad37bd1f))
* **ci:** add 10-minute timeout to rebuild:native step ([#409](https://github.com/nfh-trust-labs/opencred/issues/409)) ([#410](https://github.com/nfh-trust-labs/opencred/issues/410)) ([92ac294](https://github.com/nfh-trust-labs/opencred/commit/92ac2941e35ab2de873568bb38ca1276f730fd2b))
* **ci:** build multi-arch Docker image and fix the smoke test ([#516](https://github.com/nfh-trust-labs/opencred/issues/516)) ([bff834a](https://github.com/nfh-trust-labs/opencred/commit/bff834a0080d7d4e5c500b2561356df06190f570))
* **ci:** bump rebuild:native timeout to 20 min for Windows ([#500](https://github.com/nfh-trust-labs/opencred/issues/500)) ([af36bf4](https://github.com/nfh-trust-labs/opencred/commit/af36bf48456fa07b64c1f93353e50f5948e0cf08))
* **ci:** clear pre-existing lint + typecheck errors blocking every PR ([#466](https://github.com/nfh-trust-labs/opencred/issues/466)) ([877f90a](https://github.com/nfh-trust-labs/opencred/commit/877f90a37a17d140eee7d38cbd467ac380be0edb))
* **ci:** drop Windows from desktop-release matrix temporarily ([#502](https://github.com/nfh-trust-labs/opencred/issues/502)) ([7dda71c](https://github.com/nfh-trust-labs/opencred/commit/7dda71c4c17318b316a9ee42b0b70fe77af29158))
* **ci:** fix desktop build — add homepage field and install setuptools for pkcs11js ([b47e9b8](https://github.com/nfh-trust-labs/opencred/commit/b47e9b8a845a84af9a0eb86a487c034a0f9956ca))
* **ci:** fix desktop build metadata and use Python 3.11 for native modules ([01e4830](https://github.com/nfh-trust-labs/opencred/commit/01e483071efb8273a958e3cf1745908f54d342cd))
* **ci:** gate Docker push on tests passing ([#383](https://github.com/nfh-trust-labs/opencred/issues/383)) ([2f97a71](https://github.com/nfh-trust-labs/opencred/commit/2f97a71161b09c177f25f5145030ea4ca9665083)), closes [#149](https://github.com/nfh-trust-labs/opencred/issues/149)
* **ci:** harden desktop-release against unsigned / broken artefacts ([#455](https://github.com/nfh-trust-labs/opencred/issues/455)) ([e4a95db](https://github.com/nfh-trust-labs/opencred/commit/e4a95dbcf1553305e96937000e473fa4f616e536))
* **ci:** Linux deb + Windows build fixes ([#296](https://github.com/nfh-trust-labs/opencred/issues/296)) ([df62291](https://github.com/nfh-trust-labs/opencred/commit/df622918756171dae4832bba81e30ff94dd4dc1d))
* **ci:** native build issues on Linux and Windows ([#295](https://github.com/nfh-trust-labs/opencred/issues/295)) ([218d815](https://github.com/nfh-trust-labs/opencred/commit/218d815cf0b0191db2c4e3a6272868115e30377a))
* **ci:** remove continue-on-error on native-addon rebuild + verify ([#449](https://github.com/nfh-trust-labs/opencred/issues/449)) ([90a8976](https://github.com/nfh-trust-labs/opencred/commit/90a8976162cc9852e516825f558939bc834930f2))
* **ci:** remove duplicate test job in docker.yml ([#388](https://github.com/nfh-trust-labs/opencred/issues/388)) ([d909789](https://github.com/nfh-trust-labs/opencred/commit/d909789dfaa12cd43dec8961a9be6302b4e768cd))
* **ci:** repair desktop-release workflow + ignore claude worktrees (cherry-pick from [#401](https://github.com/nfh-trust-labs/opencred/issues/401), [#402](https://github.com/nfh-trust-labs/opencred/issues/402)) ([#403](https://github.com/nfh-trust-labs/opencred/issues/403)) ([8c3e11f](https://github.com/nfh-trust-labs/opencred/commit/8c3e11f6eb8ab1b386815769ad515d0e6572ac97))
* **ci:** repair desktop-release workflow and add manual tag dispatch ([#402](https://github.com/nfh-trust-labs/opencred/issues/402)) ([4b7410f](https://github.com/nfh-trust-labs/opencred/commit/4b7410f8b17cc3d3b2f0b41f6e5ffaf1a8072039))
* **ci:** sync pnpm-lock.yaml with package.json ([#293](https://github.com/nfh-trust-labs/opencred/issues/293)) ([c385880](https://github.com/nfh-trust-labs/opencred/commit/c385880a87ce08f6426dff886c9c20044c93b320))
* **ci:** target new-opencred-dev in release-please ([#406](https://github.com/nfh-trust-labs/opencred/issues/406)) ([e44807c](https://github.com/nfh-trust-labs/opencred/commit/e44807c23116f7822c42518186443c3b39873655))
* **ci:** unset empty CSC_* env vars when building unsigned ([#503](https://github.com/nfh-trust-labs/opencred/issues/503)) ([20d8ada](https://github.com/nfh-trust-labs/opencred/commit/20d8ada8af6e20c52e4ae15a3ad7b08dd4b372e6))
* **ci:** use explicit compose file in smoke test to avoid override ([#96](https://github.com/nfh-trust-labs/opencred/issues/96)) ([b5b227a](https://github.com/nfh-trust-labs/opencred/commit/b5b227ad934dc7d5250de7109f7a222c318c2659))
* **ci:** use pnpm exec for electron-builder in desktop build workflow ([be8f7ba](https://github.com/nfh-trust-labs/opencred/commit/be8f7baf1da512f5d04c70c92f0f06239dd3460b))
* **crypto:** remove deprecated importPrivateKey function ([#105](https://github.com/nfh-trust-labs/opencred/issues/105)) ([40ea3c5](https://github.com/nfh-trust-labs/opencred/commit/40ea3c59303435535ba3c502f78362cae9c1d5f9))
* **dedi-client,delegation:** preserve scope object structure and harden validation ([1c9a2f7](https://github.com/nfh-trust-labs/opencred/commit/1c9a2f79eb9f4a6368c638136d67796ba3d75087))
* **dedi-client:** add delegation record validation ([#121](https://github.com/nfh-trust-labs/opencred/issues/121)) ([58797ed](https://github.com/nfh-trust-labs/opencred/commit/58797ed56c17b08dc3d57b14b01c7c31505a84e2)), closes [#117](https://github.com/nfh-trust-labs/opencred/issues/117)
* **dedi-client:** add runtime validation for DeDi API responses ([#381](https://github.com/nfh-trust-labs/opencred/issues/381)) ([3962992](https://github.com/nfh-trust-labs/opencred/commit/3962992da8453dac6a6cc7ab47a2cf0bdb532d04)), closes [#177](https://github.com/nfh-trust-labs/opencred/issues/177)
* **dedi-client:** align API endpoints with real DeDi backend ([#282](https://github.com/nfh-trust-labs/opencred/issues/282)) ([e821501](https://github.com/nfh-trust-labs/opencred/commit/e8215016dd2695bbe80c0ee12d57539fe1184f70))
* **dedi-client:** circuit breaker only counts 5xx errors as failures ([#118](https://github.com/nfh-trust-labs/opencred/issues/118)) ([ad03494](https://github.com/nfh-trust-labs/opencred/commit/ad03494392784d7894d6f8b536809145d16f433a)), closes [#113](https://github.com/nfh-trust-labs/opencred/issues/113)
* **dedi-client:** enforce HTTPS and SSRF protection on DeDi API client ([#348](https://github.com/nfh-trust-labs/opencred/issues/348)) ([3e4e45b](https://github.com/nfh-trust-labs/opencred/commit/3e4e45b2beb4446a4e1c18249f12480968e45adb)), closes [#333](https://github.com/nfh-trust-labs/opencred/issues/333)
* **dedi-client:** make DeDiTokenManager.setTokens atomic ([#487](https://github.com/nfh-trust-labs/opencred/issues/487)) ([5999a97](https://github.com/nfh-trust-labs/opencred/commit/5999a97927d250cb8b02b0de449f2202aa949c6a))
* **dedi-client:** narrow retry transient error detection ([#120](https://github.com/nfh-trust-labs/opencred/issues/120)) ([eac0817](https://github.com/nfh-trust-labs/opencred/commit/eac0817f34568593d70ec95d0848494aa11ca6ce)), closes [#114](https://github.com/nfh-trust-labs/opencred/issues/114)
* **dedi-client:** narrow retry transient error detection ([#376](https://github.com/nfh-trust-labs/opencred/issues/376)) ([99d01a5](https://github.com/nfh-trust-labs/opencred/commit/99d01a51f23a12266824ad9c747e6897811317f6)), closes [#114](https://github.com/nfh-trust-labs/opencred/issues/114)
* **dedi-client:** send tag OR schema, not both ([#283](https://github.com/nfh-trust-labs/opencred/issues/283)) ([0e642fb](https://github.com/nfh-trust-labs/opencred/commit/0e642fb4e4878a5e823915bc3a52d9508340fe27))
* **dedi-client:** simplify createRegistry API ([#284](https://github.com/nfh-trust-labs/opencred/issues/284)) ([2a42e08](https://github.com/nfh-trust-labs/opencred/commit/2a42e089606bd56dc2cb9987c5f2aceb0b1af13a))
* **dedi-client:** validate certificate field in assertDelegationShape ([#392](https://github.com/nfh-trust-labs/opencred/issues/392)) ([3138d28](https://github.com/nfh-trust-labs/opencred/commit/3138d288195d6f8fa610682fbf069c33bf47f07b))
* **dedi-client:** wrap response.json() in auth performLogin/performRefresh ([#119](https://github.com/nfh-trust-labs/opencred/issues/119)) ([a9680ef](https://github.com/nfh-trust-labs/opencred/commit/a9680efd4c18eb05fdc765e5430d0d3034507bc7)), closes [#115](https://github.com/nfh-trust-labs/opencred/issues/115)
* **delegation:** enforce strict delegatee-to-signing-key comparison ([#103](https://github.com/nfh-trust-labs/opencred/issues/103)) ([4d8f7e9](https://github.com/nfh-trust-labs/opencred/commit/4d8f7e995baf01da81006cdf9337045a4bfff7a3))
* **deploy:** harden nginx config (body size, CORS, timeouts, headers) ([#385](https://github.com/nfh-trust-labs/opencred/issues/385)) ([6e13b1f](https://github.com/nfh-trust-labs/opencred/commit/6e13b1f93d59f7097853bb995c69885371dfe297))
* **desktop,vc-core,dedi-client:** timezone date bug, JSON-LD protected terms, and build fixes ([#287](https://github.com/nfh-trust-labs/opencred/issues/287)) ([ca43f7a](https://github.com/nfh-trust-labs/opencred/commit/ca43f7a6cee68aa93285c09206a8686dc5b9cc17))
* **desktop:** add .catch to batch engine.start promise ([#450](https://github.com/nfh-trust-labs/opencred/issues/450)) ([6c00915](https://github.com/nfh-trust-labs/opencred/commit/6c00915e0f12b837a9cf9499f1483a396bcf5737))
* **desktop:** add branding to ALLOWED_CONFIG_KEYS ([#447](https://github.com/nfh-trust-labs/opencred/issues/447)) ([16d0051](https://github.com/nfh-trust-labs/opencred/commit/16d0051828a2b3a0710ab306ebad0da4c6e47735))
* **desktop:** add conf as explicit dep for electron-builder packaging ([#291](https://github.com/nfh-trust-labs/opencred/issues/291)) ([64fef73](https://github.com/nfh-trust-labs/opencred/commit/64fef73aa4f08c1441e63dbb87c83ec7f34f94ba))
* **desktop:** add DeDi + did:web IPC handlers, fix IPv6 SSRF ([#275](https://github.com/nfh-trust-labs/opencred/issues/275)) ([d200f46](https://github.com/nfh-trust-labs/opencred/commit/d200f46d65eedc1021c970f50c7961f66c76104a))
* **desktop:** bundle main process with esbuild to eliminate MODULE_NOT_FOUND crashes ([9aa8e17](https://github.com/nfh-trust-labs/opencred/commit/9aa8e17eb97b87b3515b44c61e185cb0fac9e99a))
* **desktop:** clean up partial .zip on export error + unref auto-updater interval ([#492](https://github.com/nfh-trust-labs/opencred/issues/492)) ([10d2275](https://github.com/nfh-trust-labs/opencred/commit/10d22755f499c025fc59ace0bd9c0e6a3e1ee9f5))
* **desktop:** commit flatten-deps.cjs ([#294](https://github.com/nfh-trust-labs/opencred/issues/294)) ([93f6c2d](https://github.com/nfh-trust-labs/opencred/commit/93f6c2d0a1235ac1842c374be65276747c55c2e6))
* **desktop:** correct did:web verificationMethod + DeDi publish fixes ([#285](https://github.com/nfh-trust-labs/opencred/issues/285)) ([6dabe9c](https://github.com/nfh-trust-labs/opencred/commit/6dabe9cb1ba89dd11b718dbfe0e484285dfa7334))
* **desktop:** DeDi settings panel + registry creation feedback ([#281](https://github.com/nfh-trust-labs/opencred/issues/281)) ([3171ac1](https://github.com/nfh-trust-labs/opencred/commit/3171ac179de4a5cbae370c3bad45199b209f3406))
* **desktop:** drop MSI target ([#297](https://github.com/nfh-trust-labs/opencred/issues/297)) ([d54bfb8](https://github.com/nfh-trust-labs/opencred/commit/d54bfb8797dec20488e1ed76ee5588ba097ea867))
* **desktop:** enable forceCodeSigning in electron-builder config ([#353](https://github.com/nfh-trust-labs/opencred/issues/353)) ([8edc2ea](https://github.com/nfh-trust-labs/opencred/commit/8edc2ea0b20f74edb4f9311007df404b190f3c09))
* **desktop:** enable sandbox, add CSP, block navigation and window.open ([#356](https://github.com/nfh-trust-labs/opencred/issues/356)) ([c7a5ad0](https://github.com/nfh-trust-labs/opencred/commit/c7a5ad0a67ac7e0eeccbc9dafcdd12d2c6cdea86))
* **desktop:** extend logger redaction to cover base64url-encoded keys ([#354](https://github.com/nfh-trust-labs/opencred/issues/354)) ([af6c248](https://github.com/nfh-trust-labs/opencred/commit/af6c248d597b753b37459b3ee1ac000b320adcd3))
* **desktop:** format all desktop files with prettier and fix CI workflow ([4a3431c](https://github.com/nfh-trust-labs/opencred/commit/4a3431c27cc9ce560853e29231f4840ed7c62646))
* **desktop:** handle revocation queue save/load errors ([#380](https://github.com/nfh-trust-labs/opencred/issues/380)) ([55595ff](https://github.com/nfh-trust-labs/opencred/commit/55595ffdf24d81b6716663a783405f66ad6a666a)), closes [#135](https://github.com/nfh-trust-labs/opencred/issues/135)
* **desktop:** hoist missing transitive deps in flatten-deps script ([#298](https://github.com/nfh-trust-labs/opencred/issues/298)) ([84884d6](https://github.com/nfh-trust-labs/opencred/commit/84884d68d4e0d4fe9c5d73530d689b024e4dc633))
* **desktop:** log warning on store file permission failures ([#393](https://github.com/nfh-trust-labs/opencred/issues/393)) ([2c5ad22](https://github.com/nfh-trust-labs/opencred/commit/2c5ad222121a37f11d92f1bfe78e8194448b885e)), closes [#136](https://github.com/nfh-trust-labs/opencred/issues/136)
* **desktop:** only remove persisted signer entries when the file is missing ([#452](https://github.com/nfh-trust-labs/opencred/issues/452)) ([84b31ee](https://github.com/nfh-trust-labs/opencred/commit/84b31ee0bc30fa4874ddb4db916f68f5dd1e8ec1))
* **desktop:** register hoisted deps in package.json for electron-builder ([1e1fe96](https://github.com/nfh-trust-labs/opencred/commit/1e1fe965dc7c717481b9628518db1a9269a5c841))
* **desktop:** remove "preferences" from ALLOWED_CONFIG_KEYS ([#448](https://github.com/nfh-trust-labs/opencred/issues/448)) ([0bdb803](https://github.com/nfh-trust-labs/opencred/commit/0bdb803e3db81f7baebfadb8762c4dd5caf404eb))
* **desktop:** resolve CI failures — lockfile, type errors, lint, and ESM compat ([37c0614](https://github.com/nfh-trust-labs/opencred/commit/37c0614bff162c8b98d210ee44c9e73a18e534d1))
* **desktop:** restrict getConfig/setConfig IPC to allowlisted keys ([#355](https://github.com/nfh-trust-labs/opencred/issues/355)) ([e7f6e6b](https://github.com/nfh-trust-labs/opencred/commit/e7f6e6b83bd05a22f3610f264635955cea6428f9)), closes [#331](https://github.com/nfh-trust-labs/opencred/issues/331)
* **desktop:** scope hoisting to runtime deps + nested version conflict resolution ([8536158](https://github.com/nfh-trust-labs/opencred/commit/853615827a618a0c8df6ecd68c4c204c53d72284))
* **desktop:** secure electron-store key path persistence ([#106](https://github.com/nfh-trust-labs/opencred/issues/106)) ([618cf97](https://github.com/nfh-trust-labs/opencred/commit/618cf979bf95a4ea4db2c377c10b5f3ff82bbda9))
* **desktop:** ship cleanly unsigned artefacts until signing certs are acquired ([#498](https://github.com/nfh-trust-labs/opencred/issues/498)) ([d5e5048](https://github.com/nfh-trust-labs/opencred/commit/d5e50481297127f50eaf9241f2a34748a5e49353))
* **desktop:** track DeDi publish state for custom schemas ([#459](https://github.com/nfh-trust-labs/opencred/issues/459)) ([46116e5](https://github.com/nfh-trust-labs/opencred/commit/46116e59eaab0cc484aba3911e263ece0b58829f))
* **desktop:** Zod-validate KEY_IMPORT, BATCH_EXPORT, FILE_OPEN, FILE_SAVE payloads ([#464](https://github.com/nfh-trust-labs/opencred/issues/464)) ([59e92d3](https://github.com/nfh-trust-labs/opencred/commit/59e92d373fb674122a2b331cf73e57e4b83e5629))
* **docker:** add nginx capabilities for read-only filesystem ([#99](https://github.com/nfh-trust-labs/opencred/issues/99)) ([1dea9a3](https://github.com/nfh-trust-labs/opencred/commit/1dea9a31b3cc7f13094f4e2d2a3c6c00e97c3a8f))
* **docker:** copy all pnpm node_modules to runtime stage ([#97](https://github.com/nfh-trust-labs/opencred/issues/97)) ([f8c589b](https://github.com/nfh-trust-labs/opencred/commit/f8c589b39575eee8d4f1bc3e046a8d24fc95ebe9))
* **docker:** copy server node_modules for pnpm symlink resolution ([654f1ca](https://github.com/nfh-trust-labs/opencred/commit/654f1caeb9939cafad488846566ff5873fc70d9d))
* **docker:** copy server node_modules for pnpm symlink resolution ([846e945](https://github.com/nfh-trust-labs/opencred/commit/846e945ebdd1edf0d174cbce148d8d1386c78ae1))
* **docker:** run nginx as unprivileged user on port 8080 ([#107](https://github.com/nfh-trust-labs/opencred/issues/107)) ([560b2ac](https://github.com/nfh-trust-labs/opencred/commit/560b2ac9aaaa0c07d6a51d07ed8e4bf52e698f14))
* **docs:** reframe server docs as issuer-self-hosted ([#267](https://github.com/nfh-trust-labs/opencred/issues/267)) ([9bd1988](https://github.com/nfh-trust-labs/opencred/commit/9bd198851f677ab38ca2bde5dd6c70e6728ade9c))
* **docs:** remove attestation API from server docs ([#268](https://github.com/nfh-trust-labs/opencred/issues/268)) ([9f39bc4](https://github.com/nfh-trust-labs/opencred/commit/9f39bc4e70ed776e84846c352606d7a974254d3d))
* **docs:** rename docs/server to docs/self-hosted ([#269](https://github.com/nfh-trust-labs/opencred/issues/269)) ([36bc990](https://github.com/nfh-trust-labs/opencred/commit/36bc9900945e2dedf70746c4840562ffde15a8e5))
* DSC = Digital Signature Certificate ([#271](https://github.com/nfh-trust-labs/opencred/issues/271)) ([da0863e](https://github.com/nfh-trust-labs/opencred/commit/da0863e543e6c6d58eb3e1bd14e0c2e661882ca6))
* enable strict JSON-LD canonicalization + unblock CI baseline ([#321](https://github.com/nfh-trust-labs/opencred/issues/321)) ([22094e0](https://github.com/nfh-trust-labs/opencred/commit/22094e03fbbe382efa15dffb4adfc33bcd81a8ed))
* harden .gitignore for .env file variants ([#384](https://github.com/nfh-trust-labs/opencred/issues/384)) ([0e16a13](https://github.com/nfh-trust-labs/opencred/commit/0e16a13533d669f02ab65005c365a77252001590))
* **infra:** add @types/node and fix prettier formatting for CI ([0576330](https://github.com/nfh-trust-labs/opencred/commit/05763304f2cb717ba10448eb7f4198f074a1ec54))
* **infra:** harden nginx, Docker CI, systemd, and compose config ([f20eac7](https://github.com/nfh-trust-labs/opencred/commit/f20eac7fea51c3bdc8e5b6a175c410be35c4db10))
* **packages:** add exports field to all workspace packages for Node16 module resolution ([#95](https://github.com/nfh-trust-labs/opencred/issues/95)) ([0445229](https://github.com/nfh-trust-labs/opencred/commit/04452294f27f5cac12a8db4b47c408c3d924f5ee))
* resolve CI failures — prettier formatting, @types/uuid, TS cast ([#72](https://github.com/nfh-trust-labs/opencred/issues/72)) ([1ada5b6](https://github.com/nfh-trust-labs/opencred/commit/1ada5b64b825ac5e32fc348a3e544b0233ca4bcc))
* resolve post-merge build errors across server and desktop ([#279](https://github.com/nfh-trust-labs/opencred/issues/279)) ([9dbf878](https://github.com/nfh-trust-labs/opencred/commit/9dbf87888115a2b3b6cd0cf763baf7e0167cdf79))
* resolve post-merge type errors and test expectation mismatches ([a13d702](https://github.com/nfh-trust-labs/opencred/commit/a13d702ab9fec72e0b69b37d50e15794eae41378))
* resolve test failures from merge integration ([a2e53a1](https://github.com/nfh-trust-labs/opencred/commit/a2e53a1ed2cf5ab79c72196dbe7f6dbfe78c24db))
* **schema-engine:** make computeChecksum canonical + deprecate ([#488](https://github.com/nfh-trust-labs/opencred/issues/488)) ([2dbdd6c](https://github.com/nfh-trust-labs/opencred/commit/2dbdd6cb9441d8632fece41328760453a94a9d78))
* **security:** bump deps to address HIGH/CRITICAL CVEs + fix Dockerfile ([#366](https://github.com/nfh-trust-labs/opencred/issues/366)) ([40c4935](https://github.com/nfh-trust-labs/opencred/commit/40c4935f0431c1c2a0647112e036d98204abd268))
* **server,desktop:** eliminate five independent validatorInstance singletons ([#485](https://github.com/nfh-trust-labs/opencred/issues/485)) ([830d745](https://github.com/nfh-trust-labs/opencred/commit/830d745d22d8ed71a5cdd1f08d9acd40590d512c))
* **server:** add EDUCATION_SUBJECT alias and use devModeNoAuth in smoke tests ([#351](https://github.com/nfh-trust-labs/opencred/issues/351)) ([aadcc30](https://github.com/nfh-trust-labs/opencred/commit/aadcc3047b0b458b189cd7827570bd4f409c0a77))
* **server:** add per-call timeouts to Cloud HSM signers ([#458](https://github.com/nfh-trust-labs/opencred/issues/458)) ([2d54b07](https://github.com/nfh-trust-labs/opencred/commit/2d54b07991d9f0aeb95e6f2d6ac8cfc1a846434f))
* **server:** emit PRD-canonical response fields (batch status, revocationHash) ([#461](https://github.com/nfh-trust-labs/opencred/issues/461)) ([d899cf4](https://github.com/nfh-trust-labs/opencred/commit/d899cf4a1a6359fd17c7f5354558fe5413b1f6fe))
* **server:** friendlier errors + JWT-aware credential packager ([#508](https://github.com/nfh-trust-labs/opencred/issues/508)) ([20bb528](https://github.com/nfh-trust-labs/opencred/commit/20bb528a81943eb7eff45fad0d7e7c6ada014d78))
* **server:** require API key by default, add explicit dev-mode opt-out ([#317](https://github.com/nfh-trust-labs/opencred/issues/317)) ([af27515](https://github.com/nfh-trust-labs/opencred/commit/af275156458558d57bc561f60b793a024dbc8e08))
* **shared,signing:** preserve error { cause } through CryptoError rethrows ([#457](https://github.com/nfh-trust-labs/opencred/issues/457)) ([98e8470](https://github.com/nfh-trust-labs/opencred/commit/98e84707ea1b4856c8f65f7680a9ca0be1074fa8))
* **shared,verification,dedi-client:** add bounds check to JWT payload parsing ([#382](https://github.com/nfh-trust-labs/opencred/issues/382)) ([a187f66](https://github.com/nfh-trust-labs/opencred/commit/a187f66cc8d23df3af80314b53e158d6628d1a77)), closes [#139](https://github.com/nfh-trust-labs/opencred/issues/139)
* **shared:** add kind discriminator + typed code enum to OpenCredError ([#462](https://github.com/nfh-trust-labs/opencred/issues/462)) ([145ca5f](https://github.com/nfh-trust-labs/opencred/commit/145ca5fdfe8cbd898a89597f005649e334994e5f))
* **shared:** add missing IPv4/IPv6 reserved ranges to isPrivateIP ([#352](https://github.com/nfh-trust-labs/opencred/issues/352)) ([c59d0e7](https://github.com/nfh-trust-labs/opencred/commit/c59d0e75d5d9d2fb6e03b05701a2d36afb8e6c4e))
* **shared:** add Result&lt;T, E&gt; tagged-union helper for response envelopes ([#465](https://github.com/nfh-trust-labs/opencred/issues/465)) ([2eb7844](https://github.com/nfh-trust-labs/opencred/commit/2eb7844b549c51f00c73bf94bd8de3c19347e09d))
* **shared:** close IPv4-mapped IPv6 SSRF bypass ([#277](https://github.com/nfh-trust-labs/opencred/issues/277)) ([bd8ece7](https://github.com/nfh-trust-labs/opencred/commit/bd8ece74d41559559b0fe740ac8a1cd7524fef98))
* **shared:** require CORS_ORIGIN in production ([#495](https://github.com/nfh-trust-labs/opencred/issues/495)) ([d36d526](https://github.com/nfh-trust-labs/opencred/commit/d36d5261f6f3d4aa18f571d69faa403a5e14c42a))
* **shared:** sanitize OpenCredError HTTP output to prevent path/stack leaks ([#350](https://github.com/nfh-trust-labs/opencred/issues/350)) ([afe6a64](https://github.com/nfh-trust-labs/opencred/commit/afe6a64fec056ebd2f4e8fea8ebcad2edb4c3edb)), closes [#336](https://github.com/nfh-trust-labs/opencred/issues/336)
* **shared:** treat DNS AAAA lookup failures as fail-closed for SSRF ([#379](https://github.com/nfh-trust-labs/opencred/issues/379)) ([4b8bb6f](https://github.com/nfh-trust-labs/opencred/commit/4b8bb6fccf027773b0a2ce11e675d1ea4e5e39bd)), closes [#140](https://github.com/nfh-trust-labs/opencred/issues/140)
* **signing,desktop:** cross-platform native module loading + CI build pipeline ([#292](https://github.com/nfh-trust-labs/opencred/issues/292)) ([dbe1996](https://github.com/nfh-trust-labs/opencred/commit/dbe1996881a5205b4b0ccb583075e182fb1e2269))
* **signing,desktop:** wire native addon build into build pipeline and CI ([#220](https://github.com/nfh-trust-labs/opencred/issues/220)) ([1db1858](https://github.com/nfh-trust-labs/opencred/commit/1db1858118d0034e9e5e1861aedb3a820592d16e))
* **signing:** log native addon load errors + surface cause in CryptoError ([#456](https://github.com/nfh-trust-labs/opencred/issues/456)) ([223e8a0](https://github.com/nfh-trust-labs/opencred/commit/223e8a083423b0a75aab5f719358bf95248dd624))
* **signing:** log warnings for PKCS[#11](https://github.com/nfh-trust-labs/opencred/issues/11) key enumeration and cleanup errors ([#394](https://github.com/nfh-trust-labs/opencred/issues/394)) ([d651468](https://github.com/nfh-trust-labs/opencred/commit/d651468965281e23b7006f9d3d4cf51ac4a2a945)), closes [#167](https://github.com/nfh-trust-labs/opencred/issues/167) [#168](https://github.com/nfh-trust-labs/opencred/issues/168)
* **signing:** use VC-JWT as default proof format in local signing flow ([#232](https://github.com/nfh-trust-labs/opencred/issues/232)) ([d8e2c26](https://github.com/nfh-trust-labs/opencred/commit/d8e2c26a13f89d94806eca739350f3b62ebf68ce))
* **signing:** validate hex characters and check sscanf return in Windows CNG addon ([#357](https://github.com/nfh-trust-labs/opencred/issues/357)) ([939183b](https://github.com/nfh-trust-labs/opencred/commit/939183b318930dbc62638901fe506a2d676b4450)), closes [#327](https://github.com/nfh-trust-labs/opencred/issues/327)
* **vc-core,verification,delegation:** URI validation, strict dates, VC-JWT cross-validation ([d954da3](https://github.com/nfh-trust-labs/opencred/commit/d954da3235e0f234a0f951ab8edd8a0bf2781408))
* **vc-core:** add issuer URI and date format validation to CredentialBuilder setters ([#378](https://github.com/nfh-trust-labs/opencred/issues/378)) ([8acfaa2](https://github.com/nfh-trust-labs/opencred/commit/8acfaa22a741c5430fdc4cf29b49768d88e10def)), closes [#141](https://github.com/nfh-trust-labs/opencred/issues/141) [#142](https://github.com/nfh-trust-labs/opencred/issues/142)
* **vc-core:** copy bundled JSON-LD contexts to dist and use real W3C VC v2 context ([#50](https://github.com/nfh-trust-labs/opencred/issues/50)) ([ed6e7d1](https://github.com/nfh-trust-labs/opencred/commit/ed6e7d1c08c73681e9490905aea9d6e633893605))
* **verification,server:** bitstring fetch timeout + KMS keepAlive/retry ([#486](https://github.com/nfh-trust-labs/opencred/issues/486)) ([9add4d1](https://github.com/nfh-trust-labs/opencred/commit/9add4d1214d567040ceb3e3e8cc4b0eae749425e))
* **verification:** add algorithm whitelist and DM 2.0 payload support ([91655a4](https://github.com/nfh-trust-labs/opencred/commit/91655a425e204c05e34ac036cf5819f98b4b656f))
* **verification:** add digitalSignature keyUsage check on X.509 leaf cert ([#361](https://github.com/nfh-trust-labs/opencred/issues/361)) ([bba0139](https://github.com/nfh-trust-labs/opencred/commit/bba0139b9d28351db8d0668897e95e8f6b6b571c)), closes [#326](https://github.com/nfh-trust-labs/opencred/issues/326)
* **verification:** add KB-JWT verification and vct claim validation for SD-JWT VC ([6633679](https://github.com/nfh-trust-labs/opencred/commit/6633679599a168c5226d3e7103b501bf4882c6d2)), closes [#129](https://github.com/nfh-trust-labs/opencred/issues/129) [#130](https://github.com/nfh-trust-labs/opencred/issues/130)
* **verification:** add P-384 support to publicKeyFromMultibase ([#454](https://github.com/nfh-trust-labs/opencred/issues/454)) ([4554fa5](https://github.com/nfh-trust-labs/opencred/commit/4554fa53f2bc7d25715b8e6da7afc9279bb9e4c3))
* **verification:** close JWK-fragment bypass and add X.509 trust anchor ([#320](https://github.com/nfh-trust-labs/opencred/issues/320)) ([6af0d56](https://github.com/nfh-trust-labs/opencred/commit/6af0d564bcf6dd1ff9cd9e9ef9ee5a8cd5811e81))
* **verification:** enforce algorithm allowlist in jws-proof verification ([#346](https://github.com/nfh-trust-labs/opencred/issues/346)) ([4c1f367](https://github.com/nfh-trust-labs/opencred/commit/4c1f3670f7b9dd45e668cff39ddcb8789f101141)), closes [#328](https://github.com/nfh-trust-labs/opencred/issues/328)
* **verification:** invoke crossValidateVcJwtClaims on VC-JWT verify ([#451](https://github.com/nfh-trust-labs/opencred/issues/451)) ([ac51128](https://github.com/nfh-trust-labs/opencred/commit/ac51128c8beccf3918ff6635c8350f3739ec618e))
* **verification:** pin resolved IP to prevent DNS rebinding SSRF ([d05f940](https://github.com/nfh-trust-labs/opencred/commit/d05f9405bb26174d8fe74d5fef6e409d714b3406))
* **verification:** resolve JWK-fragment verificationMethod in Data Integrity proof ([622f776](https://github.com/nfh-trust-labs/opencred/commit/622f77666a1f53ce2259eda950bb13cc4e570575))
* **verification:** SD-JWT VC recursive digests + array disclosures + KB options ([#463](https://github.com/nfh-trust-labs/opencred/issues/463)) ([da7131a](https://github.com/nfh-trust-labs/opencred/commit/da7131af94dd16e772c216564fe1b32d23fa5cd3))
* **verification:** unify revocation hash with credentialStatus.id ([#467](https://github.com/nfh-trust-labs/opencred/issues/467)) ([#484](https://github.com/nfh-trust-labs/opencred/issues/484)) ([b3e2e13](https://github.com/nfh-trust-labs/opencred/commit/b3e2e13614e93c63f386af1befa60859e41c87d9))
* **web:** add rewrite rule for nginx proxy_pass with variable ([78d102d](https://github.com/nfh-trust-labs/opencred/commit/78d102db2bc09c09da0e7ef9828ebe6c6f76e5ab))
* **web:** append download anchor to DOM for correct file extensions ([3f1511d](https://github.com/nfh-trust-labs/opencred/commit/3f1511d6e8c696a65e7c358c75f026e448ad3ac2))
* **web:** clean up revocation and onboarding UI ([#210](https://github.com/nfh-trust-labs/opencred/issues/210)) ([9d02c85](https://github.com/nfh-trust-labs/opencred/commit/9d02c852f8b16136b0a5558b6009e1bad9233e4d))
* **web:** convert PKCS[#1](https://github.com/nfh-trust-labs/opencred/issues/1) to PKCS[#8](https://github.com/nfh-trust-labs/opencred/issues/8) PEM in PFX import ([#211](https://github.com/nfh-trust-labs/opencred/issues/211)) ([87bf12b](https://github.com/nfh-trust-labs/opencred/commit/87bf12b24b7e804e33baf2f21fb82aef7b47e0ce))
* **web:** fix nginx proxy DNS resolution and API routing ([ee3a351](https://github.com/nfh-trust-labs/opencred/commit/ee3a351cb363f3369e0e7f84b27b23579dd34b17))
* **web:** fix nginx proxy for Railway private networking ([5a23aac](https://github.com/nfh-trust-labs/opencred/commit/5a23aac459a489bbfd576372770602db8fb5dfeb))
* **web:** forward Authorization header through nginx proxy ([848204f](https://github.com/nfh-trust-labs/opencred/commit/848204fbf852c1d50fc9f54ac53b37c89b2afb3f))
* **web:** handle IPv6 DNS resolver in nginx proxy config ([e12f79f](https://github.com/nfh-trust-labs/opencred/commit/e12f79f7d2fa1ca40dd56301935a19ace9e991a4))
* **web:** handle non-JSON API errors and update integration tests ([#206](https://github.com/nfh-trust-labs/opencred/issues/206)) ([5facf96](https://github.com/nfh-trust-labs/opencred/commit/5facf96d44b518612ee92d370a071cade44431b0))
* **web:** strip whitespace from auth token before sending ([5ec1904](https://github.com/nfh-trust-labs/opencred/commit/5ec1904035d2eb5498bfaf85fa09bf859e763d19))
* **web:** use ref-based file input trigger for key upload button ([2df80f7](https://github.com/nfh-trust-labs/opencred/commit/2df80f76ec45d075346842c8542487ee6f8c47a7))
* **web:** use regex location for proper path rewrite in proxy ([d9ff745](https://github.com/nfh-trust-labs/opencred/commit/d9ff7454f47d5b8926b8d268a8bf07e8305ff48b))
* **web:** use schema name as PDF credential type fallback ([#213](https://github.com/nfh-trust-labs/opencred/issues/213)) ([71f60ef](https://github.com/nfh-trust-labs/opencred/commit/71f60ef5cb3cfe33bc74eee6f8b16258ae22818a))


### Performance Improvements

* **dedi-client:** cache DeDi SSRF DNS lookups with a 30s TTL ([#490](https://github.com/nfh-trust-labs/opencred/issues/490)) ([699d777](https://github.com/nfh-trust-labs/opencred/commit/699d777695481cdd0b29c16357e7638cbfab10ca))
* hoist applyMapping Set + truncate rejectKeyMaterial PEM scan ([#489](https://github.com/nfh-trust-labs/opencred/issues/489)) ([f8fa0a1](https://github.com/nfh-trust-labs/opencred/commit/f8fa0a139496e25695d39e7b7e0ed02b06a9c12d))

## [Unreleased]

## [1.1.0] - 2026-05-05

### Added

- **Public release distribution** — Docker image now published to `ghcr.io/nfh-trust-labs/opencred/opencred-server` (public, no auth). Desktop installers mirrored to `nfh-trust-labs/opencred-releases` with SHA256SUMS for integrity verification. Source repo stays private; binaries are public so end users can install without GHCR / repo authentication. (#514)
- **`POST /v1/dedi/namespace/ensure`** — server endpoint to create a DeDi namespace and its four registries (`vc-revocation-registry`, `public_key_registry`, `schema_registry`, `context_registry`) on demand. Bootcamp attendees no longer need to pre-provision the namespace before booting the container. (#509)
- **Inline custom JSON Schema in issue requests** — `POST /v1/credentials/issue` now accepts a `credentialSchema.schema` field with an inline JSON Schema, validated by Ajv at request time. Previously schemas had to be pre-registered in the schema engine. (#506)
- **DeDi public-key registry routes** — `POST /v1/dedi/keys/publish` and resolution endpoints for self-published `did:web` keys. (#506)
- **JWT-aware credential packager** — PDF + QR packaging now decodes `vc-jwt` and `sd-jwt-vc` compact tokens for display while preserving the byte-exact token in the QR payload. (#508)
- **Bootcamp guide** — `docs/bootcamp/local-docker.md` and `docs/bootcamp/gcp-vm.md` ship a 3-hour, hands-on facilitator-led path through the Docker image. Includes a Postman collection covering every API endpoint. (#512)

### Changed

- **`docker-compose.yml` defaults to the public GHCR image.** Build-from-source remains available by uncommenting the `build:` block. (#514)
- **electron-updater polls `opencred-releases` for auto-updates** instead of the private source repo, so installed Desktop clients can fetch updates without authenticating. (#514)
- **400 INVALID_JSON for malformed bodies** — server now parses JSON at the route layer and returns a clean error response instead of letting Hono's default handler 500. (#511)
- **Discriminated `CredentialInput` union** for the packager and QR generator, replacing the previous `T | string` overload. Type system now reflects the JSON-LD-vs-compact-token split honestly. (#510)

### Fixed

- **Friendlier error messages** — issuance and verification surfaces now return actionable messages instead of internal stack traces for common failure modes (missing signing key, malformed VC, schema mismatch). (#508)
- **Bitstring revocation fetch timeout + KMS keepAlive/retry** — verification was hanging indefinitely on slow `credentialStatus` URLs and dropping under KMS connection pressure. (#486)
- **Five independent `validatorInstance` singletons collapsed to one.** Previously each surface (server routes, desktop preload, etc.) constructed its own Ajv instance, doubling-counting cache misses and burning startup memory. (#485)
- **Revocation hash unified with `credentialStatus.id`** — verification was computing the hash from a different field than issuance was writing it to, so DeDi-published revocations weren't being detected. (#467, #484)
- **`computeChecksum` made canonical** — JSON-LD context checksums now use a stable serialization, so cache lookups don't churn on whitespace differences. (#488)
- **Atomic `DeDiTokenManager.setTokens`** — partial writes during token refresh could leave the manager with an access token but no refresh token, requiring a server restart to recover. (#487)
- **`CORS_ORIGIN` required in production** — the server was silently allowing all origins when the var was unset, which is fine for local dev but unsafe in deployment. Production now refuses to start without it. (#495)

### Infrastructure

- **Audit remediation** — 2026-04-16 security audit findings closed: 3 HIGH, 5 MED, 4 LOW, 4 INFO. Highlights include credential-payload TTL purge, structured logger sanitization, error-handler PEM stripping. (#426)
- **CSV parsing extracted to `@opencred/batch-core`** — desktop bulk-issuance and server CLI now share one streaming parser. (#496)
- **PKCS#11 warnings routed through structured logger** — was previously console.log noise. (#494)
- **DeDi DNS cache** — 30s TTL cache to avoid repeated SSRF protection lookups on hot paths. (#490)
- **`bulkUpload` routed through shared `doFetch`** — uniform retry / SSRF / timeout behavior for all DeDi traffic. (#493)
- **Empty `CSC_*` env vars unset before electron-builder** — was causing CSC_LINK="" to resolve to cwd and fail with "apps/desktop not a file". (#503)
- **Windows temporarily dropped from the desktop release matrix** — `@electron/rebuild` hangs for 20+ min on the pnpm symlinked tree on NTFS. Native compile itself works (~48s); only the Electron-ABI rebuild step hangs. (#502)

## [1.0.2] - 2026-04-21

### Fixed

- **"App is damaged" on macOS** — v1.0.1 shipped with
  `forceCodeSigning: true` and no `MAC_CSC_LINK` configured in the
  repo secrets, causing `electron-builder` to fall through to an
  ad-hoc signature. macOS rejects that as a broken signature with
  no user-bypass path. Flipped `forceCodeSigning: false` and
  reworked the release workflow so missing signing secrets now
  produce cleanly unsigned artefacts. Users get the standard
  "unrecognised developer" prompt (right-click → Open) instead of
  "app is damaged". See [docs/desktop/release-signing.md](docs/desktop/release-signing.md)
  for the unsigned-state UX and the roadmap to signed releases (#498).

### Infrastructure

- **Preflight for signing secrets** — `.github/workflows/desktop-release.yml`
  now emits `sign_mac` / `sign_win` job outputs from a preflight
  check. All secrets present → signed + notarised build with full
  `codesign`/`spctl`/`stapler` + `Authenticode` verification.
  All absent → unsigned build with a warning. Partial → hard
  fail. No further workflow change is required when certs are
  eventually configured (#498).

### Docs

- **`docs/desktop/release-signing.md`** — new canonical record of
  the current unsigned state, auto-update implications, target
  state, and the exact steps to restore signing once Apple
  Developer Program + Windows Authenticode certs are acquired
  (tracked in #497).
- **`docs/desktop/installation.md`** — replaced the incorrect
  "signed + notarised" claim with the right-click → Open
  walkthrough for macOS, SmartScreen "Run anyway" workaround for
  Windows, and `xattr -cr` escape hatch for users still stuck on
  the v1.0.1 broken bundle.

## [1.0.1] - 2026-04-14

### Fixed

- **Desktop release pipeline** — `desktop-release.yml` had invalid
  `secrets: inherit` under `on.workflow_call`, making every run fail at
  parse time with no artifacts published. Fixed and added
  `workflow_dispatch` with a `tag` input so historical tags can be
  rebuilt on demand (#402).
- **Native addon rebuild on Node 20** — `@electron/rebuild@3.6.1`
  transitively pulls `node-gyp@9.4.1`, whose deprecated
  `util.promisify` patterns throw `TypeError [ERR_INVALID_ARG_TYPE]` on
  Node 20, blocking `pkcs11js` rebuild during `electron-builder
  --publish`. Added a pnpm override forcing `node-gyp@>=10` (#404).
- **release-please target branch** — defaulted to `main` (which has no
  config), now explicitly targets `new-opencred-dev` (#406).

### Chores

- Consolidated `docs/self-hosted/` into `docs/docker/`; audited every
  Docker doc against source code and fixed numerous inaccuracies
  (#399).
- Added `.claude/worktrees/`, `.claude/settings.local.json`, and
  `.pnpm-store/` to `.gitignore`; removed a stray worktree submodule
  left over from a past agent session (#401).

## [1.0.0] - unreleased

Tagged in git but never published as a GitHub Release. Superseded by
1.0.1, which includes the CI fixes needed to build release artifacts.

### Added — v1 schema library overhaul

- **Curated catalogue of ~33 credentials** sourced from existing standards
  rather than hand-rolled placeholders. The library now ships:
  - **9 OpenCred-defined schemas** authored against W3C VC 2.0 with sector
    anchors:
    - `electricity/v1` (Green Button / ESPI / Beckn)
    - `salary-slip/v1` (Schema.org Invoice)
    - `immunization/v1` (HL7 FHIR R4 Immunization + CVX/SNOMED)
    - `prescription/v1` (HL7 FHIR R4 MedicationRequest + RxNorm)
    - `test-result/v1` (HL7 FHIR R4 DiagnosticReport + LOINC)
    - `insurance-policy/v1` (generic, `policyType` discriminator)
    - `functional-identity/v1` (Schema.org `hasOccupation`, optional ISCO-08)
    - `employment-offer-letter/v1` (Schema.org `JobPosting` + `EmployeeRole`)
    - `business-entity/v1` (vLEI field shape, W3C VC envelope)
  - **24 referenced upstream schemas** fetched and SHA-256 verified at
    build time, bundled into the desktop app + Docker image:
    - Open Badges 3.0 (1EdTech)
    - DIF Verified Person v1.0, DIF Proof of Age v1.0
    - 21 W3C CCG Traceability Vocabulary credentials including Commercial
      Invoice, Bill of Lading, USMCA Certification of Origin, Purchase
      Order, Packing List, IATA Air Waybill, Importer Security Filing,
      Mill Test Report, SBOM, GAP Inspection, Phytosanitary, Oil and Gas
      Product, and others
- **Build-time fetch + verify pipeline** (`packages/schema-engine/scripts/fetch-and-embed-schemas.mjs`)
  pinned to a specific `opencred-vc-schemas` commit. Runs at release build,
  hard-fails on any tamper / hash mismatch / unreachable URL / non-allowlisted
  host. The runtime never fetches remote schemas — same security model as
  the existing JSON-LD context bundling.
- **`SchemaDefinition.source`** — every registered schema carries
  `{kind: "defined" | "referenced", upstreamUrl, upstreamOwner, upstreamLicense}`
  provenance. Surfaced in the desktop schema selector and in the server
  `GET /schemas` API response.
- **`canonicalJsonSha256`** in `@opencred/shared` — recursive sorted-key
  JSON SHA-256 used as the contract between the `opencred-vc-schemas`
  hash-pinner script and the monorepo's build-time verifier. Both must
  produce bit-identical output for the same input.
- **`TRACEABILITY_V1_CONTEXT`**, **`OPEN_BADGES_V3_CONTEXT`**, and 8
  OpenCred-defined context URL constants in `@opencred/vc-core/types`,
  bundled in `BUNDLED_CONTEXTS` so the document loader resolves every v1
  credential's context offline.
- **Data-driven default SVG template** rendering — `packages/templates`
  no longer needs a per-schema SVG file for v1; the default template
  renders generic VC fields for all 33 credentials. Schema-specific
  branded SVGs are a v1.1 follow-up.
- **`formatSchemaLabel(id)` helper** in
  `apps/desktop/src/renderer/utils/schema-label.ts` — derives a
  human-readable label from any v1 schema ID (`electricity/v1` →
  "Electricity v1", `traceability/commercial-invoice/v1` →
  "Commercial Invoice v1", `dif/verified-person/v1` →
  "Verified Person v1"). Replaces 4 copies of the hardcoded
  `SCHEMA_LABELS` map across the renderer components.

### Changed

- `SchemaDefinition.checksum` is now **required** (was optional). Bundled
  registry entries always carry their canonical hash.
- `Validator.validateCredentialSubject(schemaId, subject)` now extracts the
  `properties.credentialSubject` sub-schema when the registered schema is a
  full W3C VC 2.0 envelope (the v1 catalogue style), and falls back to
  validating against the whole schema for any legacy subject-only schemas.
  This unblocks subject validation against the new envelope-shaped schemas
  without changing the public API.
- `apps/server/src/routes/schemas.ts`: `GET /schemas` and `GET /schemas/:id`
  now return `version` and `source` fields per credential.

### Removed

- **5 generic placeholder schemas** are deleted with no migration aliases:

  | Old | Replaced by |
  |---|---|
  | `education/v1` | `open-badges/v3` (Open Badges 3.0 — adopted upstream) |
  | `employment/v1` | `employment-offer-letter/v1` (authored, Schema.org-anchored) |
  | `identity/v1` | `dif/verified-person/v1` + `dif/proof-of-age/v1` (DIF — adopted upstream) |
  | `health/v1` | `immunization/v1` + `prescription/v1` + `test-result/v1` (authored, FHIR-anchored) |
  | `business/v1` | `business-entity/v1` (authored, vLEI field shape in W3C VC envelope) |

  Rationale: the old schemas were 4-field placeholders that weren't usable
  in production. Replacements are either adopted upstream from mature
  standards (Open Badges 3.0, DIF, W3C CCG Traceability) or authored as
  thin W3C VC 2.0 wrappers around established domain data models (FHIR,
  LOINC, Schema.org, vLEI).

  Issued credentials in the wild that reference the old schema URLs at
  `raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/<old>/v1/schema.json`
  continue to validate at the URL level — those files still exist in the
  schemas repo. They are simply no longer registered in the bundled
  catalogue, the registry, or the desktop UI.

- **`packages/schema-engine/src/updater.ts`** — the runtime "check for
  schema updates" download path is deleted entirely. The new model is
  bundled-at-release-only; runtime never fetches remote schemas. The
  `checkForSchemaUpdates`, `downloadSchema`, `loadCachedSchemas`,
  `saveSchemasToCache`, and `validateSchemaChecksum` exports are gone.
- **`apps/desktop/src/main/schema-updater.ts`** — the desktop startup
  hook that called the deleted updater module. Removed along with its
  invocation in `apps/desktop/src/main/index.ts`.
- **5 NFH JSON-LD context constants** (`NFH_EDUCATION_V1_CONTEXT` etc.)
  and their bundled JSON files in `packages/vc-core/src/contexts/`.
- The 5 schema-specific SVG template files in
  `packages/templates/src/templates/` (education, employment, identity,
  health, business). Default template handles all v1 credentials.

### Fixed

- The schema-engine `Validator` now correctly handles W3C VC 2.0 envelope
  schemas. Previously, `validateCredentialSubject` compiled the entire
  schema and validated only the credentialSubject against it, which
  always failed for envelope schemas because they require top-level
  `@context`, `id`, `type`, `issuer`, etc. The validator now extracts
  the `credentialSubject` sub-schema (and its `$defs` / `definitions`)
  before compiling.

### Known issues

- E2E specs (`apps/desktop/e2e/*.spec.ts`) still reference the old schema
  IDs and need to be rewritten. They require a full electron app build and
  the schema selector UI to exercise the new IDs end-to-end.
- The `OPENCRED_SCHEMAS_SHA` constant in `packages/vc-core/src/types.ts`
  must be regenerated manually whenever
  `packages/schema-engine/scripts/schema-sources.json` `commit` is bumped.
  Auto-generation from the manifest is a v1.1 follow-up.
- The `https://w3id.org/traceability/v1` context is bundled manually
  (committed at `packages/vc-core/src/contexts/traceability-v1.json`)
  rather than fetched through the build pipeline. Should be migrated
  to the manifest in v1.1 so it gets the same hash-pinning treatment.
