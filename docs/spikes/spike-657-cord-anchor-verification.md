# Spike 657 — Independent on-chain verification of the CORD anchor

**Status:** **Spike (recommendation only — no production code in this PR).**
**Parent issue:** [#657 — verify CORD anchor on-chain (today advisory-only)](https://github.com/nfh-trust-labs/opencred/issues/657)
**Spike protocol:** `CLAUDE.md` → "Spike Protocol"
**Author:** Spike branch `spike/657-cord-anchor-verification`
**Date:** 2026-06-08

## TL;DR

Today OpenCred surfaces DeDi's `proof` block **advisory-only** — `checkRegistryAnchor`
(`packages/verification/src/checks.ts`) confirms a proof exists and that
`proof.creator_did === issuerDid`, but it **never confirms the digest is actually on-chain**, and it
never flips the headline `verified` boolean. A compromised or misconfigured DeDi node could return a
fabricated `proof` (arbitrary `digest` / `creator_did`).

**Findings:** independent on-chain digest verification is **concretely implementable today** —
`@cord.network/sdk` (on `@polkadot/api`) exposes `api.query.entries.registryEntries(id).digest`, which
maps cleanly onto our `DeDiProof` fields. **But** a plain RPC query only buys **RPC-node-trusted**
assurance (it converts "trust DeDi's proof" into "trust a CORD RPC endpoint"), costs a heavy
`@polkadot/api` + WASM dependency, needs an operator-supplied `network_genesis → wss` map, and adds a
network dependency at verify time that conflicts with offline verification.

**Recommendation (in priority order):**

1. **Resolve the Option-B question with Dhiway/DeDi first** (one question): does `DediRecordProof2026`
   carry — or will it carry — a **verifiable signature** over the record with a resolvable
   `creator_did` key? If yes, verifying that signature is **by far the best fit** for OpenCred's
   offline, low-dependency posture and closes most of the attack surface with zero chain dependency.
2. **If B is unavailable, implement Option A as opt-in + degrade-to-advisory** behind a configured
   `VerifierConfig.cordRpcUrl` (a `network_genesis → endpoint` map). It must **never** turn a
   cryptographically valid VC into `verified: false` solely because a CORD node is unreachable, and
   it must **not** flip the headline `verified` until the trust model is settled — it only upgrades
   the *advisory* detail from "anchor reported by DeDi" to "anchor confirmed on-chain (RPC-trusted)".
3. **Ship the Option-C disclosure now regardless** — make the verifier UI honestly label the anchor as
   "reported by DeDi, not independently verified on-chain". Free, no new dependencies, corrects
   today's potential over-trust.
4. **Full trust-minimized (light-client) verification is out of scope** — no public CORD chain spec
   for `substrate-connect`/smoldot was found, and smoldot's weight + online requirement conflict with
   offline verification.

**No code lands in this spike PR.** It produces this doc + a recommendation; the Option-A/B decision
is gated on the Dhiway answer (Q1 below) and is the user/operator's call.

---

## 1. Problem statement

`DeDiProof` (`packages/dedi-client/src/api/types.ts`) carries `type` (`"DediRecordProof2026"`),
`namespace_did`, `creator_did`, `digest` (the on-chain hash of the record), `network_genesis` (the
anchoring network's genesis hash, may be `null`), and optional `registry_identifier` /
`record_identifier`.

`checkRegistryAnchor` (`packages/verification/src/checks.ts`, ~L613–660) currently:

1. passes silently when there is no `dediClient` / no verification method / 404 / 400;
2. returns `passed: false` (advisory) when the record has no proof block;
3. returns `passed: false` (advisory) when `proof.creator_did !== issuerDid`;
4. returns `passed: true` with an `Anchored on CORD…` detail when the proof is present and the creator
   matches.

It is **excluded from the headline-`verified` propagation** in `verifier.ts`. The in-code comment is
explicit: _"A compromised DeDi could fabricate a proof block; that's what a follow-up on-chain check
would harden against."_ This spike is that follow-up.

**Threat:** the proof block is DeDi-asserted metadata. A compromised/misconfigured DeDi node can
return a fabricated `proof` with no on-chain anchor. OpenCred currently trusts `proof.digest` was
genuinely committed on-chain with no independent confirmation.

---

## 2. Findings

### 2.1 The CORD JS/TS SDK

- **Umbrella package `@cord.network/sdk`** (npm; latest `0.9.6-x`, published 2025-10; pre-1.0, actively
  maintained). Source: [`github.com/dhiway/cord.js`](https://github.com/dhiway/cord.js).
- It is a scoped monorepo: `@cord.network/{network,types,config,identifier,entry,registry,entries,
  registries,namespace,augment-api,…}`. A **read-only digest lookup needs only** a small subset
  (`@cord.network/network` + `@cord.network/config` + `@cord.network/identifier` + `@cord.network/
  augment-api`), or raw `@polkadot/api` with the CORD type bundle.
- **Built on Polkadot/Substrate**: `@polkadot/api ^15.x`, `@polkadot/types`, `@polkadot/util-crypto`,
  `@polkadot/keyring`. Engine requirement **`node >= 20`** (OpenCred targets Node 20+, OK).

### 2.2 Packaging fit (Node + Electron + offline)

- **Node**: fine. The verifier runs in the desktop **main** process / Docker server (Node), not the
  renderer, so the Node path is the relevant one.
- **WASM (transitive)**: `@polkadot/util-crypto` → `@polkadot/wasm-crypto` (sr25519/ed25519/blake2 in
  WASM). The WASM is **base64-inlined in the npm package** — **not a runtime remote fetch**, so it
  satisfies OpenCred's "no remote fetch at runtime" supply-chain rule. It does add a WASM init step and
  the usual `@polkadot/*` asar/bundler friction in Electron (leave `@polkadot/*` unpacked or rely on
  the inlined variant). No new native `.node` addons.
- **Dependency weight**: significant — `@polkadot/api` + types + util + wasm-crypto is a large,
  fast-moving (still pre-1.0 for CORD) tree that duplicates crypto primitives we already have. This is
  the single biggest cost of Option A and materially enlarges our dependency attack surface and update
  treadmill.
- **ESM/CJS**: `@cord.network/sdk` ships dual; `@polkadot/api` v15 is ESM-first and a known source of
  interop friction in mixed toolchains. Workable but expect build/`vitest` config work.
- **Offline**: Option A introduces a **network dependency at verify time**, which conflicts with the
  desktop's offline-verification posture. Must degrade to advisory when offline/unreachable.

### 2.3 The digest → on-chain query shape (the strongest finding)

cord.js has first-class DeDi storage reads and stores exactly the `digest` we receive. From
`packages/entries/src/Entries.chain.ts` (branch `develop`):

```ts
// Existence
const encoded = await api.query.entries.registryEntries(registryEntryId); // Option<…>
if (encoded.isNone) return /* not on chain */;

// Decoded shape (decodeRegistryEntryDetailsFromChain):
//   digest:     chainRegistryEntry.digest.toHex()      // <-- compare to proof.digest
//   revoked:    chainRegistryEntry.revoked.valueOf()    // <-- independent on-chain revocation bit
//   creatorUri: `did:cord:3${encodeAddress(creator, 29)}` // <-- cross-check creator
//   registryUri: identifierToUri(hexToString(registryId))
```

A verifier would:

1. derive the raw chain id from `proof.record_identifier` via `uriToIdentifier()`;
2. read **`api.query.entries.registryEntries(id)`** → `Option<PalletEntriesRegistryEntryDetails>`;
3. if `isNone` → not on chain (fail / unknown); else **compare `chain.digest.toHex() === proof.digest`**
   (and optionally surface `chain.revoked` and the creator).

Parallel storage for registry- / namespace-scoped proofs: `api.query.registries.registryInfo(id)` and
`api.query.nameSpace.nameSpaces(id)` (both `Option<…>` with a `digest`).

**Shortcut**: `identifier/src/Identifier.ts → uriToEntryIdAndDigest()` parses
`entry:cord:<identifier>:<suffix>` into `{ identifier, digest: '0x'+suffix }` — so if DeDi's
`record_identifier` is a full `entry:cord:…:…` URI, the digest is recoverable from the URI string and
can be cross-checked against `proof.digest` **and** the on-chain value. (Whether `proof.record_identifier`
is exactly this URI form must be confirmed against a live DeDi response — see Q2.)

Sources (raw `develop`): `dhiway/cord.js` → `packages/{entries,registries,namespace,identifier}/src/*.chain.ts`.

### 2.4 Network selection via `network_genesis`

- **The genesis hash alone is NOT enough to reach the network.** `@polkadot/api` connects to an
  **explicit RPC URL** (`new WsProvider("wss://…")`); the SDK has no genesis-hash → endpoint discovery.
  So we must maintain our own **`{ network_genesis → wss URL }`** map (a trust-anchor config). The
  genesis hash's role is to **validate** we connected to the right chain (compare
  `api.genesisHash.toHex()` to `proof.network_genesis`), not to find it.
- **Known endpoints** (Dhiway runs CORD; runtimes Loom/Braid): testnet `wss://sparknet.cord.network`;
  DeDi demo `wss://registries.demo.cord.network`; local `ws://127.0.0.1:9944`. **No definitively
  documented public mainnet `wss` endpoint or any network's genesis hash was found** in public
  sources — capture them by connecting once and recording `api.genesisHash`. *Treat the mainnet
  endpoint + all genesis hashes as unknowns to confirm with the DeDi operator.*

### 2.5 Trust anchors for the CORD network itself

- A plain `@polkadot/api` RPC query **trusts the RPC node** — a malicious node can fabricate a matching
  `registryEntries(id)` digest or hide a revocation. **Option A converts "trust DeDi's proof" into
  "trust a CORD RPC endpoint."** That is a real improvement *only if the RPC node is a different, more
  trusted party than the DeDi instance*. In the target deployment where **one operator runs both DeDi
  and CORD** (`MEMORY.md → user_dedi_operator.md`), it may be the **same trust domain** → small
  security gain.
- **Trust-minimized verification** requires a **light client**: verify the finalized header chain
  (GRANDPA) + a Merkle **storage proof** (`api.rpc.state.getReadProof`) for the `registryEntries` key
  against the state root. Generic tooling exists (`@substrate/connect` + smoldot), **but no public CORD
  chain spec for substrate-connect was found**, and smoldot adds another WASM blob + a sync process
  with an online requirement — too heavy for an offline-friendly desktop verifier. **Out of scope.**

---

## 3. Options & trade-offs

| | How | Pros | Cons |
|---|---|---|---|
| **A — CORD RPC query** | `api.query.entries.registryEntries(uriToIdentifier(record_identifier)).digest === proof.digest`, behind a `network_genesis → wss` map; validate `api.genesisHash === proof.network_genesis`; degrade to advisory on any failure | Real on-chain confirmation; reuses cord.js's exact read+decode path; free independent **on-chain revocation** signal | Heavy `@polkadot/api`+WASM dependency (supply-chain, Electron bundling, ESM friction); **only RPC-node trust, not trust-minimized**; needs operator genesis→endpoint map (mainnet endpoint/genesis currently unknown); network dependency at verify time (bad for offline). Net gain modest when one operator runs both systems |
| **B — verify the DeDi proof signature** | If `DediRecordProof2026` is a signature suite, verify the signature over the record using `creator_did`'s published key | Cheapest, **fully offline**, no chain dependency; closes most of the attack surface | **Not currently possible**: the proof block we receive has **no `proofValue`/`jws`/signature field** and the suite is undocumented (not in the LF DeDi reference spec). Hinges on Dhiway defining/publishing the suite + key resolution (**Q1**) |
| **C — advisory + better disclosure** | Keep `checkRegistryAnchor` advisory; UI honestly labels "reported by DeDi, not independently verified on-chain"; visually separate "VC signature verified" from "registry attribution (advisory)" | Zero dependencies; no offline regression; corrects over-trust today | No added cryptographic assurance |

---

## 4. Recommendation

1. **Confirm Option B viability first (Q1).** DeDi's marketing claims records are "cryptographically
   signed … tamper-proof … verify without contacting the source," but the proof block we actually
   receive shows **no signature field**. If Dhiway confirms (or adds) a signature + resolvable
   `creator_did` key, **B is the best fit** and should be preferred over A.
2. **If B is unavailable, implement Option A as opt-in + degrade-to-advisory** (contract in §5). Never
   reject a cryptographically valid VC because a CORD node is unreachable; **do not flip headline
   `verified`** until the RPC-trust model is settled — only upgrade the advisory detail to
   "confirmed on-chain (RPC-trusted)". On a positive match, also surface the independent on-chain
   `revoked` bit.
3. **Ship the Option-C disclosure now** regardless of A/B — it's free and corrects today's over-trust.
   (Pairs naturally with the revocation-reason UI work in #658.)
4. **Light-client / trust-minimized verification: out of scope** (no CORD chain spec for
   substrate-connect; smoldot too heavy + online-only).

If the decision is "implement A", the remaining #657 acceptance items (the `checkRegistryAnchor` CORD
query, the verified/mismatch/timeout/no-proof unit tests, and the `VerifierConfig`/verify-sdk
`cordRpcUrl` option) land in a **separate implementation PR**, per the spike protocol.

---

## 5. Draft `VerifierConfig.cordRpcUrl` contract (for Option A)

```ts
interface VerifierConfig {
  // …existing…
  /**
   * Optional CORD on-chain anchor verification. When set, `checkRegistryAnchor`
   * confirms `proof.digest` against the on-chain `entries.registryEntries(id).digest`
   * for the matching network.
   *
   * Map keyed by `network_genesis` (hex) → CORD JSON-RPC websocket URL. Keyed by
   * genesis (not a single URL) because a verifier may see credentials anchored on
   * different CORD networks, and the genesis is what we validate the connection
   * against (`api.genesisHash === network_genesis`).
   *
   * Absent / no matching genesis / unreachable node / no `record_identifier`
   * ⇒ DEGRADE TO ADVISORY (the existing "anchor reported by DeDi, not confirmed"
   * path). Never turns a cryptographically valid VC into `verified: false`.
   * 10s timeout per the SSRF/availability policy used elsewhere.
   */
  cordRpcUrl?: Record<string /* network_genesis hex */, string /* wss:// URL */>;
}
```

Behavioural contract:

- **No `cordRpcUrl`** → current advisory behaviour, unchanged.
- **Match + digest equal** → stronger `passed: true` detail: `Confirmed on-chain (RPC) on network …`;
  optionally surface `revoked` from chain.
- **Match + digest mismatch** → `passed: false` (suspicion) — the DeDi proof disagrees with the chain.
- **Genesis mismatch on connect / unreachable / timeout / no `record_identifier`** → degrade to the
  existing advisory pass with a "could not confirm on-chain" detail.
- **Never** flips headline `verified` (gated on the trust-model decision).

---

## 6. Open questions / DeDi-team asks

- **Q1 (load-bearing, Option B):** Does `DediRecordProof2026` carry — or will it carry — a verifiable
  signature over the record, with a resolvable `creator_did` verification key? (If yes, prefer B over A.)
- **Q2:** What is the exact form of `proof.record_identifier` / `registry_identifier`? Are they the
  cord.js `entry:cord:…:<digest>` / `registry:cord:…` URIs (so `uriToIdentifier` /
  `uriToEntryIdAndDigest` drop in directly)?
- **Q3:** Confirm empirically that `proof.digest` equals the on-chain
  `api.query.entries.registryEntries(id).digest` — publish a record via the real DeDi, read the chain,
  diff. This is the load-bearing assumption of Option A.
- **Q4:** The CORD **mainnet** `wss` endpoint and the genesis hashes for each network in use — needed to
  build the `network_genesis → wss` map. (Not publicly documented.)

## 7. Acceptance-criteria mapping (#657)

- [x] Spike doc with CORD SDK packaging feasibility, digest→block RPC shape, recommended option, draft
  `VerifierConfig.cordRpcUrl` contract — **this document**.
- [ ] _(conditional on the Option-A decision)_ `checkRegistryAnchor` queries CORD; positive match →
  "verified on-chain" detail; query failure → advisory with "could not confirm on-chain".
- [ ] _(conditional)_ The check never turns a valid credential `verified: false` because the CORD node
  is unreachable.
- [ ] _(conditional)_ Unit tests: verified anchor, digest mismatch, CORD timeout (degrade), no proof.
- [ ] _(conditional)_ `VerifierConfig` + verify-sdk options extended with `cordRpcUrl?`, documented.

---

## Sources

- `dhiway/cord.js` (branch `develop`) — `packages/{entries,registries,namespace,identifier}/src/*.chain.ts`,
  `sdk/src/index.ts`, `demo/src/func-test.ts`; npm `@cord.network/{sdk,network,types}` manifests.
- `dhiway/cord` node README (Loom/Braid runtimes, `9944`, apps.cord.network).
- docs.dhiway.com CORD anchoring demo (`wss://sparknet.cord.network`).
- `@polkadot/api`, `@polkadot/util-crypto` → `@polkadot/wasm-crypto`; polkadot.js storage docs
  (`state_getReadProof`).
- `paritytech/substrate-connect`, `@substrate/smoldot-light` (light-client option, out of scope).
- LF Decentralized Trust `decentralized-directory-protocol` (DeDi reference) — proof/signature fields
  **absent** from the reference spec (Option-B uncertainty).
