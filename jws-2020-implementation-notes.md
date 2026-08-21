# JWS-2020 proof format — implementation notes

*2026-08-21 · branch `claude/jws-support-484508` · commit `1afcce58` (not yet pushed)*
*Context: DigiLocker integration request forwarded by Srikanth (Fwd: FW: Re:Digilocker Integration fixes, 2026-08-20)*

## What was built

A fourth issuance proof format, `proofFormat: "jws-2020"`, producing the embedded-proof
shape DigiLocker asked for:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "...", "https://w3id.org/security/suites/jws-2020/v1"],
  "type": ["VerifiableCredential", "..."],
  "credentialSubject": { ... },
  "proof": {
    "type": "JsonWebSignature2020",
    "created": "2026-08-21T…",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:web:…#key-0",
    "jws": "<b64(header)>..<b64(signature)>"
  }
}
```

- Detached RFC 7797 JWS: header `{"alg": "ES256", "b64": false, "crit": ["b64"]}`,
  empty payload segment.
- Signing input: `ASCII(b64(header) + ".") || SHA-256(URDNA2015(proof config)) || SHA-256(URDNA2015(document))`
  — the spec-correct JsonWebSignature2020 construction, reusing the existing
  strict-mode canonicalization infrastructure.
- All key algorithms supported: P-256 (ES256), P-384 (ES384), Ed25519 (EdDSA), RSA (PS256).
- The JWS-2020 suite context is bundled (no runtime fetch) and appended to
  `@context` automatically at issuance.
- Verification: `verifyJws2020Proof` in `@opencred/verification`, dispatched by proof
  shape (`proof.jws` string vs the vc-jwt envelope's `proof.jwt`); strict DID-document
  key resolution, alg allowlist (rejects `alg:none`, HMAC, unknown crit params).

## Surfaces

`/v1/credentials/issue`, `/v1/credentials/batch`, CLI `--proof-format`, desktop UI
(More options → Proof Format), verify endpoint/SDK, PDF packaging (Digital Signature
section shows alg from the detached header).

Bug fixed along the way: the schema's JSON-LD context was only attached when
`proofFormat === "data-integrity"` (route, desktop local-signing-flow, desktop
ipc-handlers) — jws-2020 canonicalizes too, so the gate now covers both. Without it,
issuance failed with a safe-mode canonicalization error.

## Test/validation status

- `pnpm build` exit 0; lint + prettier clean.
- Full suite: 2943 passed / 13 skipped (161 files). New: 15 crypto tests
  (round-trip all 4 algorithms, tamper, two-phase, context handling), 16 verification
  tests (verify/tamper/header attacks/dispatch), desktop router test, and the
  multi-format interop test now covers 4 formats end-to-end through the real API.

## Deliberate deviations from DigiLocker's email (to raise with them)

1. **No `typ: "JWT"` in the header.** Their proposed header includes it; a detached
   JWS proof is not a JWT and the JWS2020 suite omits `typ`. One-line change if they
   insist — but their verifier should be checked first.
2. **Their sample `jws` cannot verify.** It reuses the signature from the current
   vc-jwt with the payload deleted; a real detached signature must be computed under
   the new header. Ours is.
3. **`@context` gains the jws-2020 suite URL.** Their sample doesn't show it, but
   without it the proof terms aren't defined under canonicalization. Standard
   implementations (transmute, digitalbazaar) do the same.
4. **Signing input needs their confirmation.** We implemented spec-correct
   JsonWebSignature2020 (URDNA2015 + SHA-256 verify data). If DigiLocker's verifier
   signs over raw JSON bytes instead, nothing will interoperate — get a known-good
   sample from them or have them verify one of ours.

## Follow-ups (not in this PR)

- Batch precompute optimization for jws-2020 (data-integrity has a shared
  proof-config hash + single `created` per batch; jws-2020 currently prepares
  per-row — correct, slower on large batches).
- Nightly E2E matrix (`e2e/`) does not yet exercise jws-2020 (noted in
  `docs/concepts/support-matrix.md`).
- Batch engine has no schema-context plumbing for ANY canonicalizing format
  (pre-existing) — batch jws-2020/data-integrity only works when subject terms
  resolve in the credentials/v2 context.
- `credentialSchema` removal / hosted IES context URL (item 1 of DigiLocker's list)
  is issuer-side request configuration, not a code change — Tata Power should set the
  hosted context and omit/set `credentialSchemaUrl` accordingly. If they want the
  `india-energy-stack.github.io` context bundled, that's a schema-engine pin update.
- Reply email to Srikanth/DigiLocker still to be sent (draft on request).
