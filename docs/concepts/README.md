# Concepts

Background reading for anyone working with OpenCred. If you are already familiar with verifiable credentials, decentralized identifiers, and credential status models, you can skip ahead to the [Desktop](../desktop/README.md) or [Docker](../docker/README.md) operator guides.

## Pages in this section

* [Verifiable Credentials](verifiable-credentials.md) — what a Verifiable Credential is, how the W3C VC Data Model 2.0 is structured, the proof formats OpenCred supports, and what `credentialStatus` means.
* [DIDs (Decentralized Identifiers)](dids.md) — the three DID methods OpenCred uses (`did:key`, `did:jwk`, `did:web`), how they encode public keys, and how to choose between them.
* [Trust chains](trust-chains.md) — the three issuer types OpenCred supports (Issuer with DSC, Issuer Seeking DSC, Self-Published Keys), and how trust flows from a credential signature back to a root anchor.
* [Credential support matrix](support-matrix.md) — every valid algorithm × proof format × key source × DID method combination, the exclusions and why, and what the nightly E2E matrix proves.
* [Revocation](revocation.md) — how OpenCred handles revocation through DeDi-backed hash lookup, and how `credentialStatus` is computed and verified.

## How these concepts fit together

A typical OpenCred credential answers four questions for a verifier:

1. **Is the data intact?** — proven by the cryptographic [proof](verifiable-credentials.md#proof-formats).
2. **Whose key signed it?** — answered by resolving the [issuer DID](dids.md).
3. **Should I trust that key?** — answered by walking the [trust chain](trust-chains.md).
4. **Is it still valid?** — answered by checking validity dates and the [revocation status](revocation.md).

OpenCred enforces all four checks during verification (see `packages/verification/src/verifier.ts`).
