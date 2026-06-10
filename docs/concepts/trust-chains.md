# Trust Chains

A **trust chain** is the path a verifier walks from a credential's signature back to a root they already trust. Different issuer onboarding paths produce different trust chains. OpenCred supports three issuer types, summarised below.

## The Three Issuer Types

| Type | Onboarding | DID method | Trust chain |
|---|---|---|---|
| **Type 1: Issuer with DSC** | Imports an existing Digital Signature Certificate (PFX/PEM, hardware token, or OS cert store) | `did:key` derived from the DSC's public key | VC signature → DSC → CSCA |
| **Type 2: Issuer Seeking DSC** | OpenCred's CA adapter facilitates a DSC request; once issued, the user becomes Type 1 | (none until DSC is obtained) | Same as Type 1 once a DSC is in hand |
| **Type 3: Self-Published Keys** | OpenCred generates an ECDSA P-256 keypair locally; the user publishes the DID document on their own domain | `did:web:<domain>` | VC signature → published key → did:web resolution → domain TLS |

> **Architecture note**: Type 3 used to be "OpenCred-Attested" — OpenCred would sign the issuer's public key with its own DSC. As of v2 (2026-03-25) that workflow was removed. The new Type 3 publishes via `did:web` so trust is anchored in the issuer's own domain TLS rather than in OpenCred. This eliminates OpenCred as a trust intermediary and simplifies the architecture. Type 3 issuance remains fully supported — only the attestation packages (`packages/key-attestation/`, `packages/domain-verification/`) were deleted; signing, did:web publication, and verification live on in `@opencred/crypto`, `@opencred/did`, and `@opencred/verification`.

## Type 1: Issuer with DSC

The strongest trust model. The issuer already holds a DSC issued by a recognised Country Signing Certificate Authority (CSCA) or equivalent. Examples: government agencies, large universities, regulated healthcare providers.

```
Holder/Verifier
    |
    | reads credential
    v
[Verifiable Credential] ── proof ──> [Issuer's DSC public key]
                                            |
                                            | DSC was signed by
                                            v
                                     [CSCA root certificate]
                                            ^
                                            |
                                  Verifier trusts the CSCA
```

How OpenCred handles it:

1. Desktop user opens **Settings** → **Import File**, **Hardware Token**, or **OS Certificate Store** and selects their key.
2. OpenCred extracts the certificate metadata (subject CN, issuer, validity, key algorithm) and derives a `did:key` from the public key.
3. The DSC chain can optionally be validated against a configured CSCA trust store at signing time. The chain check lives in `packages/verification/src/x509-chain-check.ts` (`checkX509Chain`).
4. The issuer signs each credential locally; the issuer's private key never leaves the machine.

Verifier trust chain: the verifier obtains the issuer DSC (currently via `did:key` decoding; X.509 chain inclusion in proofs is a future enhancement) and walks it to the configured CSCA root.

## Type 2: Issuer Seeking DSC

The issuer does not yet hold a DSC and wants OpenCred to help acquire one. OpenCred provides a **CA adapter** extension point (`packages/ca-adapter`) that lets a deployment integrate with one or more Certificate Authority APIs. Once the CA returns a DSC, the user imports it and becomes Type 1.

OpenCred deliberately does **not** custody the DSC or its private key during this flow. The CA returns the DSC directly to the user, who imports it just like any other Type 1 issuer. CA adapter implementations are configured per deployment.

## Type 3: Self-Published Keys (did:web)

The issuer does not have a DSC, cannot easily obtain one, but **does** control a domain. They want a chain of trust without depending on a centralised PKI.

```
Holder/Verifier
    |
    | reads credential
    v
[Verifiable Credential] ── proof ──> [Issuer's published public key]
                                            ^
                                            | extracted from
                                            |
                              [DID document at https://issuer.example/.well-known/did.json]
                                            ^
                                            | served over TLS via
                                            |
                                  [Issuer's domain TLS certificate]
                                            ^
                                            | issued by
                                            |
                                    [Public CA (e.g. Let's Encrypt)]
```

Trust is anchored in the issuer's TLS chain, which is what the verifier's HTTPS client already trusts. This aligns with patterns already used by some governments — for example, India's UIDAI publishes JWKS at `https://pehchaan.uidai.gov.in/.well-known/jwks.json` and credentials reference those keys.

How OpenCred handles it:

1. Desktop user runs the **Onboarding Wizard** and chooses **Self-Published Keys**.
2. OpenCred generates an ECDSA P-256 keypair using `crypto.generateKeyPairSync` (CSPRNG; see [invariant 4](../security/invariants.md#4-csprng-only)).
3. The user enters a domain (e.g., `university.example`).
4. OpenCred builds a DID document via `generateDidWebDocument`:

   ```json
   {
     "@context": [
       "https://www.w3.org/ns/did/v1",
       "https://w3id.org/security/suites/jws-2020/v1"
     ],
     "id": "did:web:university.example",
     "verificationMethod": [
       {
         "id": "did:web:university.example#key-0",
         "type": "JsonWebKey",
         "controller": "did:web:university.example",
         "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
       }
     ],
     "authentication": ["did:web:university.example#key-0"],
     "assertionMethod": ["did:web:university.example#key-0"],
     "capabilityInvocation": ["did:web:university.example#key-0"],
     "capabilityDelegation": ["did:web:university.example#key-0"]
   }
   ```

5. The user downloads `did.json` and uploads it to `https://<domain>/.well-known/did.json` themselves. OpenCred never publishes on the user's behalf.
6. (Optional) the wizard offers a verification step that fetches the URL through the SSRF-protected `DIDWebResolver` to confirm publication.
7. From then on, every credential the user signs is issued by `did:web:<their-domain>`. Verifiers resolve the DID through the standard `DIDWebResolver`.

Key rotation: when the user wants to rotate, they generate a new key, regenerate the DID document, and replace the file at `.well-known/did.json`. Older credentials remain verifiable as long as the issuer keeps the old key in the document until those credentials expire.

## Mixing Trust Chains

Nothing prevents an issuer from having multiple keys or even multiple DIDs (e.g., a `did:key` for offline issuance and a `did:web` for institutional credentials). The Desktop Client supports multiple imported keys; the credential builder selects whichever key the user picks at signing time.

The verifier doesn't care which path you took — it only cares that the chain it sees terminates in a root it trusts.

## Where this lives in the code

| Concern | Module |
|---|---|
| Type 1 import (PFX/PEM) | `apps/desktop/src/main/dsc-import.ts`, `packages/signing/src/software-signer.ts` |
| Type 1 hardware token | `packages/signing/src/pkcs11-signer.ts` |
| Type 1 OS cert store | `packages/signing/src/os-cert-signer.ts`, `packages/signing/native/` |
| Type 2 CA adapter interface | `packages/ca-adapter/src/` |
| Type 3 key generation | `packages/crypto/src/signing-key-provider.ts` (`LocalSigningKeyProvider.generate*`) |
| Type 3 DID document | `packages/did/src/did-web.ts` (`generateDidWebDocument`) |
| Type 3 DID resolution | `packages/did/src/did-web.ts` (`DIDWebResolver`) |
| X.509 chain validation | `packages/verification/src/x509-chain-check.ts` |
