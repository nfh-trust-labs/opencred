# Key Attestation

## What is Key Attestation?

Key Attestation is how OpenCred establishes trust for issuers who do not have their own Document Signer Certificate (DSC). OpenCred verifies the issuer's identity (via domain ownership or a business credential) and then signs the issuer's public key with OpenCred's own DSC.

OpenCred signs public keys -- never credentials. The issuer still signs their own credentials locally.

## Trust Chain

```
Issuer's Credential Signature
    |
    v
Issuer's Public Key
    |
    v
Key Attestation VC (signed by OpenCred)
    |
    v
OpenCred's DSC
    |
    v
CSCA (Country Signing Certificate Authority)
```

Verifiers walk this chain from the credential signature up to the CSCA to establish trust.

## Verification Paths

### Domain Verification

1. **Request a challenge** -- provide your domain and verification method (`dns-txt` or `http`)
2. **Place the token**:
   - **DNS TXT**: Add a TXT record `opencred-domain-verification=<token>` to your domain
   - **HTTP**: Place the token at `https://yourdomain.com/.well-known/opencred-verification/<challengeId>`
3. **Submit verification** -- provide your public key, DID, and organization name
4. **Receive Key Attestation VC** -- OpenCred verifies the challenge, then signs your public key

Challenges are single-use and time-limited.

### Business VC Verification

Alternative to domain verification:

1. Submit an existing verified business credential (e.g., a government-issued business registration VC)
2. OpenCred verifies the VC signature and extracts identity information
3. OpenCred signs your public key with a Key Attestation VC

## Attestation Storage

Key Attestation VCs are stored locally on your machine. You can:

- **View** attestations for any imported key
- **Import** attestation VCs received externally
- **Remove** attestations that are no longer needed

Attestations persist as long as they remain active. They are the sole exception to the ephemeral-session-data rule -- credential payloads are purged within TTL (default 4 hours), but attestations are retained.

## Using Attestations

When you sign a credential with an attested key, the attestation is automatically embedded in the credential's proof as an `AttestationProof`. Verifiers can then validate the full trust chain from your signature through the attestation to OpenCred's DSC and the CSCA.

No additional configuration is needed. If a key has a valid attestation, it is used automatically.

## Attestation Lifecycle

| State | Description |
|-------|-------------|
| Pending | Challenge issued, awaiting verification |
| Active | Attestation VC issued and valid |
| Expired | `validUntil` date has passed |
| Revoked | Attestation revoked by OpenCred |

Expired or revoked attestations cannot be used for signing. You must request a new attestation.
