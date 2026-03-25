# Verifying Credentials

## How to Verify

1. Go to the **Verify** page
2. Paste the signed credential JSON or load a file
3. Click **Verify**

## Verification Checks

| Check | What It Validates |
|-------|-------------------|
| Signature | Cryptographic signature integrity against the issuer's public key |
| Not Before | `validFrom` date is not in the future |
| Expiry | `validUntil` date has not passed |
| Key Resolution | Issuer's DID (`did:key`) resolves to a valid public key |
| Key Attestation | If an attestation proof is present, validates the full chain |

## Result Codes

| Code | Meaning |
|------|---------|
| `VALID` | All checks passed |
| `INVALID` | Signature verification failed or a date check failed |
| `ATTESTATION_INVALID` | Key Attestation chain validation failed |

## Key Attestation Chain Validation

When a credential includes an `AttestationProof`, the verifier validates the full trust chain:

1. Verify the credential signature against the issuer's public key
2. Verify the Key Attestation VC signature against OpenCred's DSC
3. Confirm the attested public key matches the issuer's signing key
4. Check `validFrom` and `validUntil` on the attestation
5. Validate OpenCred's DSC against the CSCA

If any step fails, the result is `ATTESTATION_INVALID`.

## Offline Verification

All verification runs locally. No network requests are made:

- **JSON-LD contexts** are bundled with the app
- **DID resolution** for `did:key` is local (the public key is extracted directly from the DID)

Verification works fully offline.
