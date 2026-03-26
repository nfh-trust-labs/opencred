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
| Key Resolution | Issuer's DID (`did:key` or `did:web`) resolves to a valid public key |

## Result Codes

| Code | Meaning |
|------|---------|
| `VALID` | All checks passed |
| `INVALID` | Signature verification failed or a date check failed |

## Offline Verification

All verification runs locally. No network requests are made for `did:key` credentials:

- **JSON-LD contexts** are bundled with the app
- **DID resolution** for `did:key` is local (the public key is extracted directly from the DID)

For `did:web` credentials, key resolution fetches the DID document from the issuer's domain. Network access is required.

Verification works fully offline for `did:key` credentials.
