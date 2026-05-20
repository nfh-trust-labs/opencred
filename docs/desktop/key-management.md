# Key Management

All signing in OpenCred Desktop happens locally. Private keys never leave your machine or reach the renderer process.

## Key Sources

| Source | Formats | Setup |
|--------|---------|-------|
| Software Key File | PFX (.pfx, .p12), PEM (.pem, .key), JWK (.jwk, .json), PKCS#8 DER | File picker + optional password (for PFX) |
| Hardware Token (PKCS#11) | PKCS#11 library (.dll, .dylib, .so) | Library path + slot index + PIN |
| OS Certificate Store | macOS Keychain, Windows CNG | Select from listed certificates |
| Generated Key | ECDSA P-256 | One-click generation |

## Importing a Software Key File

1. Go to **Settings** > **Import File** tab
2. Click **Choose File** and select your key file
3. Enter the password if using PFX/P12
4. Optionally add a label
5. Click **Import Key**

## Connecting a Hardware Token

1. Go to **Settings** > **Hardware Token** tab
2. Select the PKCS#11 library file for your device
3. Choose the slot index (usually 0)
4. Enter your PIN (never persisted)
5. Click **List Slots** to see available tokens
6. Select a key and click **Connect Key**

## Using the OS Certificate Store

1. Go to **Settings** > **OS Certificate Store** tab
2. Browse the certificate list (shows Subject CN, Issuer, Algorithm, Valid dates)
3. Select a certificate and click **Connect Certificate**

Platform support: macOS (Security.framework/Keychain), Windows (CNG). Not available on Linux.

## Generating a Key

1. Go to **Settings** > **Generate Key** tab
2. Optionally enter a label
3. Click **Generate ECDSA P-256 Key**
4. The key details (DID, Fingerprint, Algorithm) appear immediately

Generated keys are for the Self-Published Keys flow. After generating, publish your public key via did:web at `.well-known/did.json` on your domain so verifiers can resolve it.

## Supported Algorithms

| Algorithm | File Import | Hardware Token | OS Cert Store | Generated |
|-----------|-------------|----------------|---------------|-----------|
| ECDSA P-256 | Yes | Yes | Yes | Yes |
| ECDSA P-384 | Yes | Yes | Yes | No |
| Ed25519 | Yes | No | No | No |
| RSA 2048/3072/4096 | Yes (PFX) | Yes | Yes | No |

## Key Persistence

Stored locally (in `~/.config/opencred/opencred-config.json`):

- Key file paths (if `persistKeyPaths` is enabled in settings)
- Key metadata: ID, fingerprint, algorithm, label, source type
- Last-used key ID

Never stored:

- Private key material
- Signing buffers
- Hardware token PINs
- Credential payloads

The config file is restricted to owner-only permissions (0600 on Unix).

## DID Derivation

Each key produces a `did:key` identifier derived from the public key, used as the issuer identifier in credentials. The derivation is deterministic — the same public key always produces the same DID.

For the Self-Published Keys flow, you can also use a `did:web` identifier by publishing your public key at `https://yourdomain.com/.well-known/did.json`.

## Auto-rotation on Key Generation

If DeDi is configured and you have previously published one or more DIDs to it from this desktop client, **generating a new key automatically marks every previously-published DID as rotated on DeDi**. The new DID (the one derived from the freshly-generated key) is excluded from the rotation list, so it is published — and remains — `keyStatus: "current"`.

Behavior:

- The rotation hook fires immediately after the new key is in memory, before the IPC handler returns success to the renderer.
- The hook is **best-effort**. A DeDi outage, a transient network error, or a misconfigured DeDi token does **not** block key generation — the new key always succeeds. The rotation hook logs the failure and moves on.
- Credentials signed under a rotated key remain cryptographically valid. The rotation marker is advisory: it lets verifier UIs surface a "key rotated" badge, but it does not invalidate existing credentials.
- The flag transitions monotonically (`current → rotated`, never back), so re-rotating to a DID that was previously marked `rotated` is a safe no-op.

Implementation: `apps/desktop/src/main/ipc-handlers.ts` (the `KEY_GENERATE` handler) calls `DeDiPublishManager.markDIDRotated()` for each previously-published DID. The desktop tracks the list locally in `dediPublishedDIDs`; see `apps/desktop/src/main/store.ts`.

Verifiers pick up the rotation flag via the `/v1/keys/resolve` response (`keyStatus: "rotated"`) and the verify endpoint's advisory `keyRotation` check — see [Concepts → DIDs → Key rotation on DeDi-published DIDs](../concepts/dids.md#key-rotation-on-dedi-published-dids).
