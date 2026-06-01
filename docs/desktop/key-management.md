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

## Publishing a Key to DeDi

Once you have a key loaded, you can advertise its public key to DeDi so verifiers can resolve it via the `opencred-key-registry`. This is step one of the DeDi lifecycle.

### Prerequisites

- DeDi is configured in Desktop Settings (DeDi base URL, auth, and your verified namespace).
- You are using the Self-Published Keys (did:web or did:key) flow.

### Step-by-step: first publish

1. Open **Settings** > **DeDi** tab.
2. Confirm the namespace shown matches your verified domain (e.g. `riverside.edu`).
3. Click **Publish Key to DeDi**.

   The Desktop Client calls `POST /v1/keys/publish` internally and publishes your active key's public JWK to the `opencred-key-registry` with status `active`.

4. A success banner shows your key ID (e.g. `did:web:riverside.edu#key-0`) and the record name DeDi assigned.
5. (Optional, did:web only) If you want DeDi to also host your `did.json`, enable **Store DID Document in DeDi** before clicking Publish. This stores the assembled W3C `did.json` in the `did-documents` registry so verifiers can resolve your DID from DeDi without hitting your domain's `.well-known/did.json`.

### Step-by-step: generate a did.json for self-hosting (Path A)

If you self-host `did.json` on your domain (Path A), you need the current DID Document to upload:

1. In the Desktop Client, go to **Settings** > **Keys**.
2. Click **Export DID Document** (or access `GET /v1/keys/did-document` on the embedded server).
3. Save the resulting JSON as `did.json` and upload it to `https://<your-domain>/.well-known/did.json`.

After key rotation, re-export and re-upload so the document includes both the new (active) and old (rotated) keys.

## Rotating a Key

Key rotation generates a new key and marks the old one as `rotated` (cleanly retired). Credentials signed by the old key **remain valid** — a rotated key was never compromised.

### What happens during rotation (did:web)

1. You generate a new key in Settings.
2. The Desktop Client calls `POST /v1/keys/rotate`:
   - Publishes the new key to `opencred-key-registry` (status `active`).
   - Flips the old key's status to `rotated`.
   - If DeDi is hosting your `did.json`, regenerates it: the active key comes first; the rotated key is retained (so old credentials still resolve).
3. If you self-host your `did.json` (Path A), you must re-export and re-upload it after rotation.

### What verifiers see after rotation

- Credentials signed by the **old** (rotated) key: still accepted as valid. The key record is retained in DeDi; the key remains in `did.json`.
- Credentials signed by the **new** (active) key: accepted as valid.
- Verifier UIs may show a "key rotated" badge for credentials under the old key — this is advisory only and does not invalidate the credential.

### Step-by-step: rotate a did:web key

1. In Desktop Settings, click **Generate ECDSA P-256 Key** (or import a new key file).
2. The rotation dialog appears. Enter the **previous verification method** (e.g. `did:web:riverside.edu#key-0`) if you want the old key explicitly marked `rotated` on DeDi.
3. Click **Rotate Key**.
4. If you self-host `did.json`: click **Export DID Document**, then upload to `https://<your-domain>/.well-known/did.json`.

### did:key rotation

`did:key` rotation is different: each new key produces an entirely new DID. The old DID record in DeDi is marked `rotated` automatically when you generate a new key (the Desktop Client calls `markDIDRotated` for each previously-published did:key DID). There is no `POST /v1/keys/rotate` step for `did:key` — regenerating the key is the rotation.

## Revoking a Key

Key revocation should be used when a signing key is **compromised** (e.g. stolen, leaked). After revocation, verifiers reject **every credential that key ever signed** with a top-level `REVOKED` result. This is a drastic action — use it for compromise, not routine rotation.

### What happens during revocation

1. The Desktop Client calls `POST /v1/keys/revoke` with the compromised key's verification method.
2. The key's status in `opencred-key-registry` is flipped to `revoked`.
3. If DeDi is hosting your `did.json`, it is regenerated dropping the revoked key entirely.
4. Any credentials signed by the revoked key are now rejected by DeDi-aware verifiers.

### Step-by-step: revoke a key

1. In Desktop Settings > **DeDi** tab, find the key you want to revoke in the key list.
2. Click **Revoke Key** next to the affected key.
3. Confirm the action in the dialog. You can optionally enter a reason (e.g. `key-compromised`).
4. The Desktop Client posts the revocation to DeDi and the key is marked `revoked`.
5. If you self-host `did.json` (Path A): click **Export DID Document** and re-upload — the revoked key is no longer in the document.

### Status badges

The Desktop Client shows a status badge next to each DeDi-published key:

| Badge | Meaning |
|---|---|
| **Active** | The key is in active use. New credentials should be signed with this key. |
| **Rotated** | The key was cleanly retired. Credentials it signed remain valid. No action needed. |
| **Revoked** | The key was compromised. All credentials it signed are rejected by verifiers. |

## Auto-rotation on Key Generation

If DeDi is configured and you have previously published one or more DIDs to it from this desktop client, **generating a new key automatically marks every previously-published DID as rotated on DeDi**. The new DID (the one derived from the freshly-generated key) is excluded from the rotation list, so it is published — and remains — `keyStatus: "current"`.

Behavior:

- The rotation hook fires immediately after the new key is in memory, before the IPC handler returns success to the renderer.
- The hook is **best-effort**. A DeDi outage, a transient network error, or a misconfigured DeDi token does **not** block key generation — the new key always succeeds. The rotation hook logs the failure and moves on.
- Credentials signed under a rotated key remain cryptographically valid. The rotation marker is advisory: it lets verifier UIs surface a "key rotated" badge, but it does not invalidate existing credentials.
- The flag transitions monotonically (`current → rotated`, never back), so re-rotating to a DID that was previously marked `rotated` is a safe no-op.

Implementation: `apps/desktop/src/main/ipc-handlers.ts` (the `KEY_GENERATE` handler) calls `DeDiPublishManager.markDIDRotated()` for each previously-published DID. The desktop tracks the list locally in `dediPublishedDIDs`; see `apps/desktop/src/main/store.ts`.

Verifiers pick up the rotation flag via the `/v1/keys/resolve` response (`keyStatus: "rotated"`) and the verify endpoint's advisory `keyRotation` check — see [Concepts → DIDs → Key rotation on DeDi-published DIDs](../concepts/dids.md#key-rotation-on-dedi-published-dids).
