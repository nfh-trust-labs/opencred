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
5. (Optional, did:web only) If you want DeDi to also host your `did.json`, enable **Store DID Document in DeDi** before clicking Publish. This embeds the assembled W3C `did.json` as an immutable snapshot **on your key's record** in the `opencred-key-registry` (the per-key `document` field) so verifiers can resolve your DID from DeDi without hitting your domain's `.well-known/did.json`. There is no separate `did-documents` registry — the snapshot lives on each key record.

### Step-by-step: generate a did.json for self-hosting (Path A)

If you self-host `did.json` on your domain (Path A), you need the current DID Document to upload:

1. In the Desktop Client, go to **Settings** > **Keys**.
2. Click **Export DID Document** (or access `GET /v1/keys/did-document` on the embedded server).
3. Save the resulting JSON as `did.json` and upload it to `https://<your-domain>/.well-known/did.json`.

After key rotation, re-export and re-upload so the document includes both the new (active) and old (rotated) keys.

## Rotating a Key

Key rotation generates a new key and marks the old one as `rotated` (cleanly retired). A rotated key was never compromised, so credentials signed under it **stay valid**. **For did:key** issuers, the old DID is self-describing and fully independent of the new key. **For did:web** issuers, the old key keeps its own sequential `#key-<n>` fragment and stays in the regenerated `did.json`'s `verificationMethod[]`, so credentials it signed continue to verify — the old `#key-0` fragment collision tracked in [#653](https://github.com/nfh-trust-labs/opencred/issues/653) is resolved.

### What happens during rotation (did:web)

1. You generate a new key in Settings.
2. The Desktop Client calls `POST /v1/keys/rotate`:
   - Publishes the new key to `opencred-key-registry` (status `active`) at its own sequential `#key-<n>` fragment.
   - Flips the old key's status to `rotated`.
   - If DeDi is hosting your `did.json`, regenerates the multi-key document: both keys are listed under their distinct fragments, and the regenerated snapshot is embedded on the new key's record. The rotated key's own record is retained in DeDi with its earlier snapshot carried forward unchanged, so old credentials continue to verify.
3. If you self-host your `did.json` (Path A), you must re-export and re-upload it after rotation.

### What verifiers see after rotation

- Credentials signed by the **new** (active) key: accepted as valid.
- Credentials signed by the **old** (rotated) did:key: still accepted as valid. The old did:key DID is self-describing, so old credentials resolve and verify without any `did.json` dependency.
- Credentials signed by the **old** (rotated) did:web key: **still accepted as valid**. The DeDi key-registry record is retained with `status: "rotated"`, and because each rotation gets its own sequential `#key-<n>` fragment, the old key stays in the regenerated `did.json`'s `verificationMethod[]` under its distinct ID — a verifier resolving the credential's `kid` finds the original key material and the signature verifies.
- Verifier UIs may show a "key rotated" badge for credentials under a rotated key — this is advisory only and does not invalidate the credential.

> **Per-rotation key fragments ([#653](https://github.com/nfh-trust-labs/opencred/issues/653), resolved):** Each rotation publishes the new key under its own sequential verification-method fragment (`#key-0`, `#key-1`, …) rather than pinning every key to `#key-0`. A rotated did:web key and its successor therefore occupy distinct entries in the `did.json`, so credentials signed under the previous key continue to verify via standard DID resolution. Use **key rotation** for routine operational moves and **key revocation** only when a key is compromised. did:key issuers were never affected — each new key is a new DID.

### Step-by-step: rotate a did:web key

1. In Desktop Settings, click **Generate ECDSA P-256 Key** (or import a new key file).
2. The rotation dialog appears. Enter the **previous verification method** (e.g. `did:web:riverside.edu#key-0`) if you want the old key explicitly marked `rotated` on DeDi.
3. Click **Rotate Key**.
4. If you self-host `did.json`: click **Export DID Document**, then upload to `https://<your-domain>/.well-known/did.json`.

### did:key rotation

`did:key` rotation is different: each new key produces an entirely new DID. The old key's record in DeDi is flipped to `rotated` automatically when you generate a new key (the Desktop Client calls `setKeyStatus(verificationMethod, "rotated")` for each previously-published key). There is no `POST /v1/keys/rotate` step for `did:key` — regenerating the key is the rotation.

## Revoking a Key

Key revocation should be used when a signing key is **compromised** (e.g. stolen, leaked). After revocation, verifiers reject **every credential that key ever signed** with a top-level `REVOKED` result. This is a drastic action — use it for compromise, not routine rotation.

### What happens during revocation

1. The Desktop Client calls `POST /v1/keys/revoke` with the compromised key's verification method.
2. The key's status in `opencred-key-registry` is flipped to `revoked`.
3. If DeDi is hosting your `did.json`, it is regenerated: the revoked key is dropped from every verification relationship (`assertionMethod`, …) but kept in `verificationMethod[]` so it stays dereferenceable and verifiers can report a precise `REVOKED`. The `setKeyStatus("revoked")` registry write is always authoritative.
4. Any credentials signed by the revoked key are now rejected by DeDi-aware verifiers.

### Step-by-step: revoke a key

1. In Desktop Settings > **DeDi** tab, find the key you want to revoke in the key list.
2. Click **Revoke Key** next to the affected key.
3. Confirm the action in the dialog. You can optionally enter a reason (e.g. `key-compromised`).
4. The Desktop Client posts the revocation to DeDi and the key is marked `revoked`.
5. If you self-host `did.json` (Path A): click **Export DID Document** and re-upload — the revoked key is no longer in any verification relationship (it remains in `verificationMethod[]` only, so it stays resolvable but de-authorized).

### Status badges

The Desktop Client shows a status badge next to each DeDi-published key:

| Badge | Meaning |
|---|---|
| **Active** | The key is in active use. New credentials should be signed with this key. |
| **Rotated** | The key was cleanly retired. Credentials it signed remain valid for both did:key and did:web — the rotated key keeps its distinct `#key-<n>` fragment in the `did.json` ([#653](https://github.com/nfh-trust-labs/opencred/issues/653) resolved). |
| **Revoked** | The key was compromised. All credentials it signed are rejected by verifiers. |

## Auto-rotation on Key Generation

If DeDi is configured and you have previously published one or more keys to it from this desktop client, **generating a new key automatically flips every previously-published key's status to `rotated` on DeDi**. The freshly-generated key has not been published yet, so it is never in the rotation list — once you publish it, its record carries `status: "active"`.

Behavior:

- The rotation hook fires immediately after the new key is in memory, before the IPC handler returns success to the renderer.
- The hook is **best-effort**. A DeDi outage, a transient network error, or a misconfigured DeDi token does **not** block key generation — the new key always succeeds. The rotation hook logs the failure and moves on.
- For **did:key**: credentials signed under a rotated key remain cryptographically valid. The rotation marker is advisory — it lets verifier UIs surface a "key rotated" badge but does not invalidate existing credentials. For **did:web**: the rotated key keeps its distinct `#key-<n>` fragment, so its credentials also continue to verify ([#653](https://github.com/nfh-trust-labs/opencred/issues/653) resolved); the auto-rotation hook simply records the per-key `status: "rotated"` in the registry.
- The status transitions monotonically (`active → rotated → revoked`, never back), so re-rotating a key that was already `rotated` is a safe no-op (`monotone-refused` on the DeDi side).

Implementation: `apps/desktop/src/main/ipc-handlers.ts` (the `KEY_GENERATE` handler) calls `DeDiPublishManager.setKeyStatus(verificationMethod, "rotated")` for each previously-published key. The desktop tracks the list of published verification methods locally in `dediPublishedKeys`; see `apps/desktop/src/main/store.ts`.

Verifiers pick up the rotation status via the `/v1/keys/resolve` response (the per-key `KeyRecord.status: "rotated"`) and the verify endpoint's advisory `keyRotation` check — see [Concepts → DIDs → Key rotation on DeDi-published DIDs](../concepts/dids.md#key-rotation-on-dedi-published-dids).
