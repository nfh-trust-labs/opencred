# Key Handling

> **The single most important rule in OpenCred:** issuer private keys are never received, transmitted, or stored by any code path. All signing happens locally on the issuer's machine (Desktop) or inside the issuer-operated container (Docker). NFH Trust Labs operates no service that touches issuer keys.

This page documents how that rule is operationalised: where keys live, how they get loaded, how they're used for signing, and what guarantees the implementation makes.

## Key sources

OpenCred supports four key sources, each implemented as a backend in `packages/signing` (Desktop) or `apps/server/src/signing` (Docker).

| Source | Available on | Implementation |
|---|---|---|
| Software key file (PFX, PEM, JWK, PKCS#8) | Desktop, Docker | `packages/signing/src/software-signer.ts`; `apps/server/src/signing/key-manager.ts` |
| Hardware token / smart card (PKCS#11) | Desktop, Docker | `packages/signing/src/pkcs11-signer.ts`, `pkcs11-session.ts` |
| OS certificate store (Windows CNG, macOS Keychain) | Desktop only | `packages/signing/src/os-cert-signer.ts` + `packages/signing/native/` (N-API addons) |
| Cloud HSM (AWS KMS, Azure Key Vault, GCP Cloud KMS) | Docker only | `apps/server/src/signing/cloud-hsm/` |

The Desktop client also supports **generated keys** for the Self-Published Keys flow: ECDSA P-256 keys created via `crypto.generateKeyPairSync` and exposed for `did:web` publication. See `LocalSigningKeyProvider` in `packages/crypto/src/signing-key-provider.ts`.

## Key lifecycle

### Loading

| Source | When | How |
|---|---|---|
| Software key file (Desktop) | User imports from Settings or via the onboarding wizard | File path passed to the main process via IPC; loaded with `node:crypto`'s `createPrivateKey`. The renderer never sees the key bytes. |
| Software key file (Docker) | At server startup | `OPENCRED_KEY_PATH` is read by `apps/server/src/signing/key-manager.ts`. Process exits if the file is unreadable. |
| Hardware token | User connects via Settings | PIN entered in the UI is passed once to the main process; the PKCS#11 session opens, the key handle is held in memory, and the PIN is discarded. |
| OS certificate store | User selects a cert from the listing | Native addon returns a handle; the actual key never enters the JavaScript heap. |
| Cloud HSM | At server startup | The factory in `apps/server/src/signing/cloud-hsm/factory.ts` instantiates the provider client with default credentials and validates that the key exists. |

### In memory

Once loaded, keys are held as **opaque references**:

* Software keys → `KeyObject` instances from `node:crypto`. The raw bytes are stored inside the V8 native heap and are not directly addressable from JavaScript.
* PKCS#11 keys → integer handles into the device's session. The actual key never leaves the token.
* OS cert store keys → opaque pointers managed by the native addon, with the underlying key never crossing the addon boundary.
* Cloud HSM keys → SDK client objects with the key reference (ARN/key name). All signing operations are remote API calls.

This means there is **no JavaScript variable**, anywhere in the codebase, that contains the raw bytes of an issuer's private key after loading. Searching the codebase for such a variable would not find one, by design.

### Use during signing

Signing is split into a **prepare** step (build the unsigned credential and the signing input) and a **complete** step (apply the signature to the proof). The split is implemented in `packages/crypto`:

```ts
// Step 1: prepare — produces the unsigned credential and bytes-to-sign
const { signingInput } = prepareVcJwtProof(unsigned, signer.algorithm, {
  verificationMethod: signer.id,
});
const dataToSign = new TextEncoder().encode(signingInput);

// Step 2: sign — only this step touches the key, and it's done by the signer
const signatureBytes = await signer.sign(dataToSign);

// Step 3: complete — assembles the signed credential
const jwt = completeVcJwtProof(signingInput, signatureBytes);
```

The signer object (whichever backend it is) exposes a `sign(data)` method that takes pre-hashed bytes and returns the signature. The signer never sees the credential; it only sees the bytes that should be signed. This is what makes hardware tokens, OS cert stores, and Cloud HSMs interchangeable — none of them need to understand JSON-LD.

### Logging

The signing path **never logs**:

* Private key bytes (which it never has anyway)
* Signing input buffers
* Signature output buffers
* Credential bodies

It **does** log:

* Key ID (e.g., `did:key:...#fragment`)
* Key fingerprint (a hash of the public key, computed by `computeKeyFingerprint` in `packages/did/src/did-key.ts`)
* Algorithm
* Source type (file / pkcs11 / os-cert / cloud-hsm)

The Desktop logger (`apps/desktop/src/main/logger.ts`) installs a redaction hook that strips PEM blocks, JWK `d` fields, and long base64 strings from any value passed to the logger as a defense in depth — even if a developer accidentally tried to log a key, the redaction hook would catch it. See [Invariant 2](invariants.md#2-never-log-key-material).

The Docker logger (`apps/server/src/logger.ts`) is pino with a clean format. It does not install a redaction hook because the codebase does not pass key material to log calls in the first place; the prevention is at the source.

### Persistence

| State | Persisted? | Where | Retention |
|---|---|---|---|
| Issuer private key | No | n/a | Never |
| Key file path (Desktop, opt-in) | Yes (if `persistKeyPaths` is on) | `~/.config/opencred/opencred-config.json` chmod 0600 | Until user removes the key |
| Key metadata (id, fingerprint, algorithm, label, source) | Yes (Desktop) | Same config file | Until user removes |
| Last-used key ID | Yes (Desktop) | Same config file | Until user changes |
| Hardware token PIN | No | n/a | Never |
| Credential payloads | No | In-process memory only | Purged within `OPENCRED_SESSION_TTL` (default 4 hours) |
| Signed credentials | No | In-process memory until returned to caller | Same |
| Batch results | No | In-process memory | Same |
| Logs | Yes (Desktop) | `electron-log` files (rotating, 5 MB) | Until rotated out |
| Logs (Docker) | No | stdout, captured by orchestrator | Per orchestrator policy |

The Desktop config file is created with mode `0600` so only the owning user can read it.

### Disposal

When a key reference is removed (the user deletes a key in Settings, or the Docker container shuts down):

* Software keys: the `KeyObject` becomes unreferenced and is garbage-collected.
* Hardware tokens: the PKCS#11 session is closed, releasing the device handle.
* OS cert store: the native addon releases the platform handle.
* Cloud HSM: the SDK client is destroyed; outstanding signing requests are aborted.

OpenCred does not actively zero memory before disposal — that is left to the V8 garbage collector and the underlying allocator. For most threat models that's acceptable; for environments with stricter requirements, run OpenCred under a hardened OS configuration.

## What OpenCred does NOT do

* OpenCred does **not** generate, transmit, or store issuer private keys remotely.
* OpenCred does **not** offer a "key escrow" or "key recovery" service.
* OpenCred does **not** sign credentials on behalf of issuers.
* OpenCred does **not** include any HTTP endpoint that accepts private key material as input. If you want to verify this, search the route handlers in `apps/server/src/routes/*.ts` and the IPC handlers in `apps/desktop/src/main/ipc-handlers.ts`. There are none.

## See also

* [Invariants](invariants.md) — the seven mandatory rules, including "never touch issuer private keys"
* [Threat model](threat-model.md) — what we protect against
* [Concepts: Trust chains](../concepts/trust-chains.md) — how keys map to issuer types
* [Desktop key management](../desktop/key-management.md) — user-facing flows for importing and managing keys
