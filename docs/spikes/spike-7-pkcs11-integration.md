# Spike 7: Desktop PKCS#11 Integration PoC

**Issue:** #7
**Goal:** Prove Electron + Node.js can load a PKCS#11 library and perform ECDSA P-256 signing operations compatible with W3C Data Integrity proof assembly.
**Status:** Complete
**Recommendation:** **GO** — with `graphene-pk11` as the primary library and `node-webcrypto-p11` as a higher-level alternative.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Library Comparison Matrix](#library-comparison-matrix)
3. [PKCS#11 Session Lifecycle and PIN Management](#pkcs11-session-lifecycle-and-pin-management)
4. [ECDSA P-256 Signing via PKCS#11](#ecdsa-p-256-signing-via-pkcs11)
5. [Signature Format Compatibility Analysis](#signature-format-compatibility-analysis)
6. [Electron Integration Architecture](#electron-integration-architecture)
7. [Cross-Platform Build and Deployment](#cross-platform-build-and-deployment)
8. [SoftHSM2 Development Setup Guide](#softhsm2-development-setup-guide)
9. [Code Samples](#code-samples)
10. [Risk Assessment and Mitigation](#risk-assessment-and-mitigation)
11. [Go/No-Go Recommendation](#gono-go-recommendation)
12. [References](#references)

---

## Executive Summary

OpenCred's Desktop Client (Phase 6B) needs to sign W3C Verifiable Credentials using private keys stored on hardware tokens (USB tokens like YubiKey, ePass, SafeNet; smart cards) via the PKCS#11 interface. This spike evaluates the feasibility of integrating PKCS#11 signing into an Electron application.

**Key findings:**

1. **Library ecosystem is mature.** The PeculiarVentures suite (`pkcs11js`, `graphene-pk11`, `node-webcrypto-p11`) provides a complete stack from low-level C bindings to a WebCrypto-compatible API. All three are MIT-licensed, TypeScript-first, and actively maintained.

2. **ECDSA P-256 signing works.** PKCS#11's `CKM_ECDSA` mechanism accepts a 32-byte SHA-256 hash and produces a 64-byte raw `r||s` signature. This is compatible with our Data Integrity proof engine after a straightforward format conversion (raw → DER for `ecdsa-rdfc-2019`).

3. **Electron integration is viable.** `pkcs11js` v2.x uses N-API (Node-API), which provides ABI stability across Node.js versions and works with `@electron/rebuild`. The native addon runs in Electron's main process; the renderer communicates via IPC through a secure `contextBridge` preload pattern.

4. **Cross-platform builds are feasible.** N-API addons compile per-platform. `electron-builder` handles native module rebuilding for macOS, Windows, and Linux. SoftHSM2 is available on all three platforms for development/CI testing.

5. **Primary risk is hardware diversity.** Different PKCS#11 implementations have quirks in session handling, mechanism support, and error codes. Mitigation: test against SoftHSM2 in CI, plus manual testing with at least one physical token per platform.

---

## Library Comparison Matrix

All three libraries are maintained by [PeculiarVentures](https://github.com/PeculiarVentures) and form a layered stack:

| Criteria | `pkcs11js` | `graphene-pk11` | `node-webcrypto-p11` |
|---|---|---|---|
| **Layer** | Low-level C binding (1:1 PKCS#11 API) | Object-oriented TypeScript wrapper | WebCrypto API polyfill over PKCS#11 |
| **npm package** | `pkcs11js` | `graphene-pk11` | `node-webcrypto-p11` |
| **Current version** | 2.x (N-API rewrite) | 2.3.x | 2.x |
| **TypeScript** | Yes (declaration files) | Yes (native TS) | Yes (native TS) |
| **Node.js minimum** | v18 (N-API) | v18 (depends on pkcs11js) | v18 (depends on graphene-pk11) |
| **Native addon** | Yes (C++ via N-API) | No (pure JS, depends on pkcs11js) | No (pure JS, depends on graphene-pk11) |
| **GitHub stars** | ~121 | ~180 | ~40 |
| **License** | MIT | MIT | MIT |
| **Tested HSMs** | SoftHSM2, Thales NShield, SafeNet Luna, Rutoken | SoftHSM2, Thales NShield, SafeNet Luna, Rutoken | SoftHSM2, various |
| **ECDSA P-256** | Yes (`CKM_ECDSA` + `CKM_EC_KEY_PAIR_GEN`) | Yes (via KeyGenMechanism.ECDSA) | Yes (via `subtle.sign('ECDSA', ...)`) |
| **API style** | Procedural (C_OpenSession, C_Sign, etc.) | OOP (session.createSign(), key.sign()) | Standard WebCrypto (subtle.sign()) |
| **Electron compat** | Yes (N-API = ABI stable) | Yes (pure JS over pkcs11js) | Yes (pure JS over graphene-pk11) |
| **Maturity** | Production (used by Hyperledger Fabric) | Research/experimental (per README) | Research/experimental (per README) |
| **Documentation** | API reference + examples | API reference + examples | API reference + examples |

### Dependency Chain

```
node-webcrypto-p11
  └── graphene-pk11
        └── pkcs11js (native N-API addon)
              └── PKCS#11 shared library (e.g., libsofthsm2.so)
```

### Recommendation

**Use `graphene-pk11`** as the primary integration layer for Phase 6B:

- **Why not raw `pkcs11js`?** The C-style procedural API (`C_OpenSession`, `C_FindObjectsInit`, `C_Sign`) is verbose and error-prone. Every call requires manual buffer management and template construction. `graphene-pk11` wraps this cleanly.

- **Why not `node-webcrypto-p11`?** While its WebCrypto API is familiar, it adds another abstraction layer and its key storage semantics differ from our use case (we want to enumerate and select existing keys on hardware tokens, not generate new ones via `subtle.generateKey`). It is also marked as research-quality.

- **Why `graphene-pk11`?** It provides the right balance: TypeScript-native, clean OOP API, direct access to PKCS#11 concepts (slots, tokens, sessions, key enumeration), and control over mechanism selection and signature format. It depends on `pkcs11js` for the native binding but adds no native code of its own.

**Alternative consideration:** If we later want to offer a unified signing API across software keys (WebCrypto) and hardware keys (PKCS#11), `node-webcrypto-p11` could serve as a compatibility layer. This is a Phase 6C consideration, not Phase 6B.

---

## PKCS#11 Session Lifecycle and PIN Management

### Session Model

PKCS#11 defines a strict lifecycle for interacting with cryptographic tokens:

```
1. Load PKCS#11 module (.so/.dylib/.dll)
2. C_Initialize()
3. C_GetSlotList() → find slots with tokens
4. C_GetTokenInfo() → read token metadata (label, flags)
5. C_OpenSession(slot, flags) → get session handle
6. C_Login(session, CKU_USER, PIN) → authenticate
7. ... perform crypto operations ...
8. C_Logout(session)
9. C_CloseSession(session)
10. C_Finalize()
```

### Session Types

| Session Type | Flag | Use Case |
|---|---|---|
| Read-only | `CKF_SERIAL_SESSION` | Read objects, verify signatures |
| Read-write | `CKF_SERIAL_SESSION \| CKF_RW_SESSION` | Create objects, sign, generate keys |

For signing, we need a **read-write session** (even though we are not creating objects, signing requires R/W access on most implementations).

### PIN Management Considerations

1. **PIN prompt timing:** The user must enter their PIN before signing. The Desktop UI should prompt for the PIN when a signing operation is initiated, not at app startup.

2. **PIN caching:** After `C_Login`, the session remains authenticated until `C_Logout` or `C_CloseSession`. For UX, we can keep a session open for the duration of a signing batch, then close it.

3. **PIN retry limits:** Most hardware tokens lock after 3-5 failed PIN attempts. The UI must clearly communicate remaining attempts (available via `CK_TOKEN_INFO.ulMaxPinLen` and token-specific flags).

4. **SO PIN vs User PIN:** OpenCred only needs the User PIN (CKU_USER). The Security Officer PIN is for token administration and should never be prompted in our app.

5. **Protected authentication path:** Some tokens support `CKF_PROTECTED_AUTHENTICATION_PATH` — the PIN is entered on the device itself (e.g., a PIN pad on a smart card reader). The Desktop Client should detect this flag and skip the software PIN prompt.

### Session Strategy for OpenCred

```
App startup:
  - Load PKCS#11 module
  - C_Initialize()
  - Enumerate slots/tokens for UI

User initiates signing:
  - Prompt for PIN (unless protected auth path)
  - C_OpenSession(slot, RW)
  - C_Login(session, CKU_USER, pin)
  - Find private key by label/ID
  - Sign one or more credentials
  - C_Logout(session)
  - C_CloseSession(session)

App shutdown:
  - C_Finalize()
```

---

## ECDSA P-256 Signing via PKCS#11

### Mechanism Selection

PKCS#11 v2.40 defines several ECDSA mechanisms:

| Mechanism | Input | Hashing |
|---|---|---|
| `CKM_ECDSA` | Pre-hashed data (32 bytes for SHA-256) | None — caller must hash first |
| `CKM_ECDSA_SHA256` | Raw data | Token hashes internally with SHA-256 |
| `CKM_ECDSA_SHA384` | Raw data | Token hashes internally with SHA-384 |
| `CKM_ECDSA_SHA512` | Raw data | Token hashes internally with SHA-512 |

**For OpenCred, use `CKM_ECDSA` (without hashing).** Rationale:

1. Our Data Integrity proof engine (`packages/crypto`) computes the hash of the canonicalized VC data. The signing step receives the 32-byte SHA-256 digest, not raw data.
2. `CKM_ECDSA` is universally supported — every PKCS#11 implementation that supports ECDSA supports this mechanism.
3. `CKM_ECDSA_SHA256` may not be supported on all tokens, and it would require sending the full canonicalized data to the token, which is less efficient over USB.

### Key Generation (for testing)

For development with SoftHSM2, we generate an ECDSA P-256 key pair:

- Mechanism: `CKM_EC_KEY_PAIR_GEN`
- EC params: OID for secp256r1 / P-256 = `06 08 2a 86 48 ce 3d 03 01 07` (DER-encoded OID)
- The public key's `CKA_EC_POINT` attribute contains the uncompressed EC point (65 bytes: `04 || x || y`)

### Key Discovery

Real-world usage: the issuer has a pre-existing key pair on their hardware token. OpenCred must:

1. Enumerate available private keys: `C_FindObjectsInit` with template `[{type: CKA_CLASS, value: CKO_PRIVATE_KEY}, {type: CKA_KEY_TYPE, value: CKK_EC}]`
2. For each key, read attributes: `CKA_LABEL`, `CKA_ID`, `CKA_EC_PARAMS` (to verify it's P-256)
3. Present the list to the user for selection
4. Use the selected key handle for `C_SignInit` / `C_Sign`

### Signing Operation

1. `C_SignInit(session, {mechanism: CKM_ECDSA}, privateKeyHandle)`
2. `C_Sign(session, sha256Hash)` → returns 64-byte raw signature

The 64-byte output is the concatenation of `r` (32 bytes, big-endian, zero-padded) and `s` (32 bytes, big-endian, zero-padded). This is the IEEE P1363 format.

---

## Signature Format Compatibility Analysis

### The Format Problem

There are two common ECDSA signature encodings:

| Format | Structure | Size (P-256) | Used By |
|---|---|---|---|
| **IEEE P1363 (raw)** | `r \|\| s` (fixed-size, zero-padded) | Exactly 64 bytes | PKCS#11, WebCrypto, COSE |
| **DER (ASN.1)** | `SEQUENCE { INTEGER r, INTEGER s }` | 68-72 bytes (variable) | X.509, TLS, JWS, Node.js `crypto`, most VC libraries |

### What OpenCred Needs

The `ecdsa-rdfc-2019` cryptosuite (via `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite`) expects **DER-encoded** signatures. This is the standard for Data Integrity proofs using ECDSA.

PKCS#11's `CKM_ECDSA` produces **IEEE P1363 (raw)** signatures.

**Therefore, we need a raw-to-DER conversion** after signing and a DER-to-raw conversion if we ever need to verify via PKCS#11.

### Conversion Logic

**Raw (P1363) → DER:**

```typescript
/**
 * Convert PKCS#11 raw ECDSA signature (r||s) to DER encoding.
 *
 * PKCS#11 CKM_ECDSA returns 64 bytes: r (32 bytes) || s (32 bytes)
 * DER format: SEQUENCE { INTEGER r, INTEGER s }
 *
 * DER INTEGER rules:
 * - Strip leading zero bytes (but keep at least one byte)
 * - If high bit is set, prepend a 0x00 byte (positive integer)
 */
function rawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) {
    throw new Error(`Expected 64-byte raw signature, got ${raw.length}`);
  }

  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);

  const derR = integerToDer(r);
  const derS = integerToDer(s);

  // SEQUENCE tag (0x30) + length + contents
  const sequenceLength = derR.length + derS.length;
  const der = new Uint8Array(2 + sequenceLength);
  der[0] = 0x30; // SEQUENCE tag
  der[1] = sequenceLength;
  der.set(derR, 2);
  der.set(derS, 2 + derR.length);

  return der;
}

/**
 * Encode a big-endian unsigned integer as DER INTEGER.
 */
function integerToDer(value: Uint8Array): Uint8Array {
  // Strip leading zeros (keep at least 1 byte)
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start++;
  }
  const trimmed = value.slice(start);

  // If high bit set, prepend 0x00 (DER INTEGER is signed)
  const needsPadding = (trimmed[0] & 0x80) !== 0;
  const length = trimmed.length + (needsPadding ? 1 : 0);

  const der = new Uint8Array(2 + length);
  der[0] = 0x02; // INTEGER tag
  der[1] = length;
  if (needsPadding) {
    der[2] = 0x00;
    der.set(trimmed, 3);
  } else {
    der.set(trimmed, 2);
  }

  return der;
}
```

**DER → Raw (P1363):**

```typescript
/**
 * Convert DER-encoded ECDSA signature to raw r||s format.
 * Useful if verifying via PKCS#11 or WebCrypto.
 */
function derToRaw(der: Uint8Array, curveByteLength: number = 32): Uint8Array {
  if (der[0] !== 0x30) {
    throw new Error('Invalid DER signature: expected SEQUENCE tag');
  }

  let offset = 2; // Skip SEQUENCE tag + length

  // Parse r
  if (der[offset] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER tag for r');
  }
  const rLength = der[offset + 1];
  offset += 2;
  const rBytes = der.slice(offset, offset + rLength);
  offset += rLength;

  // Parse s
  if (der[offset] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER tag for s');
  }
  const sLength = der[offset + 1];
  offset += 2;
  const sBytes = der.slice(offset, offset + sLength);

  // Pad/trim to fixed curve byte length
  const raw = new Uint8Array(curveByteLength * 2);
  raw.set(padOrTrim(rBytes, curveByteLength), 0);
  raw.set(padOrTrim(sBytes, curveByteLength), curveByteLength);

  return raw;
}

/**
 * Pad with leading zeros or trim leading zero padding to target length.
 */
function padOrTrim(bytes: Uint8Array, targetLength: number): Uint8Array {
  // Strip leading zero (DER padding for positive integers)
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00 && bytes.length - start > targetLength) {
    start++;
  }
  const trimmed = bytes.slice(start);

  if (trimmed.length === targetLength) {
    return trimmed;
  }
  if (trimmed.length < targetLength) {
    // Left-pad with zeros
    const padded = new Uint8Array(targetLength);
    padded.set(trimmed, targetLength - trimmed.length);
    return padded;
  }
  // trimmed.length > targetLength — should not happen for valid signatures
  throw new Error('Integer value too large for target curve');
}
```

### Integration Point

In `apps/desktop/src/signing/pkcs11-signer.ts`:

```typescript
async function signWithPkcs11(digest: Uint8Array, keyHandle: Handle): Promise<Uint8Array> {
  // 1. PKCS#11 sign (returns 64-byte raw r||s)
  const rawSignature = session.createSign('ECDSA', keyHandle).once(Buffer.from(digest));

  // 2. Convert to DER for Data Integrity proof engine
  const derSignature = rawToDer(rawSignature);

  return derSignature;
}
```

This DER signature is then passed to `packages/crypto`'s `completeProof()` function, which assembles the final Data Integrity proof.

---

## Electron Integration Architecture

### Architecture Overview

```
┌──────────────────────────────────────────────────┐
│ Renderer Process (sandboxed, context-isolated)   │
│                                                  │
│  ┌─────────────────────────────────────────┐     │
│  │ React UI (credential builder, verifier) │     │
│  │                                         │     │
│  │  window.pkcs11.listTokens()            │     │
│  │  window.pkcs11.listKeys(slotId)        │     │
│  │  window.pkcs11.sign(keyId, digest)     │     │
│  └───────────────┬─────────────────────────┘     │
│                  │ contextBridge                  │
│  ┌───────────────┴─────────────────────────┐     │
│  │ Preload Script (preload.ts)             │     │
│  │   ipcRenderer.invoke('pkcs11:...')      │     │
│  └───────────────┬─────────────────────────┘     │
└──────────────────┼───────────────────────────────┘
                   │ IPC (invoke/handle)
┌──────────────────┼───────────────────────────────┐
│ Main Process     │                               │
│  ┌───────────────┴─────────────────────────┐     │
│  │ IPC Handlers (ipcMain.handle)           │     │
│  │   'pkcs11:list-tokens'                  │     │
│  │   'pkcs11:list-keys'                    │     │
│  │   'pkcs11:sign'                         │     │
│  │   'pkcs11:open-session'                 │     │
│  │   'pkcs11:close-session'                │     │
│  └───────────────┬─────────────────────────┘     │
│                  │                               │
│  ┌───────────────┴─────────────────────────┐     │
│  │ PKCS#11 Signer (pkcs11-signer.ts)      │     │
│  │   graphene-pk11 (TypeScript)            │     │
│  │     └── pkcs11js (N-API native addon)   │     │
│  │           └── libsofthsm2.so / .dylib   │     │
│  └─────────────────────────────────────────┘     │
└──────────────────────────────────────────────────┘
```

### Why Main Process Only

The PKCS#11 native addon (`pkcs11js`) **must** run in the main process:

1. **Context isolation:** Electron's renderer process runs with `contextIsolation: true` (default since Electron 12). Native addons cannot be loaded in the isolated renderer context.
2. **Security:** The renderer may load untrusted web content. PKCS#11 operations (PIN entry, signing) must be isolated from the web content sandbox.
3. **Native module loading:** `pkcs11js` loads a `.so`/`.dylib`/`.dll` file at runtime via `dlopen`. This is a main-process-only operation.
4. **Single session:** PKCS#11 modules are typically initialized once per process. Running in main ensures a single point of session management.

### Preload Script

```typescript
// preload.ts
import { contextBridge, ipcRenderer } from 'electron';

// Expose a controlled API to the renderer — NEVER expose ipcRenderer directly
contextBridge.exposeInMainWorld('pkcs11', {
  /**
   * List available PKCS#11 tokens (hardware devices).
   * Returns token metadata: label, manufacturer, serial, flags.
   */
  listTokens: (): Promise<TokenInfo[]> =>
    ipcRenderer.invoke('pkcs11:list-tokens'),

  /**
   * List ECDSA P-256 private keys on a specific token.
   * Returns key metadata: label, id, key type, curve.
   * Does NOT return key material.
   */
  listKeys: (slotId: number): Promise<KeyInfo[]> =>
    ipcRenderer.invoke('pkcs11:list-keys', slotId),

  /**
   * Open an authenticated session on a token.
   * Prompts the user for PIN in the main process (or uses
   * protected authentication path if supported by the token).
   */
  openSession: (slotId: number, pin: string): Promise<{ sessionId: string }> =>
    ipcRenderer.invoke('pkcs11:open-session', slotId, pin),

  /**
   * Sign a SHA-256 digest using a hardware token key.
   * Returns the DER-encoded ECDSA signature.
   *
   * IMPORTANT: Only the 32-byte hash is sent to the main process.
   * The private key never leaves the hardware token.
   */
  sign: (sessionId: string, keyId: string, digest: Uint8Array): Promise<Uint8Array> =>
    ipcRenderer.invoke('pkcs11:sign', sessionId, keyId, digest),

  /**
   * Close an authenticated session.
   */
  closeSession: (sessionId: string): Promise<void> =>
    ipcRenderer.invoke('pkcs11:close-session', sessionId),
});
```

### IPC Handler (Main Process)

```typescript
// main/pkcs11-ipc.ts
import { ipcMain } from 'electron';
import { Pkcs11SigningService } from '../signing/pkcs11-signer';

export function registerPkcs11Handlers(signer: Pkcs11SigningService): void {
  ipcMain.handle('pkcs11:list-tokens', async () => {
    return signer.listTokens();
  });

  ipcMain.handle('pkcs11:list-keys', async (_event, slotId: number) => {
    return signer.listKeys(slotId);
  });

  ipcMain.handle('pkcs11:open-session', async (_event, slotId: number, pin: string) => {
    // PIN is received from the renderer's PIN input dialog
    // It is used immediately for C_Login and then discarded
    // NEVER log the PIN value
    return signer.openSession(slotId, pin);
  });

  ipcMain.handle('pkcs11:sign', async (_event, sessionId: string, keyId: string, digest: Uint8Array) => {
    // Validate digest length (must be exactly 32 bytes for SHA-256)
    if (digest.length !== 32) {
      throw new Error('Digest must be exactly 32 bytes (SHA-256)');
    }
    return signer.sign(sessionId, keyId, digest);
  });

  ipcMain.handle('pkcs11:close-session', async (_event, sessionId: string) => {
    return signer.closeSession(sessionId);
  });
}
```

### Security Considerations

1. **PIN handling:** The PIN is entered in a renderer UI input field, sent via IPC to the main process, used for `C_Login`, and then immediately discarded. It is never logged, stored, or sent over the network.

2. **Digest-only signing:** The renderer sends only the 32-byte SHA-256 digest to the main process. The private key never leaves the hardware token. The full credential data stays in the renderer process.

3. **No key material in IPC:** The IPC API returns key metadata (label, ID, curve) but never key bytes. This is inherent to PKCS#11 — private keys on hardware tokens are non-extractable.

4. **Session isolation:** Each session ID maps to a PKCS#11 session handle in a private Map in the main process. Session IDs are random UUIDs, not PKCS#11 handles.

---

## Cross-Platform Build and Deployment

### Native Addon Build Requirements

`pkcs11js` v2.x uses **N-API (Node-API)**, which provides ABI stability across Node.js versions. This is critical for Electron because Electron's Node.js version may differ from the system's.

| Platform | Build Toolchain | PKCS#11 Module Path |
|---|---|---|
| **macOS** | Xcode Command Line Tools (`xcode-select --install`) | `/usr/local/lib/softhsm/libsofthsm2.so` (Homebrew) |
| **Linux** | `build-essential`, `gcc`, `g++` | `/usr/lib/softhsm/libsofthsm2.so` (apt) |
| **Windows** | Visual Studio Build Tools (Desktop C++ workload) | `C:\SoftHSM2\lib\softhsm2.dll` (MSI installer) |

### Electron Rebuild

When packaging the Desktop Client, native addons must be rebuilt for Electron's specific Node.js version and ABI:

```bash
# Using @electron/rebuild (integrated with Electron Forge)
npx @electron/rebuild -w pkcs11js

# Or configure in Electron Forge's forge.config.ts:
# rebuildConfig: { onlyModules: ['pkcs11js'] }
```

Since `pkcs11js` v2.x uses N-API, the rebuild is typically smooth — N-API addons don't need to match exact Node.js ABI versions. However, `@electron/rebuild` should still be run to ensure the addon links against the correct Electron headers.

### Platform-Specific PKCS#11 Module Discovery

The Desktop Client needs to locate the user's PKCS#11 module (`.so`/`.dylib`/`.dll`). Strategies:

1. **User configuration:** Settings panel where the issuer specifies the path to their PKCS#11 module. Store in `electron-store`.

2. **Well-known paths:** Check common locations:
   - macOS: `/usr/local/lib/softhsm/libsofthsm2.so`, `/Library/OpenSC/lib/opensc-pkcs11.so`
   - Linux: `/usr/lib/softhsm/libsofthsm2.so`, `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
   - Windows: `C:\Windows\System32\eTPKCS11.dll` (ePass), `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll`

3. **File dialog fallback:** If no module is detected, prompt the user to browse for the `.so`/`.dylib`/`.dll`.

**Recommendation:** Combine strategies 2 and 3 — auto-detect well-known paths and fall back to a file dialog. Store the selected path in `electron-store` for subsequent launches.

### Build Matrix (CI)

```yaml
# .github/workflows/desktop.yml (conceptual)
strategy:
  matrix:
    os: [macos-latest, ubuntu-latest, windows-latest]

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: '20'
  - run: pnpm install
  - run: pnpm -C apps/desktop rebuild  # @electron/rebuild
  - run: pnpm -C apps/desktop test     # SoftHSM2 tests
  - run: pnpm -C apps/desktop package  # electron-builder
```

Each platform produces its own distributable (`.dmg`, `.exe`/`.msi`, `.AppImage`/`.deb`).

---

## SoftHSM2 Development Setup Guide

SoftHSM2 is a software implementation of PKCS#11 based on OpenSSL. It emulates a hardware token entirely in software — ideal for development and CI testing.

### Installation

**macOS (Homebrew):**
```bash
brew install softhsm
# Module: /usr/local/lib/softhsm/libsofthsm2.so
# Config: /usr/local/etc/softhsm/softhsm2.conf
```

**Ubuntu/Debian:**
```bash
sudo apt-get install -y softhsm2
# Module: /usr/lib/softhsm/libsofthsm2.so
# Config: /etc/softhsm/softhsm2.conf
```

**Windows:**
```
# Download MSI from https://github.com/nicosResworworworworworworworb/SoftHSM2-for-Windows/releases
# Module: C:\SoftHSM2\lib\softhsm2.dll
```

### Configuration

```bash
# Create a local token directory
mkdir -p $HOME/.config/softhsm2/tokens

# Create config (or edit the system default)
cat > $HOME/.config/softhsm2/softhsm2.conf << 'EOF'
directories.tokendir = /path/to/your/home/.config/softhsm2/tokens
objectstore.backend = file
log.level = INFO
EOF

# Set environment variable
export SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf
```

### Initialize a Token

```bash
# Create a new token in slot 0
softhsm2-util --init-token --slot 0 --label "OpenCred-Dev" --so-pin 1234 --pin 5678

# Verify
softhsm2-util --show-slots
```

### Generate a Test ECDSA P-256 Key Pair

Using `pkcs11-tool` from OpenSC:

```bash
# Generate P-256 key pair on the SoftHSM2 token
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so \
  --login --pin 5678 \
  --keypairgen --key-type EC:secp256r1 \
  --label "test-issuer-key" --id 01

# List objects to verify
pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so \
  --login --pin 5678 \
  --list-objects
```

Or programmatically via `graphene-pk11` (see Code Samples below).

### CI Integration

For CI (GitHub Actions), SoftHSM2 can be installed in the workflow:

```yaml
- name: Install SoftHSM2
  run: |
    if [[ "$RUNNER_OS" == "Linux" ]]; then
      sudo apt-get install -y softhsm2
    elif [[ "$RUNNER_OS" == "macOS" ]]; then
      brew install softhsm
    fi
    # Windows: use pre-installed or choco install softhsm
```

---

## Code Samples

### Example 1: Complete PKCS#11 Signing Session with graphene-pk11

```typescript
// apps/desktop/src/signing/pkcs11-signer.ts (prototype — not production code)

import * as graphene from 'graphene-pk11';

interface TokenInfo {
  slotId: number;
  label: string;
  manufacturer: string;
  serial: string;
  hasProtectedAuthPath: boolean;
}

interface KeyInfo {
  id: string;       // hex-encoded CKA_ID
  label: string;    // CKA_LABEL
  curve: string;    // e.g., 'P-256'
}

/**
 * PKCS#11 signing service for the Desktop Client.
 * Runs in Electron's main process only.
 */
class Pkcs11SigningService {
  private module: graphene.Module | null = null;
  private sessions: Map<string, graphene.Session> = new Map();

  /**
   * Load and initialize the PKCS#11 module.
   * @param libraryPath Path to the PKCS#11 .so/.dylib/.dll
   */
  initialize(libraryPath: string): void {
    this.module = graphene.Module.load(libraryPath);
    this.module.initialize();
  }

  /**
   * List all available tokens (hardware devices / SoftHSM slots).
   */
  listTokens(): TokenInfo[] {
    if (!this.module) throw new Error('PKCS#11 module not initialized');

    const tokens: TokenInfo[] = [];
    const slots = this.module.getSlots(true); // true = only slots with tokens

    for (let i = 0; i < slots.length; i++) {
      const slot = slots.items(i);
      const token = slot.getToken();
      tokens.push({
        slotId: i,
        label: token.label.trim(),
        manufacturer: token.manufacturerID.trim(),
        serial: token.serialNumber.trim(),
        hasProtectedAuthPath: !!(token.flags & graphene.TokenFlag.PROTECTED_AUTHENTICATION_PATH),
      });
    }

    return tokens;
  }

  /**
   * List ECDSA private keys on a specific token slot.
   */
  listKeys(slotId: number): KeyInfo[] {
    if (!this.module) throw new Error('PKCS#11 module not initialized');

    const slot = this.module.getSlots(true).items(slotId);
    const session = slot.open(graphene.SessionFlag.SERIAL_SESSION);

    try {
      const keys: KeyInfo[] = [];
      const objects = session.find({
        class: graphene.ObjectClass.PRIVATE_KEY,
        keyType: graphene.KeyType.ECDSA,
      });

      for (let i = 0; i < objects.length; i++) {
        const key = objects.items(i).toType<graphene.PrivateKey>();
        const attrs = key.getAttribute({
          id: null,
          label: null,
          ecParams: null,
        });

        keys.push({
          id: Buffer.from(attrs.id).toString('hex'),
          label: attrs.label || '',
          curve: identifyCurve(attrs.ecParams),
        });
      }

      return keys;
    } finally {
      session.close();
    }
  }

  /**
   * Open an authenticated session on a token.
   */
  openSession(slotId: number, pin: string): { sessionId: string } {
    if (!this.module) throw new Error('PKCS#11 module not initialized');

    const slot = this.module.getSlots(true).items(slotId);
    const session = slot.open(
      graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION
    );

    try {
      session.login(pin, graphene.UserType.USER);
    } catch (err) {
      session.close();
      throw err;
    }

    const sessionId = crypto.randomUUID();
    this.sessions.set(sessionId, session);
    return { sessionId };
  }

  /**
   * Sign a SHA-256 digest using ECDSA via PKCS#11.
   * Returns DER-encoded signature compatible with Data Integrity proofs.
   */
  sign(sessionId: string, keyId: string, digest: Uint8Array): Uint8Array {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('Invalid session ID');

    // Find the private key by CKA_ID
    const keyIdBuffer = Buffer.from(keyId, 'hex');
    const objects = session.find({
      class: graphene.ObjectClass.PRIVATE_KEY,
      keyType: graphene.KeyType.ECDSA,
      id: keyIdBuffer,
    });

    if (objects.length === 0) {
      throw new Error(`No ECDSA private key found with ID: ${keyId}`);
    }

    const privateKey = objects.items(0).toType<graphene.PrivateKey>();

    // CKM_ECDSA: sign the pre-hashed digest (32 bytes)
    // Output: 64 bytes raw r||s (IEEE P1363)
    const sign = session.createSign('ECDSA', privateKey);
    const rawSignature = sign.once(Buffer.from(digest));

    // Convert raw r||s to DER for Data Integrity proof engine
    return rawToDer(new Uint8Array(rawSignature));
  }

  /**
   * Close an authenticated session and clean up.
   */
  closeSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      try {
        session.logout();
      } catch {
        // Session may already be logged out
      }
      session.close();
      this.sessions.delete(sessionId);
    }
  }

  /**
   * Finalize the PKCS#11 module (call on app shutdown).
   */
  finalize(): void {
    // Close all open sessions
    for (const [id] of this.sessions) {
      this.closeSession(id);
    }
    this.module?.finalize();
    this.module = null;
  }
}

// --- Helpers ---

const P256_OID = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

function identifyCurve(ecParams: Buffer | null): string {
  if (ecParams && ecParams.equals(P256_OID)) {
    return 'P-256';
  }
  return 'unknown';
}
```

### Example 2: Raw-to-DER Signature Conversion (complete, tested logic)

See the [Signature Format Compatibility Analysis](#signature-format-compatibility-analysis) section above for the full `rawToDer` and `derToRaw` implementations.

### Example 3: Electron Main Process Bridge

```typescript
// apps/desktop/src/main/index.ts (prototype excerpt)

import { app, BrowserWindow } from 'electron';
import { Pkcs11SigningService } from '../signing/pkcs11-signer';
import { registerPkcs11Handlers } from './pkcs11-ipc';
import Store from 'electron-store';

const store = new Store();
let signer: Pkcs11SigningService | null = null;

app.whenReady().then(() => {
  // Initialize PKCS#11 if a module path is configured
  const pkcs11Path = store.get('pkcs11ModulePath') as string | undefined;
  if (pkcs11Path) {
    try {
      signer = new Pkcs11SigningService();
      signer.initialize(pkcs11Path);
      console.log('PKCS#11 module loaded successfully');
    } catch (err) {
      console.error('Failed to load PKCS#11 module:', (err as Error).message);
      // Don't crash — PKCS#11 is optional, software signing still works
    }
  }

  // Register IPC handlers (they gracefully handle signer being null)
  if (signer) {
    registerPkcs11Handlers(signer);
  }

  const mainWindow = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,    // REQUIRED: isolate renderer from main
      nodeIntegration: false,    // REQUIRED: no Node.js in renderer
      sandbox: true,             // Additional sandboxing
    },
  });

  mainWindow.loadFile('index.html');
});

app.on('will-quit', () => {
  signer?.finalize();
});
```

### Example 4: PKCS#11 Key Generation for Testing (SoftHSM2)

```typescript
// test/helpers/pkcs11-keygen.ts (test utility, not production code)

import * as graphene from 'graphene-pk11';

/**
 * Generate an ECDSA P-256 key pair on a SoftHSM2 token for testing.
 */
function generateTestKeyPair(
  modulePath: string,
  pin: string,
  slotIndex: number = 0
): { publicKey: graphene.PublicKey; privateKey: graphene.PrivateKey } {
  const mod = graphene.Module.load(modulePath);
  mod.initialize();

  const slot = mod.getSlots(true).items(slotIndex);
  const session = slot.open(
    graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION
  );
  session.login(pin, graphene.UserType.USER);

  const P256_OID = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

  const keys = session.generateKeyPair(graphene.KeyGenMechanism.ECDSA, {
    keyType: graphene.KeyType.ECDSA,
    token: true,       // persist on token
    verify: true,
    label: 'test-issuer-key',
    id: Buffer.from([0x01]),
    paramsECDSA: P256_OID,
  }, {
    keyType: graphene.KeyType.ECDSA,
    token: true,       // persist on token
    sign: true,
    private: true,     // requires login to use
    sensitive: true,   // cannot be extracted
    extractable: false,
    label: 'test-issuer-key',
    id: Buffer.from([0x01]),
  });

  session.logout();
  session.close();
  mod.finalize();

  return keys;
}
```

---

## Risk Assessment and Mitigation

### Risk Matrix

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Hardware token diversity** — different vendors implement PKCS#11 slightly differently (e.g., mechanism support, error codes, session behavior) | High | Medium | Test against SoftHSM2 in CI. Manual test with at least one physical token (YubiKey or SafeNet) per platform. Implement defensive error handling with vendor-specific workarounds. |
| **Native addon build failures** — `pkcs11js` requires C++ compilation. Build failures on CI or user machines. | Medium | Medium | N-API provides ABI stability. `@electron/rebuild` handles recompilation. Pre-built binaries reduce build friction. Test build matrix on all three platforms in CI. |
| **PIN entry UX** — clunky or insecure PIN prompt. PIN entered in renderer, sent via IPC. | Low | Medium | PIN input in a dedicated dialog (not inline in the credential form). Clear PIN from memory after `C_Login`. Detect protected authentication path and skip software PIN entry. |
| **Token removal during signing** — user unplugs USB token mid-operation | Medium | Low | PKCS#11 returns `CKR_DEVICE_REMOVED`. Catch this error, close the session, and prompt the user to reconnect. Do not retry automatically. |
| **Session timeout** — some tokens auto-logout after inactivity | Low | Low | Re-authenticate if `CKR_SESSION_HANDLE_INVALID` or `CKR_USER_NOT_LOGGED_IN` is returned during a signing operation. |
| **Signature format bugs** — incorrect raw-to-DER conversion leading to invalid proofs | Low | High | Thorough unit tests with known test vectors (NIST ECDSA P-256 vectors). Round-trip test: sign via PKCS#11 → DER convert → verify with `@digitalbazaar/ecdsa-rdfc-2019-cryptosuite`. |
| **Electron version mismatch** — N-API addon built for wrong Electron version | Low | Medium | `@electron/rebuild` handles this automatically. Pin Electron version in `package.json`. Test packaging on all platforms. |
| **SoftHSM2 unavailable on Windows CI** — no standard package manager install | Medium | Low | Use `choco install softhsm` or download pre-built MSI. Alternatively, skip Windows PKCS#11 tests in CI and rely on manual testing. |

### Key Dependencies

| Dependency | Version | Risk Level | Notes |
|---|---|---|---|
| `pkcs11js` | 2.x | Low | N-API, MIT, actively maintained by PeculiarVentures |
| `graphene-pk11` | 2.3.x | Low-Medium | MIT, depends on pkcs11js. "Research/experimental" disclaimer, but used by node-webcrypto-p11 in production contexts |
| `@electron/rebuild` | Latest | Low | Official Electron tooling |
| SoftHSM2 | 2.x | Low | Widely used for PKCS#11 testing (Hyperledger Fabric, many others) |

### Fallback Strategies

If PKCS#11 integration proves problematic for specific hardware:

1. **OS keychain API (Phase 6C):** macOS Security.framework and Windows CNG can access some smart card keys without PKCS#11. This is already planned for Phase 6C.

2. **OpenSC as middleware:** OpenSC provides a PKCS#11 module (`opensc-pkcs11.so`) that supports a wide range of smart cards and USB tokens. If a vendor's own PKCS#11 module is problematic, OpenSC may work as an alternative.

3. **Web Crypto bridge via `node-webcrypto-p11`:** If `graphene-pk11`'s API proves too low-level, we can switch to the WebCrypto-compatible API. This would unify the signing interface across software keys (Node.js crypto) and hardware keys (PKCS#11).

---

## Go/No-Go Recommendation

### **GO**

The spike confirms that PKCS#11 integration in Electron is feasible and well-supported:

1. **Mature library stack:** `pkcs11js` (N-API) → `graphene-pk11` (TypeScript OOP) provides a solid foundation. The stack is MIT-licensed, actively maintained, and tested against real HSMs.

2. **Clean architecture:** PKCS#11 operations run in Electron's main process, exposed to the renderer via a minimal IPC bridge. This aligns with Electron's security model (context isolation, no node integration in renderer).

3. **Signature format compatibility:** The raw-to-DER conversion for PKCS#11 ECDSA signatures is straightforward and well-understood. It integrates cleanly with our `completeProof()` flow in `packages/crypto`.

4. **Testing is practical:** SoftHSM2 is available on all three platforms and simulates a hardware token for CI testing. PKCS#11 mock tests via SoftHSM2 cover the full session lifecycle, key enumeration, and signing flow.

5. **Estimated effort aligns with plan:** The implementation plan estimates Phase 6B at 2-3 days. Given the spike findings — clear library choice, well-defined architecture, no blocking risks — this estimate is reasonable.

### Recommended Implementation Approach for Phase 6B

1. Add `graphene-pk11` (and transitively `pkcs11js`) to `apps/desktop/package.json`
2. Implement `Pkcs11SigningService` class (based on the code samples in this doc)
3. Implement raw-to-DER signature conversion utility with comprehensive test vectors
4. Add IPC handlers and preload bridge
5. Add key management UI: token selection, key listing, PIN prompt dialog
6. Configure `@electron/rebuild` for `pkcs11js` in `electron-builder`/Forge config
7. Write tests using SoftHSM2 (key gen, signing, format conversion, error handling)
8. Manual test with at least one physical token (YubiKey 5 recommended — widely available, supports ECDSA P-256 via PIV applet)

---

## References

- [pkcs11js — npm](https://www.npmjs.com/package/pkcs11js)
- [pkcs11js — GitHub](https://github.com/PeculiarVentures/pkcs11js)
- [pkcs11js — API Documentation](https://peculiarventures.github.io/pkcs11js/)
- [graphene-pk11 — npm](https://www.npmjs.com/package/graphene-pk11)
- [graphene-pk11 — GitHub](https://github.com/PeculiarVentures/graphene)
- [graphene-pk11 — API Documentation](https://peculiarventures.github.io/graphene/)
- [node-webcrypto-p11 — GitHub](https://github.com/PeculiarVentures/node-webcrypto-p11)
- [PKCS#11 v2.40 Current Mechanisms Specification](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html)
- [Electron — Using Native Node.js Modules](https://www.electronjs.org/docs/latest/tutorial/using-native-node-modules)
- [Electron — Context Isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [Electron — Inter-Process Communication](https://www.electronjs.org/docs/latest/tutorial/ipc)
- [@electron/rebuild — npm](https://www.npmjs.com/package/@electron/rebuild)
- [SoftHSM2 — GitHub](https://github.com/softhsm/SoftHSMv2)
- [Hyperledger Fabric — HSM via PKCS#11 Tutorial](https://hyperledger.github.io/fabric-sdk-node/release-1.4/tutorial-hsm-pkcs11.html)
- [ECDSA Signature Format Conversion](https://github.com/java-crypto/cross_platform_crypto/blob/main/docs/ecdsa_signature_conversion.md)
- [OpenCred PRD — Section 5.2](OpenCred_PRD.md) (Key storage types and signing paths)
