# Getting Started with OpenCred Desktop

> macOS users see a one-time security prompt on first launch — [Installation → macOS first launch](installation.md#macos-first-launch) has the steps. **Support:** [open an issue](https://github.com/nfh-trust-labs/opencred/issues).

## System Requirements

| Platform | Minimum Version |
|----------|----------------|
| macOS | 12 (Monterey)+ |
| Windows | 10+ |
| Linux | Ubuntu 20.04+ |

No runtime dependencies are needed for release builds. For development: Node.js 20+, pnpm 9+.

## Installation

### From Release

Download the latest installer for your platform from the **public release page**: <https://github.com/nfh-trust-labs/opencred-releases/releases>.

- **macOS**: `.dmg` disk image (separate Apple Silicon and Intel builds)
- **Windows**: `.exe` installer
- **Linux**: `.AppImage` or `.deb`

Each release includes a `SHA256SUMS` file. Verify integrity with `sha256sum -c SHA256SUMS --ignore-missing` (or `shasum -a 256 -c` on macOS) before running the installer.

### From Source

```bash
git clone <repo-url>
cd opencred
pnpm install
pnpm build
cd apps/desktop
pnpm dev
```

## First Launch

If no keys are imported, the app opens the **Onboarding Wizard**. Otherwise, it opens to the Home screen showing the template gallery and credential history.

## Onboarding Wizard

Three paths based on your situation:

### Path 1: I have a Digital Signature Certificate (DSC)

Choose your key source:

| Option | Description |
|--------|-------------|
| Upload Certificate File | Import PFX, PEM, JWK, or PKCS#8 DER files |
| Hardware Token | Connect PKCS#11 devices (YubiKey, smart cards) |
| OS Certificate Store | Use macOS Keychain or Windows CNG certificates |

After import, a Key Details card displays: DID, Algorithm, Fingerprint, and Source.

### Path 2: I want to get a DSC

CA integration for DSC acquisition. Coming soon.

### Path 3: Self-Published Keys (did:web)

Generate keys locally and publish your public key via did:web at `.well-known/did.json` on your domain. See [Key Management](key-management.md) for details.

## Quick Tutorial: Issue Your First Credential

1. Click **Education Credential** on the Home screen
2. Fill in the subject fields (name, degree, institution, date conferred)
3. Select your signing key
4. Click **Build & Sign**
5. Export as JSON, PDF, or QR Code

## Next Steps

- [Key Management](key-management.md) -- importing, generating, and managing signing keys
- [Issuing Credentials](issuing-credentials.md) -- single and batch issuance workflows
- [Verifying Credentials](verifying-credentials.md) -- offline credential verification
- [Settings and Diagnostics](settings-and-logging.md) -- configuration, logging, and bug reports
