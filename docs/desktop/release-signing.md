# Release signing status and roadmap

This document records the current state of OpenCred Desktop code signing and
what it takes to reach the long-term goal of signed + notarised releases on
every platform.

## Current state (as of 2026-04-21)

OpenCred Desktop releases are currently **distributed unsigned**. The release
pipeline (`.github/workflows/desktop-release.yml`) is wired for signing but
produces unsigned artefacts when the corresponding repository secrets are
absent. No secrets are configured today because the project does not hold an
Apple Developer Program membership or a Windows Authenticode code-signing
certificate.

### What users see

| Platform | First-launch experience |
|---|---|
| **macOS** | *"OpenCred cannot be opened because the developer cannot be verified"* dialog. User must right-click the app → **Open** → click **Open** again in the confirmation dialog. After that, macOS remembers the trust grant and the app opens normally. Users who dragged the DMG contents through the quarantine bit may need to run `xattr -cr /Applications/OpenCred.app` from Terminal. |
| **Windows** | SmartScreen *"Microsoft Defender SmartScreen prevented an unrecognised app from starting"*. User clicks **More info** → **Run anyway**. |
| **Linux** | No Gatekeeper equivalent — AppImage and deb install cleanly without prompts. |

### Auto-updates do not work while unsigned

`electron-updater` requires that an installed application and its update both
be signed by the same Developer ID / Authenticode certificate. While
unsigned, the in-app update flow is effectively disabled — users must
manually download each new version from the GitHub releases page. This is a
significant UX regression and is a major reason to prioritise signing.

## Why unsigned, why now

We hit this state during the v1.0.1 release investigation. Users were
receiving *"OpenCred is damaged and can't be opened"* when double-clicking
the DMG, which is the symptom of a bundle that is *ad-hoc signed but not
trusted* — worse UX than a truly unsigned bundle, because there is no
right-click-Open bypass for "damaged".

The root cause was `forceCodeSigning: true` in
[`apps/desktop/package.json`](../../apps/desktop/package.json) combined with
empty `MAC_CSC_LINK` / `APPLE_*` secrets. electron-builder fell through to
an ad-hoc signature, which macOS rejects as broken rather than treating as
unsigned.

How the release pipeline handles this today:

1. `forceCodeSigning` is **`true`** in `apps/desktop/package.json`, so a
   build that *should* be signed fails loudly if the certificate is
   missing or signing silently fails — an unsigned artefact must never
   reach the auto-updater, whose integrity guarantee depends on a
   consistent signing identity.
2. The signing preflight detects missing secrets per platform and emits a
   warning instead of failing the job (a partial configuration still
   fails — that indicates a setup error).
3. When a platform's secrets are absent, the release job opts out
   explicitly with `--config.forceCodeSigning=false`, unsets the `CSC_*` /
   `APPLE_*` variables, and sets `CSC_IDENTITY_AUTO_DISCOVERY=false` — so
   the output is *cleanly unsigned* rather than half-signed, and the log
   says so. Linux targets always opt out (no code-signing concept).
4. Post-build signature verification is skipped when signing is disabled
   (the checks would fail trivially on unsigned bundles).
5. Non-release CI builds (`desktop-build.yml`) always pass
   `--config.forceCodeSigning=false`; they have no certificates by
   design.

This is a **temporary workaround**, not a target state.

## Target state

Every stable release should be:

- Signed with an Apple Developer ID Application certificate and notarised
  by Apple for macOS (both `.dmg` and `.zip` inside the DMG).
- Signed with a Windows Authenticode certificate for `.exe` installers.
- Auto-update compatible — the installed app and its upgrade sharing the
  same signing identity.

## What it takes to get there

### macOS

| Item | Cost | Lead time |
|---|---|---|
| Apple Developer Program membership | $99 / year | 1–2 days for individual, weeks for organisation (needs DUNS) |
| Developer ID Application certificate | included | minutes once membership is active |
| Apple notarisation | included | per-build, ~10 minutes inside the CI job |

Once in hand, configure these repository secrets (Settings → Secrets and
variables → Actions):

- `MAC_CSC_LINK` — the Developer ID Application `.p12` base64-encoded
- `MAC_CSC_KEY_PASSWORD` — the password for the p12
- `APPLE_ID` — the Apple ID email tied to the membership
- `APPLE_TEAM_ID` — the 10-character Team ID (visible at
  `developer.apple.com/account`)
- `APPLE_APP_SPECIFIC_PASSWORD` — app-specific password generated at
  `appleid.apple.com` (not the account password)

The preflight job will detect the full set and automatically switch to
signed + notarised builds with no further workflow changes.

### Windows

| Item | Cost | Lead time |
|---|---|---|
| Authenticode OV certificate (Sectigo, SSL.com, Certum, etc.) | $70–$200 / year | 1–5 business days |
| Authenticode EV certificate (avoids SmartScreen "unrecognised" prompt immediately) | $300–$500 / year | 1–2 weeks (harder identity verification) |

Secrets to configure:

- `WIN_CSC_LINK` — base64-encoded `.pfx`
- `WIN_CSC_KEY_PASSWORD` — its password

Note: an OV certificate still triggers SmartScreen's "unrecognised app"
dialog until it accumulates enough downloads for Microsoft's reputation
algorithm, typically several weeks. An EV certificate avoids this from day
one.

## Irreversible decisions

- **Once a release is signed with a given identity, all future releases
  must use the same identity** (or a cross-signed successor). `electron-
  updater` refuses to install an update whose signing identity does not
  match what is already installed. This means:
  - Choose whether to sign under an individual Apple ID or an organisation
    account *once*, and stick with it.
  - If a certificate expires or gets revoked, existing installs will not
    auto-update until the user manually installs a new release.
  - If you ever change from individual to organisation accounts, existing
    users will be stranded.

- **Do not mix signed and unsigned versions in the same update channel.**
  If any v1.x is signed, all later v1.x releases must be signed. Unsigned
  releases can only flow to users who installed a previous unsigned
  release.

## Related

- [`docs/desktop/installation.md`](installation.md) — user-facing
  installation instructions including the right-click-Open workaround.
- [`.github/workflows/desktop-release.yml`](../../.github/workflows/desktop-release.yml)
  — the release workflow that adapts to whichever secrets are present.
- [`scripts/local-mac-release.sh`](../../scripts/local-mac-release.sh) —
  local-build escape hatch; enforces signing, used when Actions is
  unavailable.
