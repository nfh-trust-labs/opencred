# Installing OpenCred Desktop

OpenCred Desktop runs on macOS, Windows, and Linux. Release builds bundle Node.js and Electron — there are no additional runtime dependencies.

## System Requirements

| Platform | Minimum version | Architecture |
|---|---|---|
| macOS | 12 Monterey or later | Universal (Intel x64 + Apple Silicon arm64) |
| Windows | Windows 10 or later | x64 |
| Linux | Ubuntu 20.04 or equivalent | x64 |

## Installing from a Release

Download the installer for your platform from the **public release page**: <https://github.com/nfh-trust-labs/opencred-releases/releases>.

> Why a separate repo? OpenCred's source code is private, but binaries are distributed publicly via `nfh-trust-labs/opencred-releases`. Bug reports and feature requests should still be raised via the contact channels on <https://docs.opencred.global>.

| Platform | File | How to install |
|---|---|---|
| macOS | `OpenCred-<version>.dmg` | Open the DMG and drag OpenCred.app to Applications. |
| Windows | `OpenCred-Setup-<version>.exe` | Run the installer. The wizard lets you choose the installation directory. |
| Linux | `OpenCred-<version>.AppImage` | Make the file executable (`chmod +x OpenCred-<version>.AppImage`) and run it. |
| Linux (Debian/Ubuntu) | `opencred-desktop_<version>_amd64.deb` | `sudo dpkg -i opencred-desktop_<version>_amd64.deb` |

Each release also publishes a `SHA256SUMS` file. Verify integrity with `sha256sum -c SHA256SUMS --ignore-missing` (or `shasum -a 256 -c` on macOS) before running the installer.

### macOS first launch (unsigned build)

> **Current releases are unsigned.** We are working toward signed + notarised
> macOS releases; see [`release-signing.md`](release-signing.md) for the
> roadmap. Until then, the first launch requires a one-time trust step.

macOS will show *"OpenCred cannot be opened because the developer cannot be
verified"* on the first launch. To approve the app:

1. **Right-click** (or Ctrl-click) `OpenCred.app` in Finder → choose **Open**.
2. In the confirmation dialog, click **Open** again.
3. macOS remembers the approval. All subsequent launches work normally.

If you instead see *"OpenCred is damaged and can't be opened"*, the download
has been tagged with Apple's quarantine attribute in a way macOS can't
reconcile with the unsigned bundle. Clear it from Terminal:

```bash
xattr -cr /Applications/OpenCred.app
open /Applications/OpenCred.app
```

Auto-updates are **disabled** on unsigned builds — macOS will not install an
update whose signing identity differs from the installed version's. Check
[the releases page](https://github.com/nfh-trust-labs/opencred-releases/releases)
manually for new versions until signed releases ship.

### Windows first launch (unsigned build)

> **Current releases are unsigned.** Microsoft Defender SmartScreen will
> block the installer on first run.

When you run `OpenCred-Setup-<version>.exe`, SmartScreen shows *"Microsoft
Defender SmartScreen prevented an unrecognised app from starting"*. To
proceed:

1. Click **More info**.
2. Click **Run anyway**.

### Linux signature

AppImages and `.deb` packages are not currently signed. Verify checksums against the release manifest published in the GitHub release notes.

## Installing from Source

Building from source is supported for development and air-gapped deployments.

> **Note:** OpenCred's source repository is private. The instructions below assume you have read access. For most users the prebuilt installers above are the right path; reach out via the contact channels at <https://docs.opencred.global> if you need source access for a regulated or air-gapped deployment.

### Prerequisites

* Node.js **20 or later** (`.nvmrc` pins the version used in CI)
* pnpm **9 or later** — `npm install -g pnpm`
* A C++ build toolchain (Xcode Command Line Tools on macOS, Visual Studio Build Tools on Windows, `build-essential` on Linux). Required for compiling native addons used by hardware token and OS cert store signing.

### Build steps

```bash
git clone https://github.com/nfh-trust-labs/opencred.git
cd opencred
pnpm install
pnpm build               # builds all workspace packages
cd apps/desktop
pnpm dev                 # starts the dev server with hot reload
```

For a packaged build:

```bash
cd apps/desktop
pnpm build:dist          # rebuilds native modules for Electron, then runs electron-builder
```

The packaged installer lands in `apps/desktop/out/`. The exact format depends on the host platform — see `apps/desktop/package.json` for the `electron-builder` configuration.

### Native addons

Hardware token (PKCS#11) and OS certificate store signing require native addons compiled against the Electron ABI. The build pipeline runs `electron-rebuild` automatically as part of `pnpm build:dist`. If you see an error like `Module did not self-register`, run:

```bash
cd apps/desktop
pnpm rebuild:native
```

This rebuilds `pkcs11js` and the OpenCred OS-cert addons against your installed Electron version.

## First Launch

When OpenCred starts for the first time and no signing keys are configured, it opens the **Onboarding Wizard**. See [Getting started](getting-started.md) for the wizard walkthrough and your first credential.

## Uninstalling

| Platform | Steps |
|---|---|
| macOS | Drag `OpenCred.app` from Applications to Trash. To remove app data and logs, also delete `~/Library/Application Support/opencred/` and `~/Library/Logs/opencred/`. |
| Windows | Use **Apps & features** in Settings, or run the uninstaller from the Start menu. To remove app data, delete `%APPDATA%\opencred\`. |
| Linux | Remove the AppImage, or `sudo dpkg -r opencred-desktop`. App data lives in `~/.config/opencred/`. |

OpenCred never installs system-level services, kernel extensions, or background daemons. All state lives under your user profile.
