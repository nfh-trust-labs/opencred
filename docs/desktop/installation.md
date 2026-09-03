# Installing OpenCred Desktop

OpenCred Desktop runs on macOS, Windows, and Linux. Release builds bundle Node.js and Electron — there are no additional runtime dependencies.

> On macOS, the first launch requires a one-time approval — see [macOS first launch](#macos-first-launch) below. Windows may show a SmartScreen prompt on first run — see [Windows first launch](#windows-first-launch). Linux installs run without prompts.
>
> **Support:** [open an issue](https://github.com/nfh-trust-labs/opencred/issues) for bugs, feature requests, or questions.

## System Requirements

| Platform | Minimum version | Architecture | Status |
|---|---|---|---|
| macOS | 12 Monterey or later | x64 (Intel) and arm64 (Apple Silicon) — separate downloads | Supported |
| Linux | Ubuntu 20.04 or equivalent | x64 | Supported |
| Windows | Windows 10 or later | x64 | Supported |

## Installing from a Release

Download the installer for your platform from the **public release page**: <https://github.com/nfh-trust-labs/opencred-releases/releases>.

> Source code and the issue tracker live in [`opencred`](https://github.com/nfh-trust-labs/opencred) (open source, MIT). Release binaries are published to the [`opencred-releases`](https://github.com/nfh-trust-labs/opencred-releases/releases) mirror, which is also the desktop auto-updater feed.

| Platform | File | How to install |
|---|---|---|
| macOS (Apple Silicon) | `OpenCred-<version>-arm64.dmg` | Open the DMG and drag OpenCred.app to Applications. |
| macOS (Intel) | `OpenCred-<version>.dmg` | Open the DMG and drag OpenCred.app to Applications. |
| Windows | `OpenCred.Setup.<version>.exe` | Run the installer and follow the prompts. |
| Linux | `OpenCred-<version>.AppImage` | Make the file executable (`chmod +x OpenCred-<version>.AppImage`) and run it. |
| Linux (Debian/Ubuntu) | `OpenCred-<version>-amd64.deb` | `sudo dpkg -i OpenCred-<version>-amd64.deb` |

Each release also publishes a `SHA256SUMS` file. Verify integrity with `sha256sum -c SHA256SUMS --ignore-missing` (or `shasum -a 256 -c` on macOS) before running the installer.

### macOS first launch

The first time you open OpenCred on macOS, you'll see a one-time security prompt: *"OpenCred cannot be opened because the developer cannot be verified."* This appears because current builds are not notarized by Apple — to allow the app to launch:

1. Open **Finder → Applications**.
2. **Right-click** (or Ctrl-click) on `OpenCred.app` and choose **Open**.
3. In the confirmation dialog, click **Open** again.
4. macOS remembers the approval. Every subsequent launch is normal — you can use the Dock icon, Spotlight, etc.

> If you instead see *"OpenCred is damaged and can't be opened"*, the download picked up an extra quarantine attribute. Clear it from Terminal and retry:
>
> ```bash
> xattr -cr /Applications/OpenCred.app
> open /Applications/OpenCred.app
> ```

**Auto-update is unavailable while builds are unsigned** — see [Release signing status](release-signing.md). Check the [releases page](https://github.com/nfh-trust-labs/opencred-releases/releases) periodically for new versions and reinstall using the same approval step above.

### Windows first launch

If Windows SmartScreen reports *"Windows protected your PC"* when you run the installer, click **More info** and then **Run anyway**. Verify the installer's checksum against `SHA256SUMS` first (see above) — SmartScreen is reacting to the publisher's reputation, not to the file's integrity. As on macOS, auto-update is unavailable while builds are unsigned; install new versions from the releases page.

### Linux signature

AppImages and `.deb` packages are not currently signed. Verify checksums against the release manifest published in the GitHub release notes.

## Installing from Source

Building from source is supported for development and air-gapped deployments.

> **Note:** for most users the prebuilt installers above are the right path. Building from source is fully supported — the repository is open source (MIT) — and useful for regulated or air-gapped deployments that require auditable builds.

### Prerequisites

* Node.js **20 or later** (`.nvmrc` pins the version used in CI)
* pnpm **9 or later** — `npm install -g pnpm`
* A C++ build toolchain (Xcode Command Line Tools on macOS, Visual Studio Build Tools on Windows, `build-essential` on Linux). Required for compiling native addons used by hardware token and OS cert store signing.

### Build steps

```bash
git clone https://github.com/nfh-trust-labs/opencred.git
cd opencred
CI=true pnpm install
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
