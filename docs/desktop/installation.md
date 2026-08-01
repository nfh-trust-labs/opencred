# Installing OpenCred Desktop

OpenCred Desktop runs on macOS and Linux. Release builds bundle Node.js and Electron — there are no additional runtime dependencies.

> **🧪 Beta release.** This is an early-access build. On macOS, the first launch requires a one-time approval — see [macOS first launch](#macos-first-launch) below. Linux installs run without prompts. Windows installers are not yet published.
>
> **Support:** [open an issue](https://github.com/nfh-trust-labs/opencred/issues) for bugs, feature requests, or questions.

## System Requirements

| Platform | Minimum version | Architecture | Status |
|---|---|---|---|
| macOS | 12 Monterey or later | Universal (Intel x64 + Apple Silicon arm64) | Supported |
| Linux | Ubuntu 20.04 or equivalent | x64 | Supported |
| Windows | Windows 10 or later | x64 | Coming in a later beta |

## Installing from a Release

Download the installer for your platform from the **public release page**: <https://github.com/nfh-trust-labs/opencred-releases/releases>.

> Source code and the issue tracker live in [`opencred`](https://github.com/nfh-trust-labs/opencred) (open source, MIT). Release binaries are published to the [`opencred-releases`](https://github.com/nfh-trust-labs/opencred-releases/releases) mirror, which is also the desktop auto-updater feed.

| Platform | File | How to install |
|---|---|---|
| macOS | `OpenCred-<version>.dmg` | Open the DMG and drag OpenCred.app to Applications. |
| Linux | `OpenCred-<version>.AppImage` | Make the file executable (`chmod +x OpenCred-<version>.AppImage`) and run it. |
| Linux (Debian/Ubuntu) | `opencred-desktop_<version>_amd64.deb` | `sudo dpkg -i opencred-desktop_<version>_amd64.deb` |

Each release also publishes a `SHA256SUMS` file. Verify integrity with `sha256sum -c SHA256SUMS --ignore-missing` (or `shasum -a 256 -c` on macOS) before running the installer.

### macOS first launch

The first time you open OpenCred on macOS, you'll see a one-time security prompt: *"OpenCred cannot be opened because the developer cannot be verified."* This is expected during the beta — to allow the app to launch:

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

**During the beta, OpenCred does not auto-update on macOS.** Check the [releases page](https://github.com/nfh-trust-labs/opencred-releases/releases) periodically for new versions and reinstall using the same approval step above.

### Windows first launch

> **Beta:** Windows installers are not currently published. Subscribe to releases on the [public releases repo](https://github.com/nfh-trust-labs/opencred-releases/releases) to be notified when Windows builds ship.

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
