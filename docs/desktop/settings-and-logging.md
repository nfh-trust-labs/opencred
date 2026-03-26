# Settings and Diagnostics

## Settings

Access settings from the **Settings** link in the top bar.

| Setting | Default | Description |
|---------|---------|-------------|
| Theme | system | `light`, `dark`, or `system` (follows OS preference) |
| Offline Mode | off | Start in offline-first mode |
| Persist Key Paths | on | Save imported key file paths for auto-reload on restart |

## Logging

Logs are written by `electron-log` to platform-standard paths:

| Platform | Log Path |
|----------|----------|
| macOS | `~/Library/Logs/opencred/` |
| Windows | `%APPDATA%/opencred/logs/` |
| Linux | `~/.config/opencred/logs/` |

Log files rotate at **5 MB**. The current file is renamed to `.old` when the limit is reached. Logs persist across app restarts.

### Redaction

A hook strips sensitive data before anything reaches disk:

| Pattern | Replacement |
|---------|-------------|
| PEM private key blocks | `[REDACTED-PEM]` |
| JWK `"d"` (private key) fields | `[REDACTED]` |
| Long base64 strings (potential key material) | `[REDACTED]` |

Only key IDs and fingerprints appear in logs. Private key material is never logged.

## Bug Reports

The bug report dialog (accessible from Settings) collects:

- **System info**: app version, Electron version, Node.js version, OS, architecture
- **Recent log tail**: last 200 lines
- **User description**: free-text field for the issue

This information is submitted to a Google Form for the development team. No private keys or credential payloads are included.

## Auto-Updater

The app checks for updates on launch via GitHub Releases.

| State | What You See |
|-------|-------------|
| Checking | Spinner |
| Up to Date | "Running latest version" with a manual check button |
| Available | Version and release notes with a Download button |
| Downloading | Progress bar with download speed |
| Downloaded | "Restart Now" button to install |
| Error | Error message with Retry button |

Updates are disabled automatically in development mode.

## Network Status

The top bar shows a connectivity indicator:

| Indicator | Meaning |
|-----------|---------|
| Green | Online |
| Amber | Offline |

Connectivity is checked every 30 seconds. Being offline does not affect local operations (signing, verification). It only impacts update checks.
