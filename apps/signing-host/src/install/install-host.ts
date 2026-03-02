/**
 * Installer for the native messaging host.
 *
 * Registers the native messaging host manifest for Chrome and/or Firefox
 * on macOS, Linux, and Windows.
 *
 * Usage:
 *   node dist/install/install-host.js --host-path /path/to/binary \
 *     --chrome-extension-id EXTENSION_ID \
 *     [--firefox-extension-id EXT_ID] \
 *     [--browser chrome|firefox|both]
 *
 * On macOS/Linux, writes the manifest JSON to the browser's
 * NativeMessagingHosts directory.
 *
 * On Windows, writes the manifest to a known location and registers
 * it in the Windows Registry via `reg add`.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { generateChromeManifest, generateFirefoxManifest } from "./manifest.js";
import {
  getManifestDir,
  getManifestPath,
  MANIFEST_FILENAME,
  WINDOWS_REGISTRY_KEYS,
  type Browser,
  type Platform,
} from "./paths.js";

export interface InstallOptions {
  /** Absolute path to the native host binary. */
  hostPath: string;
  /** Chrome extension origin (e.g., "chrome-extension://ID/"). */
  chromeExtensionOrigin?: string;
  /** Firefox extension ID (e.g., "opencred@example.com"). */
  firefoxExtensionId?: string;
  /** Which browsers to install for. Defaults to "both". */
  browser?: "chrome" | "firefox" | "both";
  /** Override the detected platform. */
  platform?: Platform;
}

export interface InstallResult {
  browser: Browser;
  path: string | null;
  registryKey: string | null;
  success: boolean;
  error?: string;
}

/**
 * Install the native messaging host manifest for one or both browsers.
 *
 * @param options - Installation options.
 * @returns Array of results per browser.
 */
export function installHost(options: InstallOptions): InstallResult[] {
  const platform = options.platform ?? (process.platform as Platform);
  const browsers: Browser[] =
    options.browser === "chrome"
      ? ["chrome"]
      : options.browser === "firefox"
        ? ["firefox"]
        : ["chrome", "firefox"];

  const resolvedHostPath = resolve(options.hostPath);
  const results: InstallResult[] = [];

  for (const browser of browsers) {
    try {
      if (browser === "chrome") {
        if (!options.chromeExtensionOrigin) {
          results.push({
            browser,
            path: null,
            registryKey: null,
            success: false,
            error: "Chrome extension origin is required for Chrome installation",
          });
          continue;
        }
        const manifest = generateChromeManifest(resolvedHostPath, [options.chromeExtensionOrigin]);
        const result = writeManifest(browser, platform, JSON.stringify(manifest, null, 2));
        results.push(result);
      } else {
        if (!options.firefoxExtensionId) {
          results.push({
            browser,
            path: null,
            registryKey: null,
            success: false,
            error: "Firefox extension ID is required for Firefox installation",
          });
          continue;
        }
        const manifest = generateFirefoxManifest(resolvedHostPath, [options.firefoxExtensionId]);
        const result = writeManifest(browser, platform, JSON.stringify(manifest, null, 2));
        results.push(result);
      }
    } catch (error) {
      results.push({
        browser,
        path: null,
        registryKey: null,
        success: false,
        error: error instanceof Error ? error.message : "Installation failed",
      });
    }
  }

  return results;
}

function writeManifest(browser: Browser, platform: Platform, content: string): InstallResult {
  if (platform === "win32") {
    return writeWindowsManifest(browser, content);
  }

  const manifestPath = getManifestPath(browser, platform);
  if (!manifestPath) {
    return {
      browser,
      path: null,
      registryKey: null,
      success: false,
      error: `Unsupported platform: ${platform}`,
    };
  }

  const dir = getManifestDir(browser, platform)!;
  mkdirSync(dir, { recursive: true });
  writeFileSync(manifestPath, content, "utf-8");

  return {
    browser,
    path: manifestPath,
    registryKey: null,
    success: true,
  };
}

function writeWindowsManifest(browser: Browser, content: string): InstallResult {
  const manifestDir = resolve(".");
  const manifestPath = resolve(manifestDir, MANIFEST_FILENAME);

  mkdirSync(dirname(manifestPath), { recursive: true });
  writeFileSync(manifestPath, content, "utf-8");

  const regKey = browser === "chrome" ? WINDOWS_REGISTRY_KEYS.chrome : WINDOWS_REGISTRY_KEYS.firefox;

  try {
    // Use execFileSync (not execSync) to prevent shell injection
    execFileSync("reg", ["add", regKey, "/ve", "/t", "REG_SZ", "/d", manifestPath, "/f"], {
      stdio: "ignore",
    });
  } catch {
    return {
      browser,
      path: manifestPath,
      registryKey: regKey,
      success: false,
      error: "Failed to write Windows Registry key. Run as administrator.",
    };
  }

  return {
    browser,
    path: manifestPath,
    registryKey: regKey,
    success: true,
  };
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

if (process.argv[1]?.endsWith("install-host.js")) {
  const args = process.argv.slice(2);
  const getArg = (name: string): string | undefined => {
    const idx = args.indexOf(`--${name}`);
    return idx >= 0 ? args[idx + 1] : undefined;
  };

  const hostPath = getArg("host-path");
  if (!hostPath) {
    console.error("Usage: install-host --host-path <path> [--chrome-extension-id ID] [--firefox-extension-id ID] [--browser chrome|firefox|both]");
    process.exit(1);
  }

  const results = installHost({
    hostPath,
    chromeExtensionOrigin: getArg("chrome-extension-id")
      ? `chrome-extension://${getArg("chrome-extension-id")}/`
      : undefined,
    firefoxExtensionId: getArg("firefox-extension-id"),
    browser: (getArg("browser") as "chrome" | "firefox" | "both") ?? "both",
  });

  for (const r of results) {
    if (r.success) {
      console.log(`[${r.browser}] Installed: ${r.path ?? r.registryKey}`);
    } else {
      console.error(`[${r.browser}] Failed: ${r.error}`);
    }
  }

  process.exit(results.every((r) => r.success) ? 0 : 1);
}
