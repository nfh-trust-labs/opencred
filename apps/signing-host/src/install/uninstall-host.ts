/**
 * Uninstaller for the native messaging host.
 *
 * Removes native messaging host manifests from Chrome and Firefox
 * manifest directories, and cleans up Windows Registry entries.
 */

import { unlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import {
  getManifestPath,
  MANIFEST_FILENAME,
  WINDOWS_REGISTRY_KEYS,
  type Browser,
  type Platform,
} from "./paths.js";
import { resolve } from "node:path";

export interface UninstallOptions {
  /** Which browsers to uninstall from. Defaults to "both". */
  browser?: "chrome" | "firefox" | "both";
  /** Override the detected platform. */
  platform?: Platform;
}

export interface UninstallResult {
  browser: Browser;
  path: string | null;
  registryKey: string | null;
  success: boolean;
  error?: string;
}

/**
 * Uninstall the native messaging host manifest for one or both browsers.
 *
 * @param options - Uninstallation options.
 * @returns Array of results per browser.
 */
export function uninstallHost(options: UninstallOptions = {}): UninstallResult[] {
  const platform = options.platform ?? (process.platform as Platform);
  const browsers: Browser[] =
    options.browser === "chrome"
      ? ["chrome"]
      : options.browser === "firefox"
        ? ["firefox"]
        : ["chrome", "firefox"];

  const results: UninstallResult[] = [];

  for (const browser of browsers) {
    try {
      if (platform === "win32") {
        results.push(removeWindowsManifest(browser));
      } else {
        results.push(removeManifest(browser, platform));
      }
    } catch (error) {
      results.push({
        browser,
        path: null,
        registryKey: null,
        success: false,
        error: error instanceof Error ? error.message : "Uninstallation failed",
      });
    }
  }

  return results;
}

function removeManifest(browser: Browser, platform: Platform): UninstallResult {
  const manifestPath = getManifestPath(browser, platform);
  if (!manifestPath) {
    return {
      browser,
      path: null,
      registryKey: null,
      success: true, // Nothing to remove
    };
  }

  try {
    unlinkSync(manifestPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }

  return {
    browser,
    path: manifestPath,
    registryKey: null,
    success: true,
  };
}

function removeWindowsManifest(browser: Browser): UninstallResult {
  const regKey = browser === "chrome" ? WINDOWS_REGISTRY_KEYS.chrome : WINDOWS_REGISTRY_KEYS.firefox;
  const manifestPath = resolve(".", MANIFEST_FILENAME);

  // Remove the manifest file
  try {
    unlinkSync(manifestPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }

  // Remove the registry key
  try {
    execFileSync("reg", ["delete", regKey, "/f"], {
      stdio: "ignore",
    });
  } catch {
    // Key may not exist — that's fine
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

if (process.argv[1]?.endsWith("uninstall-host.js")) {
  const args = process.argv.slice(2);
  const getArg = (name: string): string | undefined => {
    const idx = args.indexOf(`--${name}`);
    return idx >= 0 ? args[idx + 1] : undefined;
  };

  const results = uninstallHost({
    browser: (getArg("browser") as "chrome" | "firefox" | "both") ?? "both",
  });

  for (const r of results) {
    if (r.success) {
      console.log(`[${r.browser}] Uninstalled: ${r.path ?? r.registryKey ?? "nothing to remove"}`);
    } else {
      console.error(`[${r.browser}] Failed: ${r.error}`);
    }
  }
}
