/**
 * Platform-specific paths for native messaging host manifests.
 *
 * Each browser + platform combination has a specific directory where
 * the host manifest JSON file must be placed. On Windows, manifests
 * are registered via the Windows Registry instead.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { HOST_NAME } from "./manifest.js";

export type Browser = "chrome" | "firefox";
export type Platform = "darwin" | "linux" | "win32";

/** The manifest filename (same for all platforms/browsers). */
export const MANIFEST_FILENAME = `${HOST_NAME}.json`;

/**
 * Chrome manifest directories by platform.
 */
const CHROME_MANIFEST_DIRS: Record<string, string> = {
  darwin: join(homedir(), "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts"),
  linux: join(homedir(), ".config", "google-chrome", "NativeMessagingHosts"),
};

/**
 * Firefox manifest directories by platform.
 */
const FIREFOX_MANIFEST_DIRS: Record<string, string> = {
  darwin: join(homedir(), "Library", "Application Support", "Mozilla", "NativeMessagingHosts"),
  linux: join(homedir(), ".mozilla", "native-messaging-hosts"),
};

/**
 * Windows Registry keys for native messaging host registration.
 */
export const WINDOWS_REGISTRY_KEYS = {
  chrome: `HKCU\\SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`,
  firefox: `HKCU\\SOFTWARE\\Mozilla\\NativeMessagingHosts\\${HOST_NAME}`,
} as const;

/**
 * Get the manifest directory for a given browser and platform.
 *
 * @param browser - The target browser.
 * @param platform - The target platform.
 * @returns The directory path, or null if the platform uses registry (Windows).
 */
export function getManifestDir(browser: Browser, platform: Platform): string | null {
  if (platform === "win32") {
    return null; // Windows uses registry
  }

  const dirs = browser === "chrome" ? CHROME_MANIFEST_DIRS : FIREFOX_MANIFEST_DIRS;
  return dirs[platform] ?? null;
}

/**
 * Get the full manifest file path for a given browser and platform.
 *
 * @param browser - The target browser.
 * @param platform - The target platform.
 * @returns The full file path, or null if the platform uses registry (Windows).
 */
export function getManifestPath(browser: Browser, platform: Platform): string | null {
  const dir = getManifestDir(browser, platform);
  if (!dir) return null;
  return join(dir, MANIFEST_FILENAME);
}
