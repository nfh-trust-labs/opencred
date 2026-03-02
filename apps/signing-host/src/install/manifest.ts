/**
 * Native messaging host manifest generation.
 *
 * Generates Chrome and Firefox native messaging host manifest JSON files.
 * Chrome uses "allowed_origins" while Firefox uses "allowed_extensions".
 *
 * @see https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
 * @see https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging
 */

/** The registered name of the native messaging host. */
export const HOST_NAME = "com.opencred.signing";

/** Description shown in the manifest. */
const HOST_DESCRIPTION = "OpenCred Native Signing Host";

export interface ChromeManifest {
  name: string;
  description: string;
  path: string;
  type: "stdio";
  allowed_origins: string[];
}

export interface FirefoxManifest {
  name: string;
  description: string;
  path: string;
  type: "stdio";
  allowed_extensions: string[];
}

/**
 * Generate a Chrome native messaging host manifest.
 *
 * @param hostPath - Absolute path to the native host binary.
 * @param allowedOrigins - Chrome extension origin strings (e.g., "chrome-extension://ID/").
 * @returns The manifest object.
 */
export function generateChromeManifest(
  hostPath: string,
  allowedOrigins: string[],
): ChromeManifest {
  return {
    name: HOST_NAME,
    description: HOST_DESCRIPTION,
    path: hostPath,
    type: "stdio",
    allowed_origins: allowedOrigins,
  };
}

/**
 * Generate a Firefox native messaging host manifest.
 *
 * @param hostPath - Absolute path to the native host binary.
 * @param allowedExtensions - Firefox extension IDs (e.g., "opencred@example.com").
 * @returns The manifest object.
 */
export function generateFirefoxManifest(
  hostPath: string,
  allowedExtensions: string[],
): FirefoxManifest {
  return {
    name: HOST_NAME,
    description: HOST_DESCRIPTION,
    path: hostPath,
    type: "stdio",
    allowed_extensions: allowedExtensions,
  };
}
