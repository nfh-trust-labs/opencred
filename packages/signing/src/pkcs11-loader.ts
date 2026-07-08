/**
 * Lazy loader for the pkcs11js native module.
 *
 * The pkcs11js package contains a platform-specific native .node addon.
 * Importing it at the top level (via `import * as pkcs11js from "pkcs11js"`)
 * would crash the entire @opencred/signing package on platforms where the
 * binary was compiled for a different OS (e.g., loading a macOS-compiled
 * binary on Linux).
 *
 * By isolating the load into this module and deferring it to first call,
 * non-PKCS#11 functionality (software signing, OS cert store) remains
 * available even if the pkcs11js native module is missing or incompatible.
 *
 * Both pkcs11-session.ts and pkcs11-signer.ts import from this module.
 * Tests can mock this module (`vi.mock("../pkcs11-loader.js")`) to provide
 * a fake pkcs11js without touching the real native addon.
 */

import { createRequire } from "node:module";
import { CryptoError } from "@opencred/shared";

const require = createRequire(import.meta.url);

let _pkcs11js: typeof import("pkcs11js") | undefined;

/**
 * Load and return the pkcs11js module.
 *
 * On first call, attempts to `require("pkcs11js")`. If the native addon
 * cannot be loaded (wrong architecture, missing binary, etc.), throws a
 * descriptive CryptoError instead of an opaque dlopen crash.
 *
 * Subsequent calls return the cached module.
 */
export function loadPkcs11js(): typeof import("pkcs11js") {
  if (!_pkcs11js) {
    try {
      _pkcs11js = require("pkcs11js") as typeof import("pkcs11js");
    } catch (error) {
      throw new CryptoError(
        "PKCS#11 native module failed to load. This usually means the pkcs11js binary " +
          "was compiled for a different platform. Ensure pkcs11js is rebuilt for this OS " +
          `(${process.platform}/${process.arch}). ` +
          `Original error: ${error instanceof Error ? error.message : "unknown"}`,
      );
    }
  }
  return _pkcs11js;
}
