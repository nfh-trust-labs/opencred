/**
 * Key manager — loads signing keys at startup and provides Signer instances.
 *
 * Keys are loaded from local files specified by environment variables.
 * The private key material stays in-process and is NEVER transmitted
 * over the network or logged.
 *
 * SECURITY INVARIANTS:
 *  - Private keys are loaded from local files only — never from request bodies.
 *  - Key material is NEVER logged. Only key ID and fingerprint appear in logs.
 *  - The Signer instance holds the KeyObject in memory; it is never serialized.
 */

import { createSoftwareSigner } from "@opencred/signing";
import type { Signer } from "@opencred/signing";
import { getConfig } from "../config.js";
import { getLogger } from "../logger.js";

let activeSigner: Signer | null = null;

/**
 * Load the signing key from the configured file path.
 * Call once at startup. Throws if the key cannot be loaded.
 */
export function loadSigningKey(): Signer | null {
  const config = getConfig();
  const logger = getLogger();

  if (!config.OPENCRED_KEY_PATH) {
    logger.info("No OPENCRED_KEY_PATH configured — signing will be unavailable");
    return null;
  }

  logger.info("Loading signing key from configured path");

  const { signer, format } = createSoftwareSigner(
    config.OPENCRED_KEY_PATH,
    config.OPENCRED_KEY_LABEL,
    config.OPENCRED_KEY_PASSWORD,
  );

  activeSigner = signer;

  // Log metadata only — never the key itself
  logger.info(
    {
      keyId: signer.id,
      fingerprint: signer.metadata.fingerprint,
      algorithm: signer.algorithm,
      format,
    },
    "Signing key loaded successfully",
  );

  return signer;
}

/**
 * Get the active signer. Returns null if no key is loaded.
 */
export function getActiveSigner(): Signer | null {
  return activeSigner;
}

/**
 * Require the active signer. Throws if no key is loaded.
 */
export function requireSigner(): Signer {
  if (!activeSigner) {
    throw new Error("No signing key loaded. Set OPENCRED_KEY_PATH to a valid key file.");
  }
  return activeSigner;
}
