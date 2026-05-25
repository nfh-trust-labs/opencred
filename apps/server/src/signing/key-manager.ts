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
import { didWebVerificationMethodId, encodeDidWeb } from "@opencred/did";
import { getConfig } from "../config.js";
import { getLogger } from "../logger.js";

let activeSigner: Signer | null = null;

/**
 * Compute the verification-method override the software signer should use
 * given the configured issuer DID method.
 *
 * `OPENCRED_ISSUER_DID_METHOD=web` requires the JWT `kid` header on every
 * issued credential to point at `did:web:<domain>#key-0` so that
 * verifiers fetching `did.json` find the matching `verificationMethod`
 * entry. Before issue #632 the signer derived its `id` purely from key
 * bytes (`did:key:…` / `did:jwk:…`), the override here flips it to the
 * did:web verification-method URL when the operator opts into method=web.
 *
 * Returns `undefined` for method=key — the derived `did:key:…` value is
 * the correct identifier in that case and no override is needed.
 *
 * `#key-0` matches what `generateDidWebDocument` (used by the startup
 * auto-publish path and the rotate endpoint's existing-doc reader)
 * already emits, keeping the JOSE header and the published DID Document
 * in lockstep.
 */
function computeVerificationMethodIdOverride(
  method: "key" | "web",
  domain: string | undefined,
): string | undefined {
  if (method !== "web" || !domain) return undefined;
  return didWebVerificationMethodId(encodeDidWeb(domain));
}

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

  const verificationMethodIdOverride = computeVerificationMethodIdOverride(
    config.OPENCRED_ISSUER_DID_METHOD,
    config.OPENCRED_ISSUER_DOMAIN,
  );

  const { signer, format } = createSoftwareSigner(
    config.OPENCRED_KEY_PATH,
    config.OPENCRED_KEY_LABEL,
    config.OPENCRED_KEY_PASSWORD,
    verificationMethodIdOverride,
  );

  activeSigner = signer;

  // Log metadata only — never the key itself
  logger.info(
    {
      keyId: signer.id,
      fingerprint: signer.metadata.fingerprint,
      algorithm: signer.algorithm,
      format,
      didMethod: config.OPENCRED_ISSUER_DID_METHOD,
      ...(verificationMethodIdOverride
        ? { verificationMethodIdOverride: true }
        : {}),
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
 * Set the active signer (used by the Cloud HSM factory).
 *
 * Pass `null` to clear the signer — useful for tests that need to assert
 * the "no key loaded" branch of the API.
 */
export function setActiveSigner(signer: Signer | null): void {
  activeSigner = signer;
}

/**
 * Require the active signer. Throws if no key is loaded.
 */
export function requireSigner(): Signer {
  if (!activeSigner) {
    throw new Error("No signing key loaded. Set OPENCRED_KEY_PATH or configure a KMS provider.");
  }
  return activeSigner;
}
