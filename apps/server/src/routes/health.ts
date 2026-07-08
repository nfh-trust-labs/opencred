/**
 * Health check endpoint.
 *
 * Returns both a liveness status and a readiness status:
 *  - Liveness: always "ok" if the process is running.
 *  - Readiness: true when the signing key is loaded (minimum requirement
 *    for the server to issue credentials).
 *
 * HTTP status codes:
 *  - 200: Ready — signing key loaded, server can issue credentials.
 *  - 503: Not ready — signing key not loaded.
 */

import { Hono } from "hono";
import { getActiveSigner } from "../signing/key-manager.js";
import { getDeDiClient } from "../dedi-singleton.js";
import { getDidAutoPublishedAtStartup } from "../startup-state.js";

const health = new Hono();

health.get("/health", (c) => {
  const signer = getActiveSigner();
  const signingKeyLoaded = signer !== null;

  const body = {
    status: "ok",
    ready: signingKeyLoaded,
    signingKeyLoaded,
    dediConfigured: getDeDiClient() !== null,
    // Surfaces the outcome of the startup auto-publish step driven by
    // OPENCRED_AUTO_PUBLISH_KEY / OPENCRED_DEDI_HOST_DID_DOC. `true` means
    // the issuer DID is resolvable via DeDi right now (whether freshly
    // published this boot or already in the registry from a prior run);
    // `false` means either the flag was off, no signer was loaded, or a
    // non-idempotent failure occurred. Always present so clients don't
    // have to do existence checks.
    didAutoPublished: getDidAutoPublishedAtStartup(),
    timestamp: new Date().toISOString(),
  };

  return c.json(body, signingKeyLoaded ? 200 : 503);
});

export { health };
