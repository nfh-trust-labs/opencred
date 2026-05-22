/**
 * Startup-time auto-publish of the issuer DID to DeDi.
 *
 * Two flags trigger this:
 *
 *   1. `OPENCRED_AUTO_PUBLISH_KEY=true` — works for any DID method.
 *   2. `OPENCRED_DEDI_HOST_DID_DOC=true` AND `OPENCRED_ISSUER_DID_METHOD=web`.
 *      This fixes the latent no-op surfaced by the 2026-05-21 bootcamp
 *      dry-run — previously the env var was validated at boot but never
 *      triggered an actual publish call.
 *
 * Idempotency: if the DID is already published, DeDi returns 409 → the
 * dedi-client adapter rewraps as `DeDiRecordExistsError` (#615). We log a
 * friendly "already published" message and treat it as success. Any other
 * DeDi failure is logged at warn level; the caller (server bootstrap) must
 * still start because auto-publish is a convenience, not a precondition.
 *
 * Extracted from `index.ts` so the logic can be unit-tested in isolation
 * (the full server bootstrap is too side-effectful to drive from a test).
 */

import { encodeDidWeb, generateDidWebDocument, type JWK } from "@opencred/did";
import { DeDiRecordExistsError } from "@opencred/shared";
import type { DeDiClient } from "@opencred/dedi-client";
import type { Signer } from "@opencred/signing";
import type { Logger } from "pino";

/**
 * Minimal slice of `OpenCredConfig` that the auto-publish step reads. Kept
 * as a structural type rather than importing the full config so the helper
 * stays decoupled from config.ts shape changes.
 */
export interface AutoPublishConfig {
  OPENCRED_AUTO_PUBLISH_KEY: boolean;
  OPENCRED_DEDI_HOST_DID_DOC: boolean;
  OPENCRED_ISSUER_DID_METHOD: "key" | "web";
  OPENCRED_ISSUER_DOMAIN?: string;
  OPENCRED_DEDI_NAMESPACE?: string;
}

/**
 * Result of a single auto-publish attempt. The boolean is what gets
 * surfaced via `/v1/health.didAutoPublished`. The string discriminator is
 * for tests and structured logs — it distinguishes "we genuinely published"
 * from "we found an existing record" from each failure mode.
 */
export type AutoPublishResult =
  | { didPublish: true; outcome: "published"; issuerDid: string; recordName: string }
  | { didPublish: true; outcome: "already-published"; issuerDid: string }
  | { didPublish: false; outcome: "disabled" }
  | { didPublish: false; outcome: "no-signer" }
  | { didPublish: false; outcome: "no-jwk"; issuerDid: string; signerType: string }
  | { didPublish: false; outcome: "publish-failed"; issuerDid: string; error: string };

/**
 * Run the startup auto-publish step.
 *
 * Returns a discriminated-union result describing exactly what happened.
 * Logs each branch at the appropriate level via the supplied `logger`.
 * Never throws — auto-publish failures are non-fatal by design.
 */
export async function runAutoPublishIfEnabled(
  config: AutoPublishConfig,
  dediClient: DeDiClient,
  signer: Signer | null,
  logger: Pick<Logger, "info" | "warn">,
): Promise<AutoPublishResult> {
  const shouldAutoPublish =
    config.OPENCRED_AUTO_PUBLISH_KEY ||
    (config.OPENCRED_DEDI_HOST_DID_DOC && config.OPENCRED_ISSUER_DID_METHOD === "web");
  if (!shouldAutoPublish) {
    return { didPublish: false, outcome: "disabled" };
  }
  if (!signer) {
    logger.warn(
      "Auto-publish requested but no signer is loaded — skipping. " +
        "Set OPENCRED_KEY_PATH or a Cloud HSM provider for the publish to run.",
    );
    return { didPublish: false, outcome: "no-signer" };
  }

  const isDidWeb = config.OPENCRED_ISSUER_DID_METHOD === "web";
  const issuerDid = isDidWeb
    ? encodeDidWeb(config.OPENCRED_ISSUER_DOMAIN!)
    : signer.id.split("#")[0]!;

  // For did:web we need a DID document; the adapter rejects did:web publish
  // without one. For did:key the adapter drops `document` anyway — pass
  // undefined and let it decide.
  let document: ReturnType<typeof generateDidWebDocument> | undefined;
  if (isDidWeb) {
    const jwk = signer.metadata.publicKeyJwk;
    if (!jwk) {
      logger.warn(
        { signerType: signer.type },
        "Cannot auto-publish did:web — signer does not expose publicKeyJwk. " +
          "PKCS#11 and OS-cert signers don't currently surface the JWK; " +
          "use OPENCRED_KEY_PATH (software signer) or publish manually via " +
          "POST /v1/keys/publish.",
      );
      return {
        didPublish: false,
        outcome: "no-jwk",
        issuerDid,
        signerType: signer.type,
      };
    }
    document = generateDidWebDocument(issuerDid, jwk as JWK);
  }

  try {
    const result = await dediClient.publishDID(issuerDid, document, config.OPENCRED_DEDI_NAMESPACE);
    logger.info(
      { issuerDid, recordName: result.recordName },
      "Issuer DID auto-published to DeDi at startup",
    );
    return {
      didPublish: true,
      outcome: "published",
      issuerDid,
      recordName: result.recordName,
    };
  } catch (err) {
    if (err instanceof DeDiRecordExistsError) {
      // The DID was published in a prior run; the public_key_registry
      // already has the record. From the auto-publish flag's POV this is
      // success — verifiers can already resolve via DeDi.
      logger.info({ issuerDid }, "Issuer DID already published to DeDi (idempotent skip)");
      return { didPublish: true, outcome: "already-published", issuerDid };
    }
    const errorMessage = err instanceof Error ? err.message : String(err);
    logger.warn(
      { error: errorMessage, issuerDid },
      "DeDi auto-publish failed (non-fatal — server still starts; " +
        "operators can publish manually via POST /v1/keys/publish)",
    );
    return {
      didPublish: false,
      outcome: "publish-failed",
      issuerDid,
      error: errorMessage,
    };
  }
}
