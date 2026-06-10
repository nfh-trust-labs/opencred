/**
 * Startup-time auto-publish of the issuer's signing key to DeDi.
 *
 * Publishes the active signer as a record in the `opencred-key-registry`
 * (one record per key, status `active`). For did:web issuers who opt into
 * `OPENCRED_DEDI_HOST_DID_DOC`, the assembled `did.json` snapshot is embedded
 * ON that key record (the per-key `document` field) so DeDi can serve it and
 * back the did:web fallback resolver. There is no longer a separate
 * `did-documents` registry.
 *
 * Two flags trigger this:
 *
 *   1. `OPENCRED_AUTO_PUBLISH_KEY=true` — publishes the key record for any
 *      DID method.
 *   2. `OPENCRED_DEDI_HOST_DID_DOC=true` AND `OPENCRED_ISSUER_DID_METHOD=web`
 *      — publishes the key record with the `did.json` snapshot embedded.
 *
 * Idempotency: if the key is already published, DeDi returns 409 → the
 * dedi-client adapter rewraps as `DeDiRecordExistsError` (#615). We log a
 * friendly "already published" message and treat it as success. The embedded
 * `document` snapshot is immutable and was written when the record was first
 * published, so there is nothing to refresh on a re-deploy. Any other DeDi
 * failure is logged at warn level; the caller (server bootstrap) must still
 * start because auto-publish is a convenience, not a precondition.
 *
 * The issuer's private key never reaches this code — only the public
 * `publicKeyJwk` exposed by the signer's metadata is published.
 *
 * Extracted from `index.ts` so the logic can be unit-tested in isolation
 * (the full server bootstrap is too side-effectful to drive from a test).
 */

import {
  encodeDidWeb,
  generateDidWebDocumentMultiKey,
  didWebVerificationMethodIdForIndex,
  type JWK,
} from "@opencred/did";
import { DeDiRecordExistsError } from "@opencred/shared";
import type { DeDiClient, KeyRecord } from "@opencred/dedi-client";
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
  /** Sequential index of this deployment's active key (the `#key-<n>` fragment). */
  OPENCRED_DIDWEB_KEY_INDEX: number;
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

  // Every key record needs the public JWK — it's both the key material we
  // publish and (for did:web) what goes into the did.json. PKCS#11 and
  // OS-cert signers don't surface a JWK; those operators publish manually.
  const jwk = signer.metadata.publicKeyJwk;
  if (!jwk) {
    logger.warn(
      { signerType: signer.type },
      "Cannot auto-publish — signer does not expose publicKeyJwk. " +
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

  // keyId is the verification method. For did:web it's `<did>#key-<index>`
  // (the configured OPENCRED_DIDWEB_KEY_INDEX); for did:key the signer's id
  // already carries the method-specific fragment.
  const keyId = isDidWeb
    ? didWebVerificationMethodIdForIndex(issuerDid, config.OPENCRED_DIDWEB_KEY_INDEX)
    : signer.id;
  const namespace = config.OPENCRED_DEDI_NAMESPACE;
  // Only embed a SINGLE-key did.json snapshot for a fresh issuer (index 0).
  // After a rotation (index > 0) the did.json is a multi-key document managed
  // by /v1/keys/rotate — embedding a single-key snapshot here would drop the
  // issuer's older keys from the resolver's view. The key RECORD is still
  // published either way.
  const hostDidDoc =
    isDidWeb && config.OPENCRED_DEDI_HOST_DID_DOC && config.OPENCRED_DIDWEB_KEY_INDEX === 0;

  const keyRecord: KeyRecord = {
    keyId,
    controllerDid: issuerDid,
    algorithm: String(signer.algorithm),
    publicKeyJwk: jwk,
    purpose: ["assertionMethod"],
    status: "active",
    // did:web + HOST_DID_DOC: embed the immutable did.json snapshot on the key
    // record itself (replaces the old separate did-documents publish). Only the
    // public JWK material goes in — generateDidWebDocumentMultiKey strips any
    // private members.
    ...(hostDidDoc
      ? {
          document: generateDidWebDocumentMultiKey(issuerDid, [
            { id: keyId, publicKeyJwk: jwk as JWK },
          ]) as unknown as Record<string, unknown>,
        }
      : {}),
  };

  try {
    const result = await dediClient.publishKey(keyRecord, namespace);
    if (hostDidDoc) {
      logger.info({ issuerDid }, "Issuer did.json snapshot embedded on the key record in DeDi");
    }
    logger.info(
      { issuerDid, keyId, recordName: result.recordName },
      "Issuer signing key auto-published to DeDi at startup",
    );
    return {
      didPublish: true,
      outcome: "published",
      issuerDid,
      recordName: result.recordName,
    };
  } catch (err) {
    if (err instanceof DeDiRecordExistsError) {
      // The key was published in a prior run; the key registry already has the
      // record, and (for did:web + HOST_DID_DOC) its immutable did.json snapshot
      // was written at first publish. There is nothing to refresh — from the
      // flag's POV this is success: verifiers can already resolve the key's
      // status (and document) via DeDi.
      logger.info({ issuerDid, keyId }, "Issuer key already published to DeDi (idempotent skip)");
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
