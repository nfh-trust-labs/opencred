export * from "./errors.js";
// NOTE: `./config.js` is intentionally NOT re-exported from the package
// index. It defines a process-environment zod schema with server-only
// configuration fields (signing-key paths, JWT_SECRET, CORS_ORIGIN,
// MAX_BATCH_SIZE, etc.) and is currently consumed by nothing in the
// workspace — the server has its own `apps/server/src/config.ts`. Leaving
// the re-export in place caused this module to be pulled into every
// consumer that imports anything from `@opencred/shared` (e.g. the verify
// SDK bundle), leaking server config schema definitions and internal
// review comments into the published artefact. If a future consumer
// genuinely needs the schema, import it from `@opencred/shared/dist/config.js`
// or move it into its own subpath export.
export { isPrivateIP, resolveDnsForSsrf } from "./ssrf.js";
export { canonicalJsonSha256 } from "./hash.js";
export { detectCredentialInputFormat, isPdfBytes } from "./credential-format.js";
export type { CredentialInputFormat } from "./credential-format.js";
export { MAX_JWT_BYTES, assertJwtSize } from "./jwt-size.js";
export { ok, err, isOk } from "./result.js";
export type { Result, Ok, Err } from "./result.js";
// Tier 3 #8 of #446 — queue wire-format. Pure types, no runtime cost.
// Not yet consumed in production; ships with spike-1 so the impl PR can
// pick it up without re-litigating the message shape.
export type {
  BatchJob,
  BatchJobConfig,
  BatchJobProofFormat,
  BatchJobRow,
  WebhookDeliveryJob,
} from "./batch-job.js";
export { BATCH_QUEUE_NAME, WEBHOOK_QUEUE_NAME } from "./batch-job.js";
