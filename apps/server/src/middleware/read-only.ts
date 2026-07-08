/**
 * Read-only mode enforcement (Tier 3 #9 of nfh-trust-labs/opencred#446).
 *
 * When `OPENCRED_READ_ONLY=true` the server refuses every endpoint that
 * mutates state — credential issuance, batch start, revocation publish, DID
 * publish — with `405 Method Not Allowed`. The read surface (verify, key
 * resolve, schemas, contexts, health, metrics) stays enabled. This lets an
 * operator deploy a "dedicated read tier" of replicas without the signing
 * key, fronting (or replacing) a CDN for verification traffic.
 *
 * SECURITY INVARIANT (CLAUDE.md, fail-closed):
 *
 *   The middleware is keyed off a *denylist* of write paths. Anything that
 *   matches the denylist is blocked; everything else is allowed. We deliberately
 *   do NOT use an allowlist for the read surface — if a new route is added
 *   later (say, `/credentials/reissue`) and the developer forgets to wire
 *   it into the denylist, the read-only replica will silently accept it.
 *
 *   To make the fail-closed property real, we also block any path that:
 *
 *     - sits under `/credentials/` and isn't on the explicit READ allowlist
 *       below, OR
 *     - sits under `/keys/` (or `/v1/keys/`) and is the `/publish` suffix,
 *       OR
 *     - starts with `/batch/` and isn't a GET (POST = start, GET = read).
 *
 *   In other words, the *category prefixes* (`/credentials/`, `/keys/`,
 *   `/batch/`) are treated as fail-closed by default for non-GET methods,
 *   with a small allowlist of known-safe READ operations inside each
 *   category. A new write endpoint added without updating either list is
 *   denied by default.
 */

import type { Context, Next } from "hono";
import { getConfig } from "../config.js";

/**
 * Method+path pairs that are ALWAYS safe under read-only mode. These map
 * one-to-one onto idempotent endpoints — the credential `verify` is a POST
 * but is non-mutating (the credential payload is in the body for length
 * reasons; the server never persists it).
 *
 * Updates to this list MUST be paired with: (a) a test in
 * `apps/server/src/__tests__/read-only.test.ts` covering the new path,
 * and (b) a deployment-docs entry confirming that the path is suitable
 * for a read-tier replica.
 */
const READ_OPERATIONS: ReadonlySet<string> = new Set([
  // Verify is POST-with-body but read-only by contract.
  "POST /credentials/verify",
  "POST /v1/credentials/verify",
  // Revocation status check is a read.
  "POST /credentials/revocation-status",
  "POST /v1/credentials/revocation-status",
  // Hash computation is local and deterministic.
  "POST /credentials/revocation-hash",
  "POST /v1/credentials/revocation-hash",
  "POST /credentials/revocation-hash/batch",
  "POST /v1/credentials/revocation-hash/batch",
  // Keys: resolve is a read; publish is a write.
  "POST /keys/resolve",
  "POST /v1/keys/resolve",
  "GET /keys/resolve",
  "GET /v1/keys/resolve",
]);

/**
 * Whether a request should be allowed under read-only mode.
 *
 * Decision tree:
 *
 *  1. GET / HEAD / OPTIONS — always allowed (RFC 7231 marks these as safe).
 *  2. Explicit READ_OPERATIONS — allowed.
 *  3. Any other method that lands on a denylisted category prefix
 *     (`/credentials/`, `/keys/`, `/batch/`, `/v1/credentials/`,
 *     `/v1/keys/`, `/v1/batch/`) — denied.
 *  4. Anything else (e.g. `/health`, `/metrics`, `/schemas/generate` —
 *     wait, that last one is POST → caught by the prefix check below)
 *     — allowed.
 *
 *  `POST /schemas/generate` is technically idempotent (it derives a
 *  schema from input fields) but we treat the `/schemas/` POST surface
 *  as a write to keep the fail-closed property real — if a future PR
 *  adds `POST /schemas/<id>` to upload a schema, the read-only replica
 *  must not accept it. Operators who want the schema-generator on the
 *  read tier should mount a separate "schema-utilities" tier; the cost
 *  of one extra service is small next to silently turning a read tier
 *  into a write surface.
 */
export function isAllowedUnderReadOnly(method: string, path: string): boolean {
  const upperMethod = method.toUpperCase();
  if (upperMethod === "GET" || upperMethod === "HEAD" || upperMethod === "OPTIONS") {
    return true;
  }
  if (READ_OPERATIONS.has(`${upperMethod} ${path}`)) {
    return true;
  }
  // Fail-closed prefixes. Any non-GET request landing here without an
  // explicit READ_OPERATIONS exemption is treated as a write.
  //
  // Every prefix is normalized to the trailing-slash form so:
  //  - `path.startsWith("/keys/")` cannot accidentally match a future
  //    `/keysomething` route, and
  //  - the list is uniform — `/credentials/` and `/v1/keys/` follow the
  //    same shape, avoiding cosmetic drift (the original list mixed
  //    trailing-slash and bare forms, flagged in follow-up #586).
  //
  // Routes whose path is exactly the bare prefix (e.g. `GET /keys` for the
  // key-metadata endpoint) are GETs and are short-circuited above as safe
  // methods, so the trailing-slash normalization does not regress them.
  const WRITE_PREFIXES = [
    "/credentials/",
    "/v1/credentials/",
    "/keys/",
    "/v1/keys/",
    "/batch/",
    "/v1/batch/",
    "/schemas/",
    "/v1/schemas/",
    "/dedi/",
    "/v1/dedi/",
  ];
  for (const prefix of WRITE_PREFIXES) {
    if (path.startsWith(prefix)) {
      return false;
    }
  }
  // Anything else (health, metrics, root) is allowed.
  return true;
}

/**
 * Hono middleware that enforces read-only mode when the config flag is set.
 *
 * The check is short-circuit when the flag is off (default), so production
 * deployments that don't use this feature pay zero overhead.
 */
export async function readOnlyMiddleware(c: Context, next: Next): Promise<Response | void> {
  const config = getConfig();
  if (!config.OPENCRED_READ_ONLY) {
    return next();
  }
  if (isAllowedUnderReadOnly(c.req.method, c.req.path)) {
    return next();
  }
  return c.json(
    {
      error: {
        code: "READ_ONLY_MODE",
        message:
          "This server is in read-only mode (OPENCRED_READ_ONLY=true). " +
          "Write endpoints (issuance, batch, revocation, key publish) are disabled. " +
          "Send write traffic to a non-read-only replica.",
      },
    },
    405,
  );
}
