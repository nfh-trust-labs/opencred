/**
 * DeDi runtime endpoints — operations that aren't tied to a specific registry.
 *
 *   `POST /dedi/namespace/ensure` — idempotently create a namespace and the
 *   four DeDi registries OpenCred relies on (revocation, public-key, schema,
 *   context). Wraps the same `dediClient.ensureRegistries(...)` helper that
 *   runs once at server startup, so operators can bootstrap additional
 *   namespaces at runtime without restarting the container.
 *
 * SECURITY INVARIANTS:
 *  - The body only carries a namespace name. The recursive
 *    `rejectKeyMaterial()` guard runs first as defense-in-depth so a payload
 *    smuggling a PEM private-key block (or a forbidden `privateKey` field) is
 *    rejected with 400 before any DeDi call is made.
 *  - When DeDi is not configured the endpoint returns `503 DEDI_NOT_CONFIGURED`
 *    instead of silently no-op'ing — same fail-closed pattern as the
 *    revocation and public-key routes.
 *  - Underlying DeDi errors propagate to the global `errorHandler` via the
 *    `DeDiClientError` / `OpenCredError` hierarchy. We do NOT craft custom
 *    error bodies here — that hierarchy is what guarantees no DeDi auth
 *    tokens or internal paths leak to clients (CLAUDE.md rule 5).
 */

import { Hono } from "hono";
import { z } from "zod";
import {
  REVOCATION_REGISTRY,
  OPENCRED_KEY_REGISTRY,
  DID_DOCUMENTS_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
} from "@opencred/dedi-client";
import { getDeDiClient } from "../dedi-singleton.js";
import { rejectKeyMaterial } from "./credentials.js";

const dedi = new Hono();

const ensureNamespaceSchema = z.object({
  /**
   * The DeDi namespace to ensure. Created if missing; the five registries
   * OpenCred reads/writes are then created (or left alone if they already
   * exist — `ensureRegistries` ignores 409 conflicts).
   */
  namespace: z.string().min(1).max(200),
});

/**
 * The list of registry names that `DeDiClient.ensureRegistries` brings into
 * existence on the target namespace. Kept here (rather than re-exporting from
 * the dedi-client package) so the response shape is locally auditable and the
 * test suite can assert on it without importing client internals.
 *
 * Stays in lock-step with `packages/dedi-client/src/adapter/client.ts:ensureRegistries`.
 */
const ENSURED_REGISTRIES: readonly string[] = [
  REVOCATION_REGISTRY,
  OPENCRED_KEY_REGISTRY,
  DID_DOCUMENTS_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
];

/**
 * POST /dedi/namespace/ensure
 *
 * Idempotently create a DeDi namespace and the five registries OpenCred uses.
 *
 * Request body:
 *   { namespace: string }
 *
 * Response (200):
 *   { namespace: string, registries: string[] }
 *
 * Response (503): DeDi not configured.
 *
 * Underlying DeDi failures (auth, network, 5xx) flow through the global
 * `errorHandler` as `DEDI_CLIENT_ERROR` — they are not swallowed here.
 */
dedi.post("/dedi/namespace/ensure", async (c) => {
  const body = await c.req.json();
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = ensureNamespaceSchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) {
    return c.json(
      {
        error: {
          code: "DEDI_NOT_CONFIGURED",
          message:
            "DeDi is not configured. Set OPENCRED_DEDI_BASE_URL, OPENCRED_DEDI_AUTH_TYPE, " +
            "OPENCRED_DEDI_NAMESPACE, and the matching auth secret to enable this endpoint.",
        },
      },
      503,
    );
  }

  // ensureRegistries returns Promise<void>; on success every registry in
  // ENSURED_REGISTRIES exists in the target namespace. Any underlying DeDi
  // failure is thrown and surfaces via the global errorHandler — we do NOT
  // catch it here so callers can distinguish a real 4xx/5xx from a 200.
  await dediClient.ensureRegistries(parsed.namespace);

  return c.json({
    namespace: parsed.namespace,
    registries: [...ENSURED_REGISTRIES],
  });
});

export { dedi };
