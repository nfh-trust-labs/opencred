/**
 * Tests for `POST /v1/dedi/namespace/ensure` (issue #507).
 *
 * Verifies the runtime namespace bootstrap endpoint:
 *   - 401 when the Bearer token is missing on an auth-enforced app.
 *   - 503 DEDI_NOT_CONFIGURED when no DeDi client is set on the singleton.
 *   - 200 happy path with mocked `DeDiClient.ensureRegistries` — asserts
 *     the response shape `{ namespace, registries }`.
 *   - 400 VALIDATION_ERROR when `namespace` is missing or empty.
 *   - 400 VALIDATION_ERROR when the body smuggles a PEM private-key block,
 *     exercising `rejectKeyMaterial()`.
 *
 * Mocking pattern mirrors the keys/publish tests in
 * `inline-schema-and-keys-dedi.test.ts`.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { createTestApp, generateTestKey, type TestKeyPair } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { setDeDiClient, resetDeDiClient } from "../dedi-singleton.js";
import type { Hono } from "hono";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
  resetDeDiClient();
});

// ---------------------------------------------------------------------------
// Auth (separate app with apiKey enforced)
// ---------------------------------------------------------------------------

describe("auth on POST /v1/dedi/namespace/ensure", () => {
  it("rejects requests without a Bearer token", async () => {
    const authedApp = createTestApp({ apiKey: "secret-token" });
    setActiveSigner(testKey.signer);
    const res = await authedApp.request("/v1/dedi/namespace/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ namespace: "bootcamp-2026" }),
    });
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// 503 — DeDi not configured
// ---------------------------------------------------------------------------

describe("POST /v1/dedi/namespace/ensure when DeDi is unconfigured", () => {
  it("returns 503 DEDI_NOT_CONFIGURED", async () => {
    const res = await app.request("/v1/dedi/namespace/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ namespace: "bootcamp-2026" }),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });
});

// ---------------------------------------------------------------------------
// 200 — happy path
// ---------------------------------------------------------------------------

describe("POST /v1/dedi/namespace/ensure when DeDi is configured", () => {
  it("ensures the namespace and returns the registry list", async () => {
    const calls: Array<{ namespace: string }> = [];
    const mockClient = {
      ensureRegistries: async (namespace: string) => {
        calls.push({ namespace });
        // The real implementation returns Promise<void>.
      },
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/dedi/namespace/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ namespace: "bootcamp-2026-04-29" }),
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as { namespace: string; registries: string[] };
    expect(body.namespace).toBe("bootcamp-2026-04-29");
    // The endpoint advertises the five registries that `ensureRegistries`
    // brings into existence — keep this list in lock-step with
    // `apps/server/src/routes/dedi.ts:ENSURED_REGISTRIES`.
    expect(body.registries).toEqual(
      expect.arrayContaining([
        "vc-revocation-registry",
        "opencred-key-registry",
        "did-documents",
        "schema_registry",
        "context_registry",
      ]),
    );
    expect(body.registries).toHaveLength(5);

    expect(calls).toHaveLength(1);
    expect(calls[0]!.namespace).toBe("bootcamp-2026-04-29");
  });
});

// ---------------------------------------------------------------------------
// 400 — validation
// ---------------------------------------------------------------------------

describe("POST /v1/dedi/namespace/ensure validation", () => {
  it("returns 400 when namespace is missing", async () => {
    const mockClient = { ensureRegistries: async () => {} } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/dedi/namespace/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("returns 400 when namespace is the empty string", async () => {
    const mockClient = { ensureRegistries: async () => {} } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/dedi/namespace/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ namespace: "" }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("rejects a payload that smuggles a PEM private key", async () => {
    const mockClient = { ensureRegistries: async () => {} } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/dedi/namespace/ensure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        namespace: "bootcamp-2026",
        // The PEM regex matches at any depth, including non-schema fields.
        secret:
          "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toMatch(/private/i);
  });
});
