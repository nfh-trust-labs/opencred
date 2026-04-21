import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { serve } from "@hono/node-server";
import type { ServerType } from "@hono/node-server";
import {
  createTestApp,
  generateTestKey,
  FUNCTIONAL_IDENTITY_SUBJECT,
  DEFAULT_TEST_API_KEY,
} from "./helpers.js";
import type { TestKeyPair } from "./helpers.js";
import { setActiveSigner } from "../../signing/key-manager.js";

let server: ServerType;
let baseUrl: string;
let testKey: TestKeyPair;

beforeAll(async () => {
  testKey = generateTestKey();
  const app = createTestApp({ apiKey: DEFAULT_TEST_API_KEY });
  setActiveSigner(testKey.signer);

  server = serve({ fetch: app.fetch, port: 0 });

  await new Promise<void>((resolve) => {
    server.once("listening", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
});

afterAll(async () => {
  if (server) {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  }
});

function authHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${DEFAULT_TEST_API_KEY}`,
  };
}

describe("real HTTP server smoke tests", () => {
  it("GET /v1/health returns 200", async () => {
    const res = await fetch(`${baseUrl}/v1/health`, {
      headers: authHeaders(),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });

  it("issue -> verify round-trip over real HTTP", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];

    const issueRes = await fetch(`${baseUrl}/v1/credentials/issue`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid,
        credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "data-integrity",
      }),
    });
    expect(issueRes.status).toBe(200);

    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    const verifyRes = await fetch(`${baseUrl}/v1/credentials/verify`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ credential: JSON.stringify(issued.credential) }),
    });
    expect(verifyRes.status).toBe(200);

    const result = (await verifyRes.json()) as { valid: boolean; code: string };
    expect(result.valid).toBe(true);
    expect(result.code).toBe("VALID");
  });

  it("rejects unauthenticated requests with 401", async () => {
    const res = await fetch(`${baseUrl}/v1/credentials/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        issuerDid: "did:web:example.com",
        credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
      }),
    });
    expect(res.status).toBe(401);
  });

  it("returns 404 for unknown routes", async () => {
    const res = await fetch(`${baseUrl}/v1/nonexistent`, {
      headers: authHeaders(),
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("NOT_FOUND");
  });
});
