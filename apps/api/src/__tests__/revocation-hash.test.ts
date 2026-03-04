import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { computeRevocationHash } from "@opencred/crypto";
import { createRevocationHashRoute } from "../routes/revocation-hash.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

interface HashResponse {
  hash: string;
}

interface BatchHashResponse {
  hashes: Array<{ hash: string; index: number }>;
}

const logger = makeTestLogger();

function createTestApp() {
  const app = new Hono();
  app.route("/credentials/revocation-hash", createRevocationHashRoute());
  app.onError(errorHandler(logger));
  return app;
}

const SAMPLE_CREDENTIAL = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  type: ["VerifiableCredential"],
  issuer: "did:example:issuer",
  credentialSubject: {
    id: "did:example:subject",
    name: "Test Subject",
  },
};

describe("POST /credentials/revocation-hash", () => {
  it("computes hash from credential body", async () => {
    const app = createTestApp();

    const res = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: SAMPLE_CREDENTIAL }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as HashResponse;
    expect(body.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns deterministic hashes for the same credential", async () => {
    const app = createTestApp();

    const res1 = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: SAMPLE_CREDENTIAL }),
    });
    const res2 = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: SAMPLE_CREDENTIAL }),
    });

    const body1 = (await res1.json()) as HashResponse;
    const body2 = (await res2.json()) as HashResponse;
    expect(body1.hash).toBe(body2.hash);
  });

  it("matches computeRevocationHash output", async () => {
    const app = createTestApp();
    const expectedHash = computeRevocationHash(SAMPLE_CREDENTIAL);

    const res = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: SAMPLE_CREDENTIAL }),
    });

    const body = (await res.json()) as HashResponse;
    expect(body.hash).toBe(expectedHash);
  });

  it("does not require authentication", async () => {
    const app = createTestApp();

    const res = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: SAMPLE_CREDENTIAL }),
    });

    expect(res.status).toBe(200);
  });

  it("returns 400 for empty credential object", async () => {
    const app = createTestApp();

    const res = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: {} }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 when credential field is missing", async () => {
    const app = createTestApp();

    const res = await app.request("/credentials/revocation-hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
  });
});

describe("POST /credentials/revocation-hash/batch", () => {
  it("computes hashes for multiple credentials", async () => {
    const app = createTestApp();
    const cred1 = { ...SAMPLE_CREDENTIAL, id: "cred-1" };
    const cred2 = { ...SAMPLE_CREDENTIAL, id: "cred-2" };

    const res = await app.request("/credentials/revocation-hash/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credentials: [cred1, cred2] }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as BatchHashResponse;
    expect(body.hashes).toHaveLength(2);
    expect(body.hashes[0].index).toBe(0);
    expect(body.hashes[1].index).toBe(1);
    expect(body.hashes[0].hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.hashes[1].hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns hashes matching computeRevocationHash", async () => {
    const app = createTestApp();
    const cred1 = { ...SAMPLE_CREDENTIAL, id: "cred-1" };
    const cred2 = { ...SAMPLE_CREDENTIAL, id: "cred-2" };

    const res = await app.request("/credentials/revocation-hash/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credentials: [cred1, cred2] }),
    });

    const body = (await res.json()) as BatchHashResponse;
    expect(body.hashes[0].hash).toBe(computeRevocationHash(cred1));
    expect(body.hashes[1].hash).toBe(computeRevocationHash(cred2));
  });

  it("returns 400 for empty credentials array", async () => {
    const app = createTestApp();

    const res = await app.request("/credentials/revocation-hash/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credentials: [] }),
    });

    expect(res.status).toBe(400);
  });

  it("returns 400 when credentials field is missing", async () => {
    const app = createTestApp();

    const res = await app.request("/credentials/revocation-hash/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
  });

  it("does not require authentication", async () => {
    const app = createTestApp();

    const res = await app.request("/credentials/revocation-hash/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credentials: [SAMPLE_CREDENTIAL] }),
    });

    expect(res.status).toBe(200);
  });
});
