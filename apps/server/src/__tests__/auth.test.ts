/**
 * Auth middleware tests.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { createTestApp, generateTestKey } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import type { Hono } from "hono";

const TEST_API_KEY = "test-api-key-12345";
const testKey = generateTestKey();

describe("Auth middleware — with API key configured", () => {
  let app: Hono;

  beforeEach(() => {
    app = createTestApp({ apiKey: TEST_API_KEY });
    setActiveSigner(testKey.signer);
  });

  it("rejects requests without Authorization header with 401", async () => {
    const res = await app.request("/schemas");
    expect(res.status).toBe(401);

    const body = (await res.json()) as Record<string, unknown>;
    expect((body as { error: { code: string } }).error.code).toBe("AUTHENTICATION_ERROR");
  });

  it("rejects requests with wrong Bearer token with 401", async () => {
    const res = await app.request("/schemas", {
      headers: { Authorization: "Bearer wrong-key" },
    });
    expect(res.status).toBe(401);

    const body = (await res.json()) as Record<string, unknown>;
    expect((body as { error: { code: string } }).error.code).toBe("AUTHENTICATION_ERROR");
  });

  it("rejects requests with invalid Authorization format with 401", async () => {
    const res = await app.request("/schemas", {
      headers: { Authorization: "Basic abc123" },
    });
    expect(res.status).toBe(401);
  });

  it("passes requests with correct Bearer token", async () => {
    const res = await app.request("/schemas", {
      headers: { Authorization: `Bearer ${TEST_API_KEY}` },
    });
    expect(res.status).toBe(200);
  });

  it("allows /health without auth even when API key is set", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
  });
});

describe("Auth middleware — without API key configured", () => {
  let app: Hono;

  beforeEach(() => {
    app = createTestApp({ apiKey: undefined });
    setActiveSigner(testKey.signer);
  });

  it("allows all requests when no API key is configured", async () => {
    const res = await app.request("/schemas");
    expect(res.status).toBe(200);
  });

  it("allows /health without auth", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);
  });
});
