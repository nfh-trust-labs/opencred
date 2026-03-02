import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createSchemaStubRoutes, createDelegationStubRoutes, createRevocationStatusStubRoutes } from "../routes/stubs.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

function createTestApp() {
  const app = new Hono();
  app.route("/schemas", createSchemaStubRoutes());
  app.route("/delegations", createDelegationStubRoutes());
  app.route("/revocation-status", createRevocationStatusStubRoutes());
  app.onError(errorHandler(logger));
  return app;
}

interface ErrorBody { error: { code: string; message: string } }

describe("Stub routes (#132)", () => {
  const app = createTestApp();

  it("GET /schemas returns 501", async () => {
    const res = await app.request("/schemas");
    expect(res.status).toBe(501);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("NOT_IMPLEMENTED");
  });

  it("GET /schemas/:id returns 501", async () => {
    const res = await app.request("/schemas/test-id");
    expect(res.status).toBe(501);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("NOT_IMPLEMENTED");
  });

  it("POST /schemas returns 501", async () => {
    const res = await app.request("/schemas", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    expect(res.status).toBe(501);
  });

  it("GET /delegations returns 501", async () => {
    const res = await app.request("/delegations");
    expect(res.status).toBe(501);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("NOT_IMPLEMENTED");
  });

  it("POST /delegations returns 501", async () => {
    const res = await app.request("/delegations", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    expect(res.status).toBe(501);
  });

  it("GET /delegations/:id returns 501", async () => {
    const res = await app.request("/delegations/del-123");
    expect(res.status).toBe(501);
  });

  it("DELETE /delegations/:id returns 501", async () => {
    const res = await app.request("/delegations/del-123", { method: "DELETE" });
    expect(res.status).toBe(501);
  });

  it("GET /revocation-status/:hash returns 501", async () => {
    const res = await app.request("/revocation-status/abc123");
    expect(res.status).toBe(501);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("NOT_IMPLEMENTED");
  });
});
