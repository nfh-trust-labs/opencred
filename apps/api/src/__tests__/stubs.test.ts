import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createRevocationStatusStubRoutes } from "../routes/stubs.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

function createTestApp() {
  const app = new Hono();
  app.route("/revocation-status", createRevocationStatusStubRoutes());
  app.onError(errorHandler(logger));
  return app;
}

interface ErrorBody { error: { code: string; message: string } }

describe("Stub routes (#132)", () => {
  const app = createTestApp();

  it("GET /revocation-status/:hash returns 501", async () => {
    const res = await app.request("/revocation-status/abc123");
    expect(res.status).toBe(501);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("NOT_IMPLEMENTED");
  });
});
