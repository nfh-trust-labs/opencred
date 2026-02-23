import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createCapabilityToken } from "@opencred/auth";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

interface ErrorBody {
  error: { code: string; message: string };
}

const logger = makeTestLogger();

// 32-byte symmetric key for HS256
const TEST_SECRET = new TextEncoder().encode("test-secret-key-that-is-at-least-32-bytes-long!!");

function createTestApp(requiredScope?: string) {
  const app = new Hono();
  app.use(
    "/protected/*",
    authMiddleware(
      {
        verificationKey: TEST_SECRET,
        issuer: "opencred",
        algorithms: ["HS256"],
      },
      requiredScope,
    ),
  );
  app.get("/protected/resource", (c) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const payload = (c as any).get("tokenPayload");
    return c.json({ sub: payload.sub });
  });
  app.onError(errorHandler(logger));
  return app;
}

async function makeToken(
  overrides: {
    scope?: string[];
    namespace?: string;
    subject?: string;
    expiresInSeconds?: number;
  } = {},
) {
  return createCapabilityToken({
    subject: overrides.subject ?? "user-1",
    issuer: "opencred",
    expiresInSeconds: overrides.expiresInSeconds ?? 3600,
    scope: overrides.scope ?? ["credentials:read"],
    namespace: overrides.namespace ?? "default",
    signingKey: TEST_SECRET,
    algorithm: "HS256",
  });
}

describe("Auth middleware", () => {
  it("rejects requests without Authorization header", async () => {
    const app = createTestApp();
    const res = await app.request("/protected/resource");
    expect(res.status).toBe(401);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("AUTHENTICATION_ERROR");
    expect(body.error.message).toContain("Missing Authorization header");
  });

  it("rejects requests with invalid Authorization format", async () => {
    const app = createTestApp();
    const res = await app.request("/protected/resource", {
      headers: { Authorization: "Basic abc123" },
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("Invalid Authorization header format");
  });

  it("rejects expired tokens", async () => {
    const token = await makeToken({ expiresInSeconds: -1 });
    const app = createTestApp();
    const res = await app.request("/protected/resource", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(401);
  });

  it("allows valid tokens", async () => {
    const token = await makeToken({ subject: "user-42" });
    const app = createTestApp();
    const res = await app.request("/protected/resource", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sub: string };
    expect(body.sub).toBe("user-42");
  });

  it("rejects tokens missing required scope", async () => {
    const token = await makeToken({ scope: ["credentials:read"] });
    const app = createTestApp("credentials:write");
    const res = await app.request("/protected/resource", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("AUTHORIZATION_ERROR");
    expect(body.error.message).toContain("credentials:write");
  });

  it("allows tokens with matching required scope", async () => {
    const token = await makeToken({ scope: ["credentials:read", "credentials:write"] });
    const app = createTestApp("credentials:write");
    const res = await app.request("/protected/resource", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  it("rejects completely invalid tokens", async () => {
    const app = createTestApp();
    const res = await app.request("/protected/resource", {
      headers: { Authorization: "Bearer not-a-real-jwt-token" },
    });
    expect(res.status).toBe(401);
  });
});
