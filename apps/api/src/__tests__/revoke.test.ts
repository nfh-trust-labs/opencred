import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { createCapabilityToken } from "@opencred/auth";
import { computeRevocationHash } from "@opencred/crypto";
import type { DeDiClient, RevocationHashRecord } from "@opencred/dedi-client";
import { DeDiClientError } from "@opencred/shared";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { createRevokeRoute } from "../routes/revoke.js";
import { makeTestLogger } from "./helpers.js";

interface ErrorBody {
  error: { code: string; message: string };
}

interface RevokeResponse {
  hash: string;
  status: string;
}

const logger = makeTestLogger();
const TEST_SECRET = new TextEncoder().encode("test-secret-key-that-is-at-least-32-bytes-long!!");

function makeDeDiClient(overrides: Partial<DeDiClient> = {}): DeDiClient {
  return {
    publishRevocationHash: vi.fn<(hash: string) => Promise<RevocationHashRecord>>().mockResolvedValue({
      hash: "abc123",
      revoked: true,
      revokedAt: new Date().toISOString(),
    }),
    queryRevocationHash: vi.fn(),
    resolveDID: vi.fn(),
    registerDelegation: vi.fn(),
    resolveDelegation: vi.fn(),
    ...overrides,
  } as unknown as DeDiClient;
}

function createTestApp(dediClient: DeDiClient) {
  const app = new Hono();
  app.use(
    "/credentials/revoke",
    authMiddleware(
      { verificationKey: TEST_SECRET, issuer: "opencred", algorithms: ["HS256"] },
      "credentials:revoke",
    ),
  );
  app.route("/", createRevokeRoute(dediClient));
  app.onError(errorHandler(logger));
  return app;
}

async function makeToken(scope: string[] = ["credentials:revoke"]) {
  return createCapabilityToken({
    subject: "user-1",
    issuer: "opencred",
    expiresInSeconds: 3600,
    scope,
    namespace: "default",
    signingKey: TEST_SECRET,
    algorithm: "HS256",
  });
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

describe("POST /credentials/revoke", () => {
  describe("revoke by hash", () => {
    it("revokes a credential by precomputed hash", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);
      const token = await makeToken();
      const hash = "a".repeat(64);

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credentialHash: hash }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as RevokeResponse;
      expect(body.hash).toBe(hash);
      expect(body.status).toBe("revoked");
      expect(dediClient.publishRevocationHash).toHaveBeenCalledWith(hash);
    });
  });

  describe("revoke by full credential", () => {
    it("computes hash from credential and revokes it", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);
      const token = await makeToken();
      const expectedHash = computeRevocationHash(SAMPLE_CREDENTIAL);

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credential: SAMPLE_CREDENTIAL }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as RevokeResponse;
      expect(body.hash).toBe(expectedHash);
      expect(body.status).toBe("revoked");
      expect(dediClient.publishRevocationHash).toHaveBeenCalledWith(expectedHash);
    });

    it("uses credentialHash when both are provided", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);
      const token = await makeToken();
      const hash = "b".repeat(64);

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credentialHash: hash, credential: SAMPLE_CREDENTIAL }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as RevokeResponse;
      expect(body.hash).toBe(hash);
      expect(dediClient.publishRevocationHash).toHaveBeenCalledWith(hash);
    });
  });

  describe("DeDi failure handling", () => {
    it("returns 502 when DeDi is unavailable", async () => {
      const dediClient = makeDeDiClient({
        publishRevocationHash: vi.fn().mockRejectedValue(
          new DeDiClientError("DeDi API network error", 502),
        ),
      } as unknown as Partial<DeDiClient>);
      const app = createTestApp(dediClient);
      const token = await makeToken();

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credentialHash: "c".repeat(64) }),
      });

      expect(res.status).toBe(502);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("DEDI_CLIENT_ERROR");
    });

    it("returns 504 when DeDi times out", async () => {
      const dediClient = makeDeDiClient({
        publishRevocationHash: vi.fn().mockRejectedValue(
          new DeDiClientError("DeDi API request timed out", 504),
        ),
      } as unknown as Partial<DeDiClient>);
      const app = createTestApp(dediClient);
      const token = await makeToken();

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credentialHash: "d".repeat(64) }),
      });

      expect(res.status).toBe(504);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("DEDI_CLIENT_ERROR");
    });
  });

  describe("authentication and authorization", () => {
    it("rejects requests without auth header", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credentialHash: "e".repeat(64) }),
      });

      expect(res.status).toBe(401);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("AUTHENTICATION_ERROR");
    });

    it("rejects tokens without revoke scope", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);
      const token = await makeToken(["credentials:read"]);

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credentialHash: "f".repeat(64) }),
      });

      expect(res.status).toBe(403);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("AUTHORIZATION_ERROR");
    });
  });

  describe("input validation", () => {
    it("rejects empty body", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);
      const token = await makeToken();

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({}),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("rejects invalid hash format (not hex)", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);
      const token = await makeToken();

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credentialHash: "not-a-valid-hex-hash" }),
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("rejects hash with wrong length", async () => {
      const dediClient = makeDeDiClient();
      const app = createTestApp(dediClient);
      const token = await makeToken();

      const res = await app.request("/credentials/revoke", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ credentialHash: "abcdef" }),
      });

      expect(res.status).toBe(400);
    });
  });
});
