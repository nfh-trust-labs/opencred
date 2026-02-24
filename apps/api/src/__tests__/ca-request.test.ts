import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import {
  createCaRequestRoutes,
  type CertificateAuthorityAdapter,
  type DscRequestParams,
  type DscRequestResult,
  type DscRequestStatus,
  type DscRequestStatusCode,
  type CaRequestRoutesDeps,
} from "../routes/ca-request.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

// --- Response types ---

interface ErrorBody {
  error: { code: string; message: string };
}

interface CaRequestResponseBody {
  requestId: string;
  status: string;
  estimatedCompletion?: string;
}

interface CaStatusResponseBody {
  requestId: string;
  status: string;
  certificateChain?: string[];
  rejectionReason?: string;
  updatedAt?: string;
}

// --- Mock adapter ---

function createMockAdapter(
  overrides: Partial<CertificateAuthorityAdapter> = {},
): CertificateAuthorityAdapter {
  return {
    requestDSC:
      overrides.requestDSC ??
      vi.fn().mockResolvedValue({
        requestId: "req-001",
        status: "pending" as DscRequestStatusCode,
        estimatedCompletion: "2026-03-01T00:00:00Z",
      } satisfies DscRequestResult),

    checkStatus:
      overrides.checkStatus ??
      vi.fn().mockResolvedValue({
        requestId: "req-001",
        status: "pending" as DscRequestStatusCode,
        updatedAt: "2026-02-24T12:00:00Z",
      } satisfies DscRequestStatus),
  };
}

// --- Test app factory ---

function createTestApp(overrides: Partial<CaRequestRoutesDeps> = {}) {
  const app = new Hono();
  app.route(
    "/onboarding",
    createCaRequestRoutes({
      caAdapter: overrides.caAdapter,
    }),
  );
  app.onError(errorHandler(logger));
  return app;
}

// --- Valid request payloads ---

function makeValidCaRequest(): Record<string, unknown> {
  return {
    csr: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBkTCB...\n-----END CERTIFICATE REQUEST-----",
    countryCode: "NF",
    organisation: "Norfolk Island Immigration",
    commonName: "NF Document Signer 2025",
  };
}

function makeValidStatusRequest(): Record<string, unknown> {
  return { requestId: "req-001" };
}

// ========================
// POST /onboarding/ca-request
// ========================

describe("POST /onboarding/ca-request", () => {
  describe("no adapter configured → 501", () => {
    it("returns 501 when no CA adapter is registered", async () => {
      const app = createTestApp(); // no adapter
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidCaRequest()),
      });
      expect(res.status).toBe(501);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("NOT_IMPLEMENTED");
      expect(body.error.message).toContain("Certificate Authority adapter is not configured");
    });

    it("does not leak internal details in 501 error", async () => {
      const app = createTestApp();
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidCaRequest()),
      });
      expect(res.status).toBe(501);
      const body = (await res.json()) as ErrorBody;
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toContain("/Users/");
      expect(bodyStr).not.toContain("node_modules");
      expect(bodyStr).not.toContain("stack");
    });
  });

  describe("input validation", () => {
    it("returns 400 for empty body", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for missing csr", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          countryCode: "NF",
          organisation: "Test Org",
          commonName: "Test CN",
        }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for invalid countryCode (lowercase)", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const req = { ...makeValidCaRequest(), countryCode: "nf" };
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
      expect(res.status).toBe(400);
    });

    it("returns 400 for countryCode longer than 2 characters", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const req = { ...makeValidCaRequest(), countryCode: "NFF" };
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
      expect(res.status).toBe(400);
    });

    it("returns 400 for empty organisation", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const req = { ...makeValidCaRequest(), organisation: "" };
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
      expect(res.status).toBe(400);
    });

    it("returns 400 for empty commonName", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const req = { ...makeValidCaRequest(), commonName: "" };
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("with mock adapter → successful DSC request", () => {
    it("returns 202 with requestId and status", async () => {
      const adapter = createMockAdapter();
      const app = createTestApp({ caAdapter: adapter });
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidCaRequest()),
      });
      expect(res.status).toBe(202);
      const body = (await res.json()) as CaRequestResponseBody;
      expect(body.requestId).toBe("req-001");
      expect(body.status).toBe("pending");
      expect(body.estimatedCompletion).toBe("2026-03-01T00:00:00Z");
    });

    it("passes correct params to the adapter", async () => {
      const requestDSC = vi.fn().mockResolvedValue({
        requestId: "req-002",
        status: "pending" as DscRequestStatusCode,
      } satisfies DscRequestResult);
      const adapter = createMockAdapter({ requestDSC });
      const app = createTestApp({ caAdapter: adapter });
      const reqPayload = makeValidCaRequest();
      await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqPayload),
      });

      expect(requestDSC).toHaveBeenCalledOnce();
      const passedParams = requestDSC.mock.calls[0][0] as DscRequestParams;
      expect(passedParams.csr).toBe(reqPayload.csr);
      expect(passedParams.countryCode).toBe(reqPayload.countryCode);
      expect(passedParams.organisation).toBe(reqPayload.organisation);
      expect(passedParams.commonName).toBe(reqPayload.commonName);
    });

    it("omits estimatedCompletion from response when adapter does not provide it", async () => {
      const adapter = createMockAdapter({
        requestDSC: vi.fn().mockResolvedValue({
          requestId: "req-003",
          status: "pending" as DscRequestStatusCode,
        } satisfies DscRequestResult),
      });
      const app = createTestApp({ caAdapter: adapter });
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidCaRequest()),
      });
      expect(res.status).toBe(202);
      const body = (await res.json()) as CaRequestResponseBody;
      expect(body.requestId).toBe("req-003");
      expect(body).not.toHaveProperty("estimatedCompletion");
    });

    it("accepts optional keyAlgorithm and validityDays fields", async () => {
      const requestDSC = vi.fn().mockResolvedValue({
        requestId: "req-004",
        status: "pending" as DscRequestStatusCode,
      } satisfies DscRequestResult);
      const adapter = createMockAdapter({ requestDSC });
      const app = createTestApp({ caAdapter: adapter });
      const res = await app.request("/onboarding/ca-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...makeValidCaRequest(),
          keyAlgorithm: "EC-P256",
          validityDays: 365,
        }),
      });
      expect(res.status).toBe(202);
      const passedParams = requestDSC.mock.calls[0][0] as DscRequestParams;
      expect(passedParams.keyAlgorithm).toBe("EC-P256");
      expect(passedParams.validityDays).toBe(365);
    });
  });
});

// ========================
// POST /onboarding/ca-request/status
// ========================

describe("POST /onboarding/ca-request/status", () => {
  describe("no adapter configured → 501", () => {
    it("returns 501 when no CA adapter is registered", async () => {
      const app = createTestApp(); // no adapter
      const res = await app.request("/onboarding/ca-request/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidStatusRequest()),
      });
      expect(res.status).toBe(501);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("NOT_IMPLEMENTED");
    });
  });

  describe("input validation", () => {
    it("returns 400 for empty body", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const res = await app.request("/onboarding/ca-request/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for empty requestId", async () => {
      const app = createTestApp({ caAdapter: createMockAdapter() });
      const res = await app.request("/onboarding/ca-request/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requestId: "" }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("with mock adapter → status check", () => {
    it("returns pending status", async () => {
      const adapter = createMockAdapter();
      const app = createTestApp({ caAdapter: adapter });
      const res = await app.request("/onboarding/ca-request/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidStatusRequest()),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as CaStatusResponseBody;
      expect(body.requestId).toBe("req-001");
      expect(body.status).toBe("pending");
      expect(body.updatedAt).toBe("2026-02-24T12:00:00Z");
    });

    it("returns issued status with certificate chain", async () => {
      const adapter = createMockAdapter({
        checkStatus: vi.fn().mockResolvedValue({
          requestId: "req-001",
          status: "issued" as DscRequestStatusCode,
          certificateChain: ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
          updatedAt: "2026-02-25T10:00:00Z",
        } satisfies DscRequestStatus),
      });
      const app = createTestApp({ caAdapter: adapter });
      const res = await app.request("/onboarding/ca-request/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidStatusRequest()),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as CaStatusResponseBody;
      expect(body.status).toBe("issued");
      expect(body.certificateChain).toHaveLength(1);
      expect(body.certificateChain![0]).toContain("BEGIN CERTIFICATE");
    });

    it("returns rejected status with reason", async () => {
      const adapter = createMockAdapter({
        checkStatus: vi.fn().mockResolvedValue({
          requestId: "req-001",
          status: "rejected" as DscRequestStatusCode,
          rejectionReason: "CSR does not meet policy requirements",
          updatedAt: "2026-02-25T10:00:00Z",
        } satisfies DscRequestStatus),
      });
      const app = createTestApp({ caAdapter: adapter });
      const res = await app.request("/onboarding/ca-request/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(makeValidStatusRequest()),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as CaStatusResponseBody;
      expect(body.status).toBe("rejected");
      expect(body.rejectionReason).toBe("CSR does not meet policy requirements");
    });

    it("passes the requestId to the adapter", async () => {
      const checkStatus = vi.fn().mockResolvedValue({
        requestId: "req-xyz",
        status: "approved" as DscRequestStatusCode,
      } satisfies DscRequestStatus);
      const adapter = createMockAdapter({ checkStatus });
      const app = createTestApp({ caAdapter: adapter });
      await app.request("/onboarding/ca-request/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requestId: "req-xyz" }),
      });
      expect(checkStatus).toHaveBeenCalledWith("req-xyz");
    });
  });
});

// ========================
// Type definitions compile check
// ========================

describe("CertificateAuthorityAdapter type definitions", () => {
  it("mock adapter satisfies the CertificateAuthorityAdapter interface", () => {
    const adapter: CertificateAuthorityAdapter = createMockAdapter();
    expect(typeof adapter.requestDSC).toBe("function");
    expect(typeof adapter.checkStatus).toBe("function");
  });

  it("DscRequestParams shape is enforced by TypeScript (runtime shape check)", () => {
    const params: DscRequestParams = {
      csr: "pem-data",
      countryCode: "NF",
      organisation: "Test Org",
      commonName: "Test CN",
    };
    expect(params.csr).toBeDefined();
    expect(params.countryCode).toBeDefined();
    expect(params.organisation).toBeDefined();
    expect(params.commonName).toBeDefined();
  });

  it("DscRequestResult shape is complete", () => {
    const result: DscRequestResult = {
      requestId: "r-1",
      status: "pending",
      estimatedCompletion: "2026-03-01T00:00:00Z",
    };
    expect(result.requestId).toBe("r-1");
    expect(result.status).toBe("pending");
    expect(result.estimatedCompletion).toBeDefined();
  });

  it("DscRequestStatus shape supports all status codes", () => {
    const statuses: DscRequestStatusCode[] = ["pending", "approved", "rejected", "issued"];
    for (const s of statuses) {
      const status: DscRequestStatus = { requestId: "r-1", status: s };
      expect(status.status).toBe(s);
    }
  });
});
