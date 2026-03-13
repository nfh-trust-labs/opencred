import { describe, it, expect } from "vitest";
import { OpenCredError } from "@opencred/shared";
import {
  createCaAdapter,
  NoopCaAdapter,
  CaAdapterError,
  CaAdapterNotConfiguredError,
  CaRequestNotFoundError,
} from "../index.js";
import type {
  CertificateAuthorityAdapter,
  DscRequest,
  DscRequestResult,
  DscRequestStatus,
} from "../index.js";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const validDscRequest: DscRequest = {
  subject: {
    organizationName: "Test Organization",
    country: "NL",
    domain: "test.example.com",
  },
  csr: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBfake...\n-----END CERTIFICATE REQUEST-----",
  keyAlgorithm: "ES256",
};

// ---------------------------------------------------------------------------
// Error hierarchy tests
// ---------------------------------------------------------------------------

describe("CaAdapterError", () => {
  it("extends OpenCredError", () => {
    const err = new CaAdapterError("test error");
    expect(err).toBeInstanceOf(OpenCredError);
    expect(err).toBeInstanceOf(CaAdapterError);
  });

  it("has correct code and default status", () => {
    const err = new CaAdapterError("something failed");
    expect(err.code).toBe("CA_ADAPTER_ERROR");
    expect(err.statusCode).toBe(502);
    expect(err.name).toBe("CaAdapterError");
    expect(err.message).toBe("something failed");
  });

  it("accepts a custom status code", () => {
    const err = new CaAdapterError("bad request", 400);
    expect(err.statusCode).toBe(400);
  });

  it("toJSON does not leak internals", () => {
    const err = new CaAdapterError("oops");
    const json = err.toJSON();
    expect(json).toEqual({
      error: {
        code: "CA_ADAPTER_ERROR",
        message: "oops",
      },
    });
    expect(JSON.stringify(json)).not.toContain("stack");
  });
});

describe("CaAdapterNotConfiguredError", () => {
  it("extends CaAdapterError with 501 status", () => {
    const err = new CaAdapterNotConfiguredError();
    expect(err).toBeInstanceOf(CaAdapterError);
    expect(err.statusCode).toBe(501);
    expect(err.name).toBe("CaAdapterNotConfiguredError");
    expect(err.message).toBe("CA adapter is not configured");
  });

  it("accepts a custom message", () => {
    const err = new CaAdapterNotConfiguredError("custom msg");
    expect(err.message).toBe("custom msg");
  });
});

describe("CaRequestNotFoundError", () => {
  it("extends CaAdapterError with 404 status", () => {
    const err = new CaRequestNotFoundError("req-123");
    expect(err).toBeInstanceOf(CaAdapterError);
    expect(err.statusCode).toBe(404);
    expect(err.name).toBe("CaRequestNotFoundError");
    expect(err.message).toBe("DSC request not found: req-123");
  });
});

// ---------------------------------------------------------------------------
// NoopCaAdapter tests
// ---------------------------------------------------------------------------

describe("NoopCaAdapter", () => {
  const adapter = new NoopCaAdapter();

  it("has name 'No-Op'", () => {
    expect(adapter.name).toBe("No-Op");
  });

  it("implements CertificateAuthorityAdapter", () => {
    // Type-level check — if this compiles, the interface is satisfied
    const _typed: CertificateAuthorityAdapter = adapter;
    expect(_typed).toBe(adapter);
  });

  it("requestDSC throws CaAdapterNotConfiguredError", async () => {
    await expect(adapter.requestDSC(validDscRequest)).rejects.toThrow(
      CaAdapterNotConfiguredError,
    );
  });

  it("requestDSC error message mentions extension point", async () => {
    await expect(adapter.requestDSC(validDscRequest)).rejects.toThrow(
      /extension point/i,
    );
  });

  it("checkStatus throws CaAdapterNotConfiguredError", async () => {
    await expect(adapter.checkStatus("any-id")).rejects.toThrow(
      CaAdapterNotConfiguredError,
    );
  });

  it("checkStatus error message mentions extension point", async () => {
    await expect(adapter.checkStatus("any-id")).rejects.toThrow(
      /extension point/i,
    );
  });
});

// ---------------------------------------------------------------------------
// Factory tests
// ---------------------------------------------------------------------------

describe("createCaAdapter", () => {
  it("returns NoopCaAdapter when called with no config", () => {
    const adapter = createCaAdapter();
    expect(adapter).toBeInstanceOf(NoopCaAdapter);
  });

  it("returns NoopCaAdapter when type is 'noop'", () => {
    const adapter = createCaAdapter({ type: "noop" });
    expect(adapter).toBeInstanceOf(NoopCaAdapter);
  });

  it("throws CaAdapterError for unknown adapter type", () => {
    expect(() => createCaAdapter({ type: "unknown-ca" })).toThrow(
      CaAdapterError,
    );
  });

  it("error message includes the unknown type name", () => {
    expect(() => createCaAdapter({ type: "acme-corp" })).toThrow(
      /acme-corp/,
    );
  });
});

// ---------------------------------------------------------------------------
// Interface contract tests (using a mock adapter)
// ---------------------------------------------------------------------------

describe("CertificateAuthorityAdapter contract", () => {
  /**
   * A mock adapter that simulates a successful CA flow.
   * Used to verify the interface contract works end-to-end.
   */
  class MockCaAdapter implements CertificateAuthorityAdapter {
    readonly name = "Mock CA";
    private readonly requests = new Map<string, DscRequestStatus>();

    async requestDSC(request: DscRequest): Promise<DscRequestResult> {
      if (!request.csr) {
        throw new CaAdapterError("CSR is required", 400);
      }
      if (!request.subject.organizationName) {
        throw new CaAdapterError("Organization name is required", 400);
      }

      const requestId = `mock-${Date.now()}`;
      this.requests.set(requestId, {
        requestId,
        status: "pending",
        updatedAt: new Date().toISOString(),
      });

      return {
        requestId,
        status: "pending",
        estimatedCompletion: "PT24H",
        message: "Request submitted",
      };
    }

    async checkStatus(requestId: string): Promise<DscRequestStatus> {
      const status = this.requests.get(requestId);
      if (!status) {
        throw new CaRequestNotFoundError(requestId);
      }
      return status;
    }

    // Test helper: simulate the CA issuing a certificate
    simulateIssuance(requestId: string, certificate: string): void {
      this.requests.set(requestId, {
        requestId,
        status: "issued",
        certificate,
        updatedAt: new Date().toISOString(),
      });
    }

    // Test helper: simulate the CA rejecting a request
    simulateRejection(requestId: string, reason: string): void {
      this.requests.set(requestId, {
        requestId,
        status: "rejected",
        rejectionReason: reason,
        updatedAt: new Date().toISOString(),
      });
    }
  }

  it("requestDSC returns a result with requestId and status", async () => {
    const adapter = new MockCaAdapter();
    const result = await adapter.requestDSC(validDscRequest);

    expect(result.requestId).toBeDefined();
    expect(typeof result.requestId).toBe("string");
    expect(result.status).toBe("pending");
  });

  it("checkStatus returns the current status", async () => {
    const adapter = new MockCaAdapter();
    const result = await adapter.requestDSC(validDscRequest);
    const status = await adapter.checkStatus(result.requestId);

    expect(status.requestId).toBe(result.requestId);
    expect(status.status).toBe("pending");
  });

  it("checkStatus throws CaRequestNotFoundError for unknown requestId", async () => {
    const adapter = new MockCaAdapter();

    await expect(adapter.checkStatus("nonexistent")).rejects.toThrow(
      CaRequestNotFoundError,
    );
  });

  it("full flow: request -> pending -> issued with certificate", async () => {
    const adapter = new MockCaAdapter();
    const fakeCert =
      "-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----";

    // Step 1: Request a DSC
    const result = await adapter.requestDSC(validDscRequest);
    expect(result.status).toBe("pending");

    // Step 2: Check status (still pending)
    const pending = await adapter.checkStatus(result.requestId);
    expect(pending.status).toBe("pending");
    expect(pending.certificate).toBeUndefined();

    // Step 3: CA issues the certificate
    adapter.simulateIssuance(result.requestId, fakeCert);

    // Step 4: Check status (now issued)
    const issued = await adapter.checkStatus(result.requestId);
    expect(issued.status).toBe("issued");
    expect(issued.certificate).toBe(fakeCert);
  });

  it("full flow: request -> pending -> rejected", async () => {
    const adapter = new MockCaAdapter();

    const result = await adapter.requestDSC(validDscRequest);
    adapter.simulateRejection(
      result.requestId,
      "Organization not verified",
    );

    const rejected = await adapter.checkStatus(result.requestId);
    expect(rejected.status).toBe("rejected");
    expect(rejected.rejectionReason).toBe("Organization not verified");
    expect(rejected.certificate).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Type validation tests
// ---------------------------------------------------------------------------

describe("Type validation", () => {
  it("DscRequest requires subject and csr", () => {
    // These are compile-time checks. If this file compiles, the types work.
    const request: DscRequest = {
      subject: {
        organizationName: "Org",
        country: "US",
      },
      csr: "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
    };
    expect(request.subject.organizationName).toBe("Org");
    expect(request.subject.country).toBe("US");
    expect(request.csr).toBeDefined();
  });

  it("DscRequest supports optional fields", () => {
    const request: DscRequest = {
      subject: {
        organizationName: "Org",
        country: "DE",
        domain: "example.de",
        organizationalUnit: "IT",
        commonName: "Example Org",
      },
      csr: "...",
      keyAlgorithm: "ES384",
      metadata: { reference: "REF-001" },
    };
    expect(request.subject.domain).toBe("example.de");
    expect(request.keyAlgorithm).toBe("ES384");
    expect(request.metadata?.reference).toBe("REF-001");
  });

  it("DscRequestStatusCode covers all valid values", () => {
    const statuses: Array<
      import("../types.js").DscRequestStatusCode
    > = ["pending", "approved", "rejected", "issued"];
    expect(statuses).toHaveLength(4);
  });

  it("KeyAlgorithm covers supported algorithms", () => {
    const algos: Array<import("../types.js").KeyAlgorithm> = [
      "ES256",
      "ES384",
      "ES512",
      "RS256",
      "EdDSA",
    ];
    expect(algos).toHaveLength(5);
  });
});
