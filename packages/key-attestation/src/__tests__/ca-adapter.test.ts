import { describe, it, expect } from "vitest";
import type {
  CertificateAuthorityAdapter,
  DSCRequest,
  DSCRequestStatus,
} from "../ca-adapter.js";
import type { IdentityVerification } from "../types.js";
import type { BusinessIdentity } from "../business-vc-types.js";

/**
 * Mock CA adapter that simulates a simple in-memory CA.
 * Demonstrates that the interface is implementable and type-safe.
 */
class MockCertificateAuthority implements CertificateAuthorityAdapter {
  readonly name = "MockCA";
  private readonly requests = new Map<string, DSCRequestStatus>();
  private nextId = 1;

  async requestDSC(request: DSCRequest): Promise<{ requestId: string }> {
    const requestId = `mock-${this.nextId++}`;
    this.requests.set(requestId, {
      requestId,
      status: "pending",
      updatedAt: new Date().toISOString(),
    });

    // Simulate auto-approval for requests with domain evidence
    if ("verifiedDomain" in request.identityEvidence) {
      const status = this.requests.get(requestId)!;
      status.status = "approved";
      status.updatedAt = new Date().toISOString();
    }

    return { requestId };
  }

  async checkStatus(requestId: string): Promise<DSCRequestStatus> {
    const status = this.requests.get(requestId);
    if (!status) {
      return {
        requestId,
        status: "rejected",
        rejectionReason: "Request not found",
        updatedAt: new Date().toISOString(),
      };
    }
    return status;
  }

  // Test helper: issue a DSC for a pending/approved request
  issueDSC(requestId: string, pem: string): void {
    const status = this.requests.get(requestId);
    if (status) {
      status.status = "issued";
      status.dscPem = pem;
      status.updatedAt = new Date().toISOString();
    }
  }
}

describe("CertificateAuthorityAdapter (interface compliance)", () => {
  it("mock adapter implements the interface correctly", () => {
    const ca: CertificateAuthorityAdapter = new MockCertificateAuthority();

    expect(ca.name).toBe("MockCA");
    expect(typeof ca.requestDSC).toBe("function");
    expect(typeof ca.checkStatus).toBe("function");
  });

  it("requestDSC returns a request ID", async () => {
    const ca = new MockCertificateAuthority();

    const domainEvidence: IdentityVerification = {
      method: "dns-txt",
      verifiedDomain: "university.example",
      verifiedAt: "2026-03-10T00:00:00Z",
      challengeId: "urn:uuid:challenge-1",
    };

    const request: DSCRequest = {
      subjectDid: "did:key:z6MkIssuer",
      organizationName: "Test University",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      keyAlgorithm: "P-256",
      identityEvidence: domainEvidence,
    };

    const result = await ca.requestDSC(request);

    expect(result.requestId).toBeDefined();
    expect(typeof result.requestId).toBe("string");
  });

  it("checkStatus returns pending for new requests with business VC evidence", async () => {
    const ca = new MockCertificateAuthority();

    const businessEvidence: BusinessIdentity = {
      organizationName: "Acme Corp",
      legalName: "Acme Corporation Ltd.",
      registrationNumber: "HRB-12345",
      country: "DE",
      verifiedAt: "2026-03-10T00:00:00Z",
    };

    const request: DSCRequest = {
      subjectDid: "did:key:z6MkIssuer",
      organizationName: "Acme Corp",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      keyAlgorithm: "P-256",
      identityEvidence: businessEvidence,
    };

    const { requestId } = await ca.requestDSC(request);
    const status = await ca.checkStatus(requestId);

    expect(status.requestId).toBe(requestId);
    expect(status.status).toBe("pending");
    expect(status.updatedAt).toBeDefined();
  });

  it("checkStatus returns approved for domain-verified requests", async () => {
    const ca = new MockCertificateAuthority();

    const domainEvidence: IdentityVerification = {
      method: "dns-txt",
      verifiedDomain: "university.example",
      verifiedAt: "2026-03-10T00:00:00Z",
      challengeId: "urn:uuid:challenge-1",
    };

    const request: DSCRequest = {
      subjectDid: "did:key:z6MkIssuer",
      organizationName: "Test University",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      keyAlgorithm: "P-256",
      identityEvidence: domainEvidence,
    };

    const { requestId } = await ca.requestDSC(request);
    const status = await ca.checkStatus(requestId);

    expect(status.status).toBe("approved");
  });

  it("tracks issued DSC with PEM", async () => {
    const ca = new MockCertificateAuthority();

    const domainEvidence: IdentityVerification = {
      method: "dns-txt",
      verifiedDomain: "university.example",
      verifiedAt: "2026-03-10T00:00:00Z",
      challengeId: "urn:uuid:challenge-1",
    };

    const request: DSCRequest = {
      subjectDid: "did:key:z6MkIssuer",
      organizationName: "Test University",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      keyAlgorithm: "P-256",
      identityEvidence: domainEvidence,
    };

    const { requestId } = await ca.requestDSC(request);
    const fakePem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----";
    ca.issueDSC(requestId, fakePem);

    const status = await ca.checkStatus(requestId);

    expect(status.status).toBe("issued");
    expect(status.dscPem).toBe(fakePem);
  });

  it("returns rejected for unknown request IDs", async () => {
    const ca = new MockCertificateAuthority();

    const status = await ca.checkStatus("nonexistent-id");

    expect(status.status).toBe("rejected");
    expect(status.rejectionReason).toBeDefined();
  });

  it("generates unique request IDs", async () => {
    const ca = new MockCertificateAuthority();

    const domainEvidence: IdentityVerification = {
      method: "dns-txt",
      verifiedDomain: "university.example",
      verifiedAt: "2026-03-10T00:00:00Z",
      challengeId: "urn:uuid:challenge-1",
    };

    const request: DSCRequest = {
      subjectDid: "did:key:z6MkIssuer",
      organizationName: "Test University",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      keyAlgorithm: "P-256",
      identityEvidence: domainEvidence,
    };

    const result1 = await ca.requestDSC(request);
    const result2 = await ca.requestDSC(request);

    expect(result1.requestId).not.toBe(result2.requestId);
  });
});
