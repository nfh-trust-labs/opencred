import { describe, it, expect, vi } from "vitest";
import { DelegationError } from "@opencred/shared";
import type { DeDiClient, DelegationRecord } from "@opencred/dedi-client";
import { registerDelegation, resolveDelegation } from "../registry.js";
import { createDelegationCertificate } from "../certificate.js";
import type { CreateDelegationParams, DelegationCertificate } from "../types.js";

function createValidParams(): CreateDelegationParams {
  return {
    delegator: {
      id: "https://example.com",
      name: "Example Corp Ltd",
    },
    delegatee: {
      id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    },
    scope: {
      credentialTypes: ["UniversityDegreeCredential"],
      namespaces: ["education"],
    },
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    authorisationPath: "ephemeral-keypair",
  };
}

function createSignedCert(): DelegationCertificate {
  const unsigned = createDelegationCertificate(createValidParams());
  return {
    ...unsigned,
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2026-01-01T00:00:00Z",
      verificationMethod: "did:key:z6Mk-delegator#key-1",
      proofPurpose: "assertionMethod",
      proofValue: "zFakeProofValue",
    },
  };
}

function createMockDeDiClient(overrides?: Partial<DeDiClient>): DeDiClient {
  return {
    publishRevocationHash: vi.fn(),
    queryRevocationHash: vi.fn(),
    resolveDID: vi.fn(),
    registerDelegation: vi.fn(),
    resolveDelegation: vi.fn(),
    ...overrides,
  } as unknown as DeDiClient;
}

describe("registerDelegation", () => {
  it("should register a signed delegation certificate in DeDi", async () => {
    const cert = createSignedCert();
    const expectedRecord: DelegationRecord = {
      id: cert.id,
      issuerDid: cert.delegator.id,
      delegateDid: cert.delegatee.id,
      scope: [...cert.scope.credentialTypes, ...cert.scope.namespaces],
      validFrom: cert.validFrom,
      validUntil: cert.validUntil,
      certificate: cert,
    };

    const client = createMockDeDiClient({
      registerDelegation: vi.fn().mockResolvedValue(expectedRecord),
    });

    const result = await registerDelegation(client, { certificate: cert });

    expect(result).toEqual(expectedRecord);
    expect(client.registerDelegation).toHaveBeenCalledOnce();
    expect(client.registerDelegation).toHaveBeenCalledWith(
      expect.objectContaining({
        id: cert.id,
        issuerDid: "https://example.com",
        delegateDid: cert.delegatee.id,
      }),
    );
  });

  it("should throw for unsigned delegation certificate", async () => {
    const unsigned = createDelegationCertificate(createValidParams());
    const client = createMockDeDiClient();

    await expect(
      registerDelegation(client, { certificate: unsigned as unknown as DelegationCertificate }),
    ).rejects.toThrow(DelegationError);
    await expect(
      registerDelegation(client, { certificate: unsigned as unknown as DelegationCertificate }),
    ).rejects.toThrow("unsigned delegation certificate");
  });

  it("should throw when DeDi API fails", async () => {
    const cert = createSignedCert();
    const client = createMockDeDiClient({
      registerDelegation: vi.fn().mockRejectedValue(new Error("network error")),
    });

    await expect(registerDelegation(client, { certificate: cert })).rejects.toThrow(
      DelegationError,
    );
    await expect(registerDelegation(client, { certificate: cert })).rejects.toThrow(
      "Failed to register delegation",
    );
  });

  it("should throw for certificate missing delegator.id", async () => {
    const cert = createSignedCert();
    cert.delegator.id = "";

    const client = createMockDeDiClient();

    await expect(registerDelegation(client, { certificate: cert })).rejects.toThrow(
      DelegationError,
    );
    await expect(registerDelegation(client, { certificate: cert })).rejects.toThrow(
      "delegator.id is required",
    );
  });

  it("should throw for certificate missing delegatee.id", async () => {
    const cert = createSignedCert();
    cert.delegatee.id = "";

    const client = createMockDeDiClient();

    await expect(registerDelegation(client, { certificate: cert })).rejects.toThrow(
      DelegationError,
    );
    await expect(registerDelegation(client, { certificate: cert })).rejects.toThrow(
      "delegatee.id is required",
    );
  });
});

describe("resolveDelegation", () => {
  it("should resolve a delegation certificate from DeDi", async () => {
    const cert = createSignedCert();
    const record: DelegationRecord = {
      id: cert.id,
      issuerDid: cert.delegator.id,
      delegateDid: cert.delegatee.id,
      scope: [...cert.scope.credentialTypes, ...cert.scope.namespaces],
      validFrom: cert.validFrom,
      validUntil: cert.validUntil,
      certificate: cert,
    };

    const client = createMockDeDiClient({
      resolveDelegation: vi.fn().mockResolvedValue(record),
    });

    const result = await resolveDelegation(client, { delegationId: cert.id });

    expect(result).toEqual(cert);
    expect(client.resolveDelegation).toHaveBeenCalledWith(cert.id);
  });

  it("should throw for empty delegationId", async () => {
    const client = createMockDeDiClient();

    await expect(resolveDelegation(client, { delegationId: "" })).rejects.toThrow(
      DelegationError,
    );
    await expect(resolveDelegation(client, { delegationId: "" })).rejects.toThrow(
      "delegationId is required",
    );
  });

  it("should throw for whitespace-only delegationId", async () => {
    const client = createMockDeDiClient();

    await expect(resolveDelegation(client, { delegationId: "   " })).rejects.toThrow(
      DelegationError,
    );
  });

  it("should throw when DeDi record has no certificate", async () => {
    const record: DelegationRecord = {
      id: "del-123",
      issuerDid: "https://example.com",
      delegateDid: "did:key:z6Mk...",
      scope: [],
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
      certificate: null,
    };

    const client = createMockDeDiClient({
      resolveDelegation: vi.fn().mockResolvedValue(record),
    });

    await expect(resolveDelegation(client, { delegationId: "del-123" })).rejects.toThrow(
      DelegationError,
    );
    await expect(resolveDelegation(client, { delegationId: "del-123" })).rejects.toThrow(
      "has no certificate",
    );
  });

  it("should throw when DeDi API fails", async () => {
    const client = createMockDeDiClient({
      resolveDelegation: vi.fn().mockRejectedValue(new Error("timeout")),
    });

    await expect(resolveDelegation(client, { delegationId: "del-123" })).rejects.toThrow(
      DelegationError,
    );
    await expect(resolveDelegation(client, { delegationId: "del-123" })).rejects.toThrow(
      "Failed to resolve delegation",
    );
  });
});
