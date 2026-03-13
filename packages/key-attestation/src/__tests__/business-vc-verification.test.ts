import { describe, it, expect, vi } from "vitest";
import { BusinessVcVerifier, extractIssuerIdentity } from "../business-vc-verification.js";
import type { BusinessVcVerificationResult } from "../business-vc-types.js";

// Mock the verification module
vi.mock("@opencred/verification", () => ({
  verifyCredential: vi.fn(),
}));

import { verifyCredential } from "@opencred/verification";
const mockVerifyCredential = vi.mocked(verifyCredential);

function validBusinessCredential(): Record<string, unknown> {
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2",
    ],
    id: "urn:uuid:abc-123",
    type: ["VerifiableCredential", "BusinessRegistrationCredential"],
    issuer: "did:key:z6MkRegistrar",
    validFrom: "2025-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:key:z6MkIssuer",
      organizationName: "Acme Corp",
      legalName: "Acme Corporation Ltd.",
      registrationNumber: "HRB-12345",
      country: "DE",
      domain: "acme.example.com",
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: "2025-06-01T00:00:00Z",
      verificationMethod: "did:key:z6MkRegistrar#z6MkRegistrar",
      proofPurpose: "assertionMethod",
      proofValue: "z...",
    },
  };
}

describe("BusinessVcVerifier", () => {
  const verifier = new BusinessVcVerifier();

  it("returns identity when credential is valid", async () => {
    mockVerifyCredential.mockResolvedValueOnce({
      code: "VALID",
      verified: true,
      checks: [{ name: "signature", passed: true }],
    });

    const result: BusinessVcVerificationResult =
      await verifier.verifyBusinessVc(validBusinessCredential());

    expect(result.verified).toBe(true);
    expect(result.identity).toBeDefined();
    expect(result.identity!.organizationName).toBe("Acme Corp");
    expect(result.identity!.legalName).toBe("Acme Corporation Ltd.");
    expect(result.identity!.registrationNumber).toBe("HRB-12345");
    expect(result.identity!.country).toBe("DE");
    expect(result.identity!.domain).toBe("acme.example.com");
    expect(result.identity!.sourceCredentialId).toBe("urn:uuid:abc-123");
    expect(result.identity!.verifiedAt).toBeDefined();
    expect(result.verificationResult).toBeDefined();
    expect(result.verificationResult!.verified).toBe(true);
  });

  it("returns error when credential is invalid", async () => {
    mockVerifyCredential.mockResolvedValueOnce({
      code: "INVALID",
      verified: false,
      checks: [{ name: "signature", passed: false, detail: "Bad signature" }],
    });

    const result = await verifier.verifyBusinessVc(validBusinessCredential());

    expect(result.verified).toBe(false);
    expect(result.identity).toBeUndefined();
    expect(result.error).toContain("INVALID");
    expect(result.verificationResult).toBeDefined();
    expect(result.verificationResult!.verified).toBe(false);
  });

  it("returns error when credential is expired", async () => {
    mockVerifyCredential.mockResolvedValueOnce({
      code: "EXPIRED",
      verified: false,
      checks: [
        { name: "signature", passed: true },
        { name: "dates", passed: false, detail: "Credential has expired" },
      ],
    });

    const result = await verifier.verifyBusinessVc(validBusinessCredential());

    expect(result.verified).toBe(false);
    expect(result.error).toContain("EXPIRED");
  });

  it("returns error when credential is revoked", async () => {
    mockVerifyCredential.mockResolvedValueOnce({
      code: "REVOKED",
      verified: false,
      checks: [
        { name: "signature", passed: true },
        { name: "revocation", passed: false, detail: "Credential is revoked" },
      ],
    });

    const result = await verifier.verifyBusinessVc(validBusinessCredential());

    expect(result.verified).toBe(false);
    expect(result.error).toContain("REVOKED");
  });

  it("handles verifier throwing an exception", async () => {
    mockVerifyCredential.mockRejectedValueOnce(new Error("Network failure"));

    const result = await verifier.verifyBusinessVc(validBusinessCredential());

    expect(result.verified).toBe(false);
    expect(result.error).toContain("Credential verification failed");
    expect(result.error).toContain("Network failure");
  });

  it("returns error when credentialSubject is missing", async () => {
    mockVerifyCredential.mockResolvedValueOnce({
      code: "VALID",
      verified: true,
      checks: [{ name: "signature", passed: true }],
    });

    const credential = validBusinessCredential();
    delete credential["credentialSubject"];

    const result = await verifier.verifyBusinessVc(credential);

    expect(result.verified).toBe(false);
    expect(result.error).toContain("Identity extraction failed");
    expect(result.error).toContain("credentialSubject");
  });

  it("returns error when organization name is missing from subject", async () => {
    mockVerifyCredential.mockResolvedValueOnce({
      code: "VALID",
      verified: true,
      checks: [{ name: "signature", passed: true }],
    });

    const credential = validBusinessCredential();
    const subject = credential["credentialSubject"] as Record<string, unknown>;
    delete subject["organizationName"];
    delete subject["name"];
    delete subject["legalName"];

    const result = await verifier.verifyBusinessVc(credential);

    expect(result.verified).toBe(false);
    expect(result.error).toContain("Identity extraction failed");
    expect(result.error).toContain("organization name");
  });

  it("extracts identity with only organizationName (all others optional)", async () => {
    mockVerifyCredential.mockResolvedValueOnce({
      code: "VALID",
      verified: true,
      checks: [{ name: "signature", passed: true }],
    });

    const credential: Record<string, unknown> = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:minimal",
      type: ["VerifiableCredential"],
      issuer: "did:key:z6MkRegistrar",
      credentialSubject: {
        id: "did:key:z6MkIssuer",
        organizationName: "Minimal Org",
      },
      proof: { type: "DataIntegrityProof", proofValue: "z..." },
    };

    const result = await verifier.verifyBusinessVc(credential);

    expect(result.verified).toBe(true);
    expect(result.identity!.organizationName).toBe("Minimal Org");
    expect(result.identity!.legalName).toBeUndefined();
    expect(result.identity!.registrationNumber).toBeUndefined();
    expect(result.identity!.country).toBeUndefined();
    expect(result.identity!.domain).toBeUndefined();
    expect(result.identity!.sourceCredentialId).toBe("urn:uuid:minimal");
  });
});

describe("extractIssuerIdentity", () => {
  it("extracts identity from a standard business credential", () => {
    const credential = validBusinessCredential();

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("Acme Corp");
    expect(identity.legalName).toBe("Acme Corporation Ltd.");
    expect(identity.registrationNumber).toBe("HRB-12345");
    expect(identity.country).toBe("DE");
    expect(identity.domain).toBe("acme.example.com");
    expect(identity.sourceCredentialId).toBe("urn:uuid:abc-123");
    expect(identity.verifiedAt).toBeDefined();
  });

  it("extracts identity using LEI-style fields", () => {
    const credential: Record<string, unknown> = {
      id: "urn:uuid:lei-cred",
      credentialSubject: {
        name: "LEI Organization",
        officialName: "LEI Organization GmbH",
        leiCode: "5493001KJTIIGC8Y1R12",
        jurisdiction: "AT",
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("LEI Organization");
    expect(identity.legalName).toBe("LEI Organization GmbH");
    expect(identity.registrationNumber).toBe("5493001KJTIIGC8Y1R12");
    expect(identity.country).toBe("AT");
  });

  it("extracts name from nested organization object", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: {
        organization: {
          name: "Nested Org Name",
        },
        countryCode: "US",
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("Nested Org Name");
    expect(identity.country).toBe("US");
  });

  it("uses legalName as organizationName fallback", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: {
        legalName: "Legal Entity Name",
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("Legal Entity Name");
  });

  it("handles array credentialSubject (uses first element)", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: [
        { organizationName: "First Org", country: "DE" },
        { organizationName: "Second Org", country: "FR" },
      ],
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("First Org");
    expect(identity.country).toBe("DE");
  });

  it("throws when credentialSubject is missing", () => {
    expect(() => extractIssuerIdentity({})).toThrow(
      "Credential does not contain a valid credentialSubject",
    );
  });

  it("throws when credentialSubject is null", () => {
    expect(() =>
      extractIssuerIdentity({ credentialSubject: null }),
    ).toThrow("Credential does not contain a valid credentialSubject");
  });

  it("throws when organization name cannot be found", () => {
    expect(() =>
      extractIssuerIdentity({
        credentialSubject: {
          id: "did:key:z6Mk...",
          registrationNumber: "12345",
        },
      }),
    ).toThrow("credentialSubject does not contain an organization name");
  });

  it("throws when organization name is empty string", () => {
    expect(() =>
      extractIssuerIdentity({
        credentialSubject: {
          organizationName: "",
        },
      }),
    ).toThrow("credentialSubject does not contain an organization name");
  });

  it("throws when organization name is whitespace only", () => {
    expect(() =>
      extractIssuerIdentity({
        credentialSubject: {
          organizationName: "   ",
        },
      }),
    ).toThrow("credentialSubject does not contain an organization name");
  });

  it("trims whitespace from extracted fields", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: {
        organizationName: "  Padded Org  ",
        legalName: "  Padded Legal  ",
        registrationNumber: "  HRB-99  ",
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("Padded Org");
    expect(identity.legalName).toBe("Padded Legal");
    expect(identity.registrationNumber).toBe("HRB-99");
  });

  it("skips non-string field values", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: {
        organizationName: "Valid Org",
        registrationNumber: 12345, // number, not string
        country: null, // null
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("Valid Org");
    expect(identity.registrationNumber).toBeUndefined();
    expect(identity.country).toBeUndefined();
  });

  it("extracts sourceCredentialId when present", () => {
    const credential: Record<string, unknown> = {
      id: "urn:uuid:test-cred-id",
      credentialSubject: { organizationName: "Test" },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.sourceCredentialId).toBe("urn:uuid:test-cred-id");
  });

  it("omits sourceCredentialId when credential has no id", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: { organizationName: "Test" },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.sourceCredentialId).toBeUndefined();
  });

  it("extracts from VC-JWT nested vc claim", () => {
    const credential: Record<string, unknown> = {
      vc: {
        credentialSubject: {
          organizationName: "JWT Org",
          country: "JP",
        },
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.organizationName).toBe("JWT Org");
    expect(identity.country).toBe("JP");
  });

  it("uses website field for domain", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: {
        name: "Web Org",
        website: "https://web.example",
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.domain).toBe("https://web.example");
  });

  it("tries alternative registration number fields", () => {
    const credential: Record<string, unknown> = {
      credentialSubject: {
        name: "Alt Reg Org",
        companyNumber: "CN-7890",
      },
    };

    const identity = extractIssuerIdentity(credential);

    expect(identity.registrationNumber).toBe("CN-7890");
  });
});
