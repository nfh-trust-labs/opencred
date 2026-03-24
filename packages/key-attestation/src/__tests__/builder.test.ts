import { describe, it, expect } from "vitest";
import { createKeyAttestationVC } from "../builder.js";
import { OPENCRED_KEY_ATTESTATION_V1_CONTEXT } from "../types.js";
import { W3C_CREDENTIALS_V2_CONTEXT, DATA_INTEGRITY_V1_CONTEXT } from "@opencred/vc-core";
import type { CreateKeyAttestationParams, PublicKeyJwk } from "../types.js";

function validParams(): CreateKeyAttestationParams {
  return {
    opencredDid: "did:key:z6MkOpenCred",
    issuerDid: "did:key:z6MkIssuer",
    issuerKeyJwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
    keyFingerprint: "sha256:a1b2c3d4",
    keyAlgorithm: "P-256",
    verificationMethodId: "did:key:z6MkIssuer#z6MkIssuer",
    identityVerification: {
      method: "dns-txt",
      verifiedDomain: "university.example",
      verifiedAt: "2026-03-10T12:00:00Z",
    },
    organizationName: "Example University",
  };
}

describe("createKeyAttestationVC", () => {
  it("builds a VC with correct @context", () => {
    const vc = createKeyAttestationVC(validParams());

    expect(vc["@context"]).toEqual([
      W3C_CREDENTIALS_V2_CONTEXT,
      DATA_INTEGRITY_V1_CONTEXT,
      OPENCRED_KEY_ATTESTATION_V1_CONTEXT,
    ]);
  });

  it("builds a VC with correct type", () => {
    const vc = createKeyAttestationVC(validParams());

    expect(vc.type).toEqual(["VerifiableCredential", "KeyAttestationCredential"]);
  });

  it("sets issuer to OpenCred's DID", () => {
    const vc = createKeyAttestationVC(validParams());

    expect(vc.issuer).toBe("did:key:z6MkOpenCred");
  });

  it("generates a urn:uuid id", () => {
    const vc = createKeyAttestationVC(validParams());

    expect(vc.id).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  });

  it("sets credentialSubject with all required fields", () => {
    const vc = createKeyAttestationVC(validParams());
    const subject = vc.credentialSubject;

    expect(subject.id).toBe("did:key:z6MkIssuer");
    expect(subject.keyJwk).toEqual({ kty: "EC", crv: "P-256", x: "abc", y: "def" });
    expect(subject.keyFingerprint).toBe("sha256:a1b2c3d4");
    expect(subject.keyAlgorithm).toBe("P-256");
    expect(subject.verificationMethodId).toBe("did:key:z6MkIssuer#z6MkIssuer");
    expect(subject.organizationName).toBe("Example University");
  });

  it("sets identityVerification details", () => {
    const vc = createKeyAttestationVC(validParams());
    const iv = vc.credentialSubject.identityVerification;

    expect(iv.method).toBe("dns-txt");
    expect(iv.verifiedDomain).toBe("university.example");
    expect(iv.verifiedAt).toBe("2026-03-10T12:00:00Z");
    expect(iv.sourceCredentialId).toBeUndefined();
  });

  it("sets sourceCredentialId for business-vc method", () => {
    const params = validParams();
    params.identityVerification = {
      method: "business-vc",
      verifiedDomain: "acme.example",
      verifiedAt: "2026-03-10T12:00:00Z",
      sourceCredentialId: "urn:uuid:business-vc-id",
    };
    const vc = createKeyAttestationVC(params);
    const iv = vc.credentialSubject.identityVerification;

    expect(iv.method).toBe("business-vc");
    expect(iv.sourceCredentialId).toBe("urn:uuid:business-vc-id");
  });

  it("rejects business-vc method without sourceCredentialId", () => {
    const params = validParams();
    params.identityVerification = {
      method: "business-vc",
      verifiedDomain: "acme.example",
      verifiedAt: "2026-03-10T12:00:00Z",
    };

    expect(() => createKeyAttestationVC(params)).toThrow(
      "identityVerification.sourceCredentialId is required when method is business-vc",
    );
  });

  it("defaults validFrom to now and validUntil to 1 year from now", () => {
    const before = new Date();
    const vc = createKeyAttestationVC(validParams());
    const after = new Date();

    const from = new Date(vc.validFrom);
    const until = new Date(vc.validUntil);

    expect(from.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(from.getTime()).toBeLessThanOrEqual(after.getTime());

    // validUntil should be ~1 year from validFrom
    const expectedUntil = new Date(from);
    expectedUntil.setFullYear(expectedUntil.getFullYear() + 1);
    expect(Math.abs(until.getTime() - expectedUntil.getTime())).toBeLessThan(1000);
  });

  it("accepts custom validFrom and validUntil", () => {
    const params = validParams();
    params.validFrom = "2026-01-01T00:00:00Z";
    params.validUntil = "2027-01-01T00:00:00Z";

    const vc = createKeyAttestationVC(params);

    expect(vc.validFrom).toBe("2026-01-01T00:00:00Z");
    expect(vc.validUntil).toBe("2027-01-01T00:00:00Z");
  });

  it("generates unique IDs per call", () => {
    const vc1 = createKeyAttestationVC(validParams());
    const vc2 = createKeyAttestationVC(validParams());

    expect(vc1.id).not.toBe(vc2.id);
  });

  // Error cases
  it("rejects invalid opencredDid", () => {
    const params = validParams();
    params.opencredDid = "not-a-did";

    expect(() => createKeyAttestationVC(params)).toThrow("opencredDid must be a valid DID");
  });

  it("rejects empty opencredDid", () => {
    const params = validParams();
    params.opencredDid = "";

    expect(() => createKeyAttestationVC(params)).toThrow("opencredDid must be a valid DID");
  });

  it("rejects invalid issuerDid", () => {
    const params = validParams();
    params.issuerDid = "not-a-did";

    expect(() => createKeyAttestationVC(params)).toThrow("issuerDid must be a valid DID");
  });

  it("rejects missing JWK kty", () => {
    const params = validParams();
    params.issuerKeyJwk = {} as PublicKeyJwk;

    expect(() => createKeyAttestationVC(params)).toThrow("issuerKeyJwk must be a valid JWK");
  });

  it("rejects missing keyFingerprint", () => {
    const params = validParams();
    params.keyFingerprint = "";

    expect(() => createKeyAttestationVC(params)).toThrow("keyFingerprint is required");
  });

  it("rejects missing organizationName", () => {
    const params = validParams();
    params.organizationName = "";

    expect(() => createKeyAttestationVC(params)).toThrow("organizationName is required");
  });

  it("rejects invalid validFrom date", () => {
    const params = validParams();
    params.validFrom = "not-a-date";

    expect(() => createKeyAttestationVC(params)).toThrow("validFrom must be a valid ISO 8601 date");
  });

  it("rejects validFrom >= validUntil", () => {
    const params = validParams();
    params.validFrom = "2027-01-01T00:00:00Z";
    params.validUntil = "2026-01-01T00:00:00Z";

    expect(() => createKeyAttestationVC(params)).toThrow("validFrom must be before validUntil");
  });

  it("rejects missing identityVerification.method", () => {
    const params = validParams();
    params.identityVerification.method = "" as "dns-txt";

    expect(() => createKeyAttestationVC(params)).toThrow("identityVerification.method is required");
  });

  it("rejects missing identityVerification.verifiedDomain", () => {
    const params = validParams();
    params.identityVerification.verifiedDomain = "";

    expect(() => createKeyAttestationVC(params)).toThrow("identityVerification.verifiedDomain is required");
  });
});
