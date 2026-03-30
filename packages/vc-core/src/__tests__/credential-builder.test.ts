import { describe, it, expect } from "vitest";
import { ValidationError } from "@opencred/shared";
import { CredentialBuilder } from "../credential-builder.js";
import {
  W3C_CREDENTIALS_V2_CONTEXT,
  DATA_INTEGRITY_V1_CONTEXT,
  OPENCRED_DELEGATION_V1_CONTEXT,
} from "../types.js";
import { createDocumentLoader, getBundledContextUrls } from "../document-loader.js";

describe("CredentialBuilder", () => {
  const validIssuer = "did:web:university.example";
  const validSubject = {
    id: "did:example:holder456",
    name: "Jane Doe",
    degree: {
      type: "BachelorDegree",
      name: "Bachelor of Computer Science",
      institution: "Example University",
    },
  };
  const validFrom = "2026-02-09T00:00:00Z";
  const validUntil = "2027-02-09T00:00:00Z";
  const validStatus = {
    id: "https://dedi.global/dedi/lookup/university.example/vc-revocation-registry/abc123",
    type: "dedi",
    statusPurpose: "revocation",
    statusListCredential: "https://dedi.global/dedi/query/university.example/vc-revocation-registry",
  };

  function buildMinimalCredential() {
    return new CredentialBuilder()
      .setIssuer(validIssuer)
      .setCredentialSubject(validSubject)
      .setValidFrom(validFrom)
      .build();
  }

  describe("build() — valid credential", () => {
    it("should build a valid unsigned VC with all W3C required fields", () => {
      const vc = buildMinimalCredential();

      expect(vc).toHaveProperty("@context");
      expect(vc).toHaveProperty("id");
      expect(vc).toHaveProperty("type");
      expect(vc).toHaveProperty("issuer");
      expect(vc).toHaveProperty("validFrom");
      expect(vc).toHaveProperty("credentialSubject");
      expect(vc).not.toHaveProperty("proof");
    });

    it("should generate a urn:uuid:* ID", () => {
      const vc = buildMinimalCredential();

      expect(vc.id).toMatch(
        /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
    });

    it("should generate unique IDs for each build", () => {
      const vc1 = buildMinimalCredential();
      const vc2 = buildMinimalCredential();

      expect(vc1.id).not.toBe(vc2.id);
    });

    it("should allow setting a custom urn:uuid ID", () => {
      const customId = "urn:uuid:custom-id-here";
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .setId(customId)
        .build();

      expect(vc.id).toBe(customId);
    });

    it("should allow setting a custom https:// ID", () => {
      const customId = "https://example.com/credentials/123";
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .setId(customId)
        .build();

      expect(vc.id).toBe(customId);
    });

    it("should set validFrom and validUntil dates", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .setValidUntil(validUntil)
        .build();

      expect(vc.validFrom).toBe(validFrom);
      expect(vc.validUntil).toBe(validUntil);
    });

    it("should omit validUntil when not set", () => {
      const vc = buildMinimalCredential();

      expect(vc).not.toHaveProperty("validUntil");
    });

    it("should set issuer as a DID string", () => {
      const vc = buildMinimalCredential();
      expect(vc.issuer).toBe(validIssuer);
    });

    it("should set issuer as an object with id and name", () => {
      const issuerObj = { id: "did:web:university.example", name: "Example University" };
      const vc = new CredentialBuilder()
        .setIssuer(issuerObj)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .build();

      expect(vc.issuer).toEqual(issuerObj);
    });

    it("should accept https:// issuer URI", () => {
      const vc = new CredentialBuilder()
        .setIssuer("https://university.example")
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .build();

      expect(vc.issuer).toBe("https://university.example");
    });

    it("should set credentialSubject with nested claims", () => {
      const vc = buildMinimalCredential();
      expect(vc.credentialSubject).toEqual(validSubject);
    });

    it("should accept dates with fractional seconds", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom("2026-02-09T00:00:00.000Z")
        .build();

      expect(vc.validFrom).toBe("2026-02-09T00:00:00.000Z");
    });

    it("should accept dates with timezone offset", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom("2026-02-09T00:00:00+05:30")
        .build();

      expect(vc.validFrom).toBe("2026-02-09T00:00:00+05:30");
    });
  });

  describe("@context array", () => {
    it("should always include credentials/v2 as the first context", () => {
      const vc = buildMinimalCredential();

      expect(vc["@context"][0]).toBe(W3C_CREDENTIALS_V2_CONTEXT);
    });

    it("should silently skip data-integrity/v1 since credentials/v2 subsumes it", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .addContext(DATA_INTEGRITY_V1_CONTEXT)
        .build();

      // credentials/v2 subsumes data-integrity/v1; should only have v2
      expect(vc["@context"]).toEqual([W3C_CREDENTIALS_V2_CONTEXT]);
    });

    it("should allow adding non-redundant additional contexts", () => {
      const customContext = "https://example.com/context/v1";
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .addContext(customContext)
        .build();

      expect(vc["@context"]).toEqual([W3C_CREDENTIALS_V2_CONTEXT, customContext]);
    });

    it("should not duplicate the base credentials/v2 context", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .addContext(W3C_CREDENTIALS_V2_CONTEXT)
        .build();

      const contextCount = vc["@context"].filter((c) => c === W3C_CREDENTIALS_V2_CONTEXT).length;
      expect(contextCount).toBe(1);
    });

    it("should not duplicate additional contexts when added multiple times", () => {
      const customContext = "https://example.com/context/v1";
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .addContext(customContext)
        .addContext(customContext)
        .build();

      expect(vc["@context"]).toHaveLength(2);
    });
  });

  describe("type array", () => {
    it("should always include VerifiableCredential", () => {
      const vc = buildMinimalCredential();
      expect(vc.type).toContain("VerifiableCredential");
    });

    it("should allow adding additional types", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .addType("UniversityDegreeCredential")
        .build();

      expect(vc.type).toEqual(["VerifiableCredential", "UniversityDegreeCredential"]);
    });
  });

  describe("credentialStatus", () => {
    it("should embed credentialStatus when set", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .setCredentialStatus(validStatus)
        .build();

      expect(vc.credentialStatus).toEqual(validStatus);
    });

    it("should omit credentialStatus when not set", () => {
      const vc = buildMinimalCredential();
      expect(vc).not.toHaveProperty("credentialStatus");
    });
  });

  describe("credentialSchema", () => {
    it("should embed credentialSchema when set", () => {
      const schema = {
        id: "https://example.com/schemas/degree",
        type: "JsonSchema",
      };
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .setSchema(schema)
        .build();

      expect(vc.credentialSchema).toEqual(schema);
    });

    it("should omit credentialSchema when not set", () => {
      const vc = buildMinimalCredential();
      expect(vc).not.toHaveProperty("credentialSchema");
    });
  });

  describe("revocationRegistryUrl validation", () => {
    it("should accept a valid HTTPS URL", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .setCredentialStatus(validStatus)
        .build();

      expect(vc.credentialStatus?.id).toBe(validStatus.id);
    });

    it("should reject HTTP URLs", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .setCredentialStatus({
            id: "http://dedi.example/revocations/university.example/revocation-registry",
            type: "dedi",
            statusPurpose: "revocation",
          })
          .build(),
      ).toThrow(ValidationError);
    });

    it("should reject HTTP URLs with proper error message", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .setCredentialStatus({
            id: "http://insecure.example/registry",
            type: "dedi",
            statusPurpose: "revocation",
          })
          .build(),
      ).toThrow(/must use HTTPS/);
    });

    it("should reject unparseable URLs", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .setCredentialStatus({
            id: "not-a-valid-url",
            type: "dedi",
            statusPurpose: "revocation",
          })
          .build(),
      ).toThrow(ValidationError);
    });

    it("should reject unparseable URLs with proper error message", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .setCredentialStatus({
            id: ":::invalid",
            type: "dedi",
            statusPurpose: "revocation",
          })
          .build(),
      ).toThrow(/Invalid revocation registry URL/);
    });
  });

  describe("issuer URI validation (#141)", () => {
    it("should accept did: issuer URIs", () => {
      const vc = new CredentialBuilder()
        .setIssuer("did:web:university.example")
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .build();
      expect(vc.issuer).toBe("did:web:university.example");
    });

    it("should accept https:// issuer URIs", () => {
      const vc = new CredentialBuilder()
        .setIssuer("https://university.example")
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .build();
      expect(vc.issuer).toBe("https://university.example");
    });

    it("should accept https:// issuer URIs in object form", () => {
      const vc = new CredentialBuilder()
        .setIssuer({ id: "https://university.example", name: "University" })
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom)
        .build();
      expect((vc.issuer as { id: string }).id).toBe("https://university.example");
    });

    it("should reject issuer without valid URI scheme", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer("university.example")
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .build(),
      ).toThrow(ValidationError);
    });

    it("should reject issuer with valid URI scheme error message", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer("university.example")
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .build(),
      ).toThrow(/Issuer must be a valid URI/);
    });

    it("should reject http:// issuer (not https)", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer("http://university.example")
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .build(),
      ).toThrow(ValidationError);
    });

    it("should reject issuer object with non-URI id", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer({ id: "plain-string", name: "Test" })
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .build(),
      ).toThrow(ValidationError);
    });
  });

  describe("strict date format validation (#142)", () => {
    it("should accept YYYY-MM-DDTHH:mm:ssZ", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom("2026-01-01T00:00:00Z")
        .build();
      expect(vc.validFrom).toBe("2026-01-01T00:00:00Z");
    });

    it("should accept dates with fractional seconds", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom("2026-01-01T00:00:00.000Z")
        .build();
      expect(vc.validFrom).toBe("2026-01-01T00:00:00.000Z");
    });

    it("should accept dates with positive timezone offset", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom("2026-01-01T05:30:00+05:30")
        .build();
      expect(vc.validFrom).toBe("2026-01-01T05:30:00+05:30");
    });

    it("should accept dates with negative timezone offset", () => {
      const vc = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom("2026-01-01T00:00:00-05:00")
        .build();
      expect(vc.validFrom).toBe("2026-01-01T00:00:00-05:00");
    });

    it("should reject date-only string (no time component)", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("2026-01-01")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should reject ambiguous date formats", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("Jan 1, 2026")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should reject date without timezone", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("2026-01-01T00:00:00")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should reject year-only date", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("2026")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should include helpful error message for invalid date format", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("2026-01-01")
          .build(),
      ).toThrow(/Must be ISO 8601 format/);
    });

    it("should reject non-date strings", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("not-a-date")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should also validate validUntil strictly", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .setValidUntil("2027-01-01")
          .build(),
      ).toThrow(ValidationError);
    });
  });

  describe("credential id URI validation (#154)", () => {
    it("should accept urn:uuid: IDs", () => {
      const builder = new CredentialBuilder();
      builder.setId("urn:uuid:12345678-1234-1234-1234-123456789012");
      // No throw
    });

    it("should accept https:// IDs", () => {
      const builder = new CredentialBuilder();
      builder.setId("https://example.com/credentials/123");
      // No throw
    });

    it("should reject non-URI IDs", () => {
      expect(() => new CredentialBuilder().setId("plain-string")).toThrow(ValidationError);
    });

    it("should reject http:// IDs (not https)", () => {
      expect(() => new CredentialBuilder().setId("http://example.com/credentials/123")).toThrow(
        ValidationError,
      );
    });

    it("should reject empty string IDs", () => {
      expect(() => new CredentialBuilder().setId("")).toThrow(ValidationError);
    });

    it("should include helpful error message for invalid credential ID", () => {
      expect(() => new CredentialBuilder().setId("bad-id")).toThrow(
        /Credential id must be a valid URI/,
      );
    });
  });

  describe("validation errors", () => {
    it("should throw when issuer is missing", () => {
      expect(() =>
        new CredentialBuilder().setCredentialSubject(validSubject).setValidFrom(validFrom).build(),
      ).toThrow(ValidationError);
    });

    it("should throw when credentialSubject is missing", () => {
      expect(() =>
        new CredentialBuilder().setIssuer(validIssuer).setValidFrom(validFrom).build(),
      ).toThrow(ValidationError);
    });

    it("should throw when validFrom is missing", () => {
      expect(() =>
        new CredentialBuilder().setIssuer(validIssuer).setCredentialSubject(validSubject).build(),
      ).toThrow(ValidationError);
    });

    it("should throw when validFrom is not a valid date", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("not-a-date")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should throw when validUntil is not a valid date", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .setValidUntil("not-a-date")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should throw when validUntil is before validFrom", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom("2027-01-01T00:00:00Z")
          .setValidUntil("2026-01-01T00:00:00Z")
          .build(),
      ).toThrow(ValidationError);
    });

    it("should throw when validUntil equals validFrom", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer(validIssuer)
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .setValidUntil(validFrom)
          .build(),
      ).toThrow(ValidationError);
    });

    it("should throw when issuer is an empty string", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer("")
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .build(),
      ).toThrow(ValidationError);
    });

    it("should throw when issuer object has empty id", () => {
      expect(() =>
        new CredentialBuilder()
          .setIssuer({ id: "", name: "Test" })
          .setCredentialSubject(validSubject)
          .setValidFrom(validFrom)
          .build(),
      ).toThrow(ValidationError);
    });
  });

  describe("immutability", () => {
    it("should return a new context array (not a reference to internal state)", () => {
      const builder = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom);

      const vc = builder.build();
      vc["@context"].push("https://malicious.example");

      const vc2 = builder.build();
      expect(vc2["@context"]).toHaveLength(1);
    });

    it("should return a new credentialSubject object (not a reference)", () => {
      const builder = new CredentialBuilder()
        .setIssuer(validIssuer)
        .setCredentialSubject(validSubject)
        .setValidFrom(validFrom);

      const vc = builder.build();
      (vc.credentialSubject as Record<string, unknown>).injected = "malicious";

      const vc2 = builder.build();
      expect(vc2.credentialSubject).not.toHaveProperty("injected");
    });
  });

  describe("PRD sample VC structure (Section 10.1)", () => {
    it("should produce a VC matching the PRD sample structure", () => {
      const vc = new CredentialBuilder()
        .setIssuer("did:web:university.example")
        .setCredentialSubject({
          id: "did:example:holder456",
          name: "Jane Doe",
          degree: {
            type: "BachelorDegree",
            name: "Bachelor of Computer Science",
            institution: "Example University",
          },
        })
        .setValidFrom("2026-02-09T00:00:00Z")
        .setValidUntil("2027-02-09T00:00:00Z")
        .setCredentialStatus({
          id: "https://dedi.global/dedi/lookup/university.example/vc-revocation-registry/abc123",
          type: "dedi",
          statusPurpose: "revocation",
          statusListCredential: "https://dedi.global/dedi/query/university.example/vc-revocation-registry",
        })
        .addContext(OPENCRED_DELEGATION_V1_CONTEXT)
        .build();

      // Verify structure matches PRD Section 10.1
      expect(vc["@context"]).toEqual([
        "https://www.w3.org/ns/credentials/v2",
        OPENCRED_DELEGATION_V1_CONTEXT,
      ]);
      expect(vc.id).toMatch(/^urn:uuid:/);
      expect(vc.type).toEqual(["VerifiableCredential"]);
      expect(vc.issuer).toBe("did:web:university.example");
      expect(vc.validFrom).toBe("2026-02-09T00:00:00Z");
      expect(vc.validUntil).toBe("2027-02-09T00:00:00Z");
      expect(vc.credentialSubject).toEqual({
        id: "did:example:holder456",
        name: "Jane Doe",
        degree: {
          type: "BachelorDegree",
          name: "Bachelor of Computer Science",
          institution: "Example University",
        },
      });
      expect(vc.credentialStatus).toEqual({
        id: "https://dedi.global/dedi/lookup/university.example/vc-revocation-registry/abc123",
        type: "dedi",
        statusPurpose: "revocation",
        statusListCredential: "https://dedi.global/dedi/query/university.example/vc-revocation-registry",
      });
      // Unsigned — no proof
      expect(vc).not.toHaveProperty("proof");
    });
  });
});

describe("Document Loader", () => {
  it("should load the bundled credentials/v2 context", () => {
    const loader = createDocumentLoader();
    const result = loader(W3C_CREDENTIALS_V2_CONTEXT);

    expect(result.documentUrl).toBe(W3C_CREDENTIALS_V2_CONTEXT);
    expect(result.contextUrl).toBeNull();
    expect(result.document).toHaveProperty("@context");
  });

  it("should load the bundled data-integrity/v1 context", () => {
    const loader = createDocumentLoader();
    const result = loader(DATA_INTEGRITY_V1_CONTEXT);

    expect(result.documentUrl).toBe(DATA_INTEGRITY_V1_CONTEXT);
    expect(result.document).toHaveProperty("@context");
  });

  it("should reject unknown/remote context URLs", () => {
    const loader = createDocumentLoader();

    expect(() => loader("https://malicious.example/context")).toThrow(
      /JSON-LD context not found/,
    );
  });

  it("should list bundled context URLs", () => {
    const urls = getBundledContextUrls();

    expect(urls).toContain(W3C_CREDENTIALS_V2_CONTEXT);
    expect(urls).toContain(DATA_INTEGRITY_V1_CONTEXT);
    expect(urls.size).toBe(8);
  });
});
