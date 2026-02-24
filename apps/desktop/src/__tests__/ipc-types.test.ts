/**
 * Tests for IPC type definitions.
 *
 * These tests verify that the type contracts for IPC communication are
 * structurally correct. While TypeScript provides compile-time checking,
 * these runtime tests ensure that objects conforming to the interfaces
 * contain the expected fields and that the OpenCredDesktopAPI shape is
 * complete.
 */

import { describe, it, expect } from "vitest";
import type {
  KeyMetadata,
  KeyImportRequest,
  KeyImportResponse,
  KeyListResponse,
  SchemaListResponse,
  SchemaGetRequest,
  SchemaGetResponse,
  SignCredentialRequest,
  SignCredentialResponse,
  BuildAndSignRequest,
  BuildAndSignResponse,
  VerifyCredentialRequest,
  VerifyCredentialResponse,
  PackageCredentialRequest,
  PackageCredentialResponse,
  RevocationQueueRequest,
  RevocationQueueResponse,
  RevocationStatusResponse,
  RevocationPublishResponse,
  FileOpenRequest,
  FileOpenResponse,
  FileSaveRequest,
  FileSaveResponse,
  ConfigGetRequest,
  ConfigSetRequest,
  OpenCredDesktopAPI,
} from "../shared/ipc-types";

describe("IPC type contracts", () => {
  it("KeyMetadata should have the required fields", () => {
    const meta: KeyMetadata = {
      id: "abc123",
      fingerprint: "deadbeef",
      algorithm: "EC P-256",
      importedAt: "2026-01-01T00:00:00Z",
    };
    expect(meta.id).toBe("abc123");
    expect(meta.fingerprint).toBe("deadbeef");
    expect(meta.algorithm).toBe("EC P-256");
    expect(meta.importedAt).toBe("2026-01-01T00:00:00Z");
  });

  it("KeyMetadata should accept optional label and format", () => {
    const meta: KeyMetadata = {
      id: "abc123",
      fingerprint: "deadbeef",
      algorithm: "EC P-256",
      importedAt: "2026-01-01T00:00:00Z",
      label: "My signing key",
      format: "pem",
    };
    expect(meta.label).toBe("My signing key");
    expect(meta.format).toBe("pem");
  });

  it("KeyImportRequest should require a filePath", () => {
    const req: KeyImportRequest = { filePath: "/path/to/key.jwk" };
    expect(req.filePath).toBe("/path/to/key.jwk");
  });

  it("KeyImportResponse should indicate success or failure", () => {
    const success: KeyImportResponse = {
      success: true,
      key: {
        id: "x",
        fingerprint: "f",
        algorithm: "EC P-256",
        importedAt: new Date().toISOString(),
      },
    };
    expect(success.success).toBe(true);
    expect(success.key?.id).toBe("x");

    const failure: KeyImportResponse = {
      success: false,
      error: "Bad format",
    };
    expect(failure.success).toBe(false);
    expect(failure.error).toBe("Bad format");
  });

  it("KeyListResponse should contain an array of keys", () => {
    const resp: KeyListResponse = { keys: [] };
    expect(Array.isArray(resp.keys)).toBe(true);
  });

  it("SchemaListResponse should contain an array of schema IDs", () => {
    const resp: SchemaListResponse = { schemas: ["education", "employment"] };
    expect(resp.schemas).toHaveLength(2);
  });

  it("SchemaGetRequest should require a schemaId", () => {
    const req: SchemaGetRequest = { schemaId: "education" };
    expect(req.schemaId).toBe("education");
  });

  it("SchemaGetResponse should contain schema definition", () => {
    const resp: SchemaGetResponse = {
      id: "education",
      schema: { type: "object" },
      contextUrl: "https://opencred.dev/contexts/education/v1",
    };
    expect(resp.id).toBe("education");
    expect(resp.schema).toBeDefined();
  });

  it("SignCredentialRequest should require unsignedCredential and keyId", () => {
    const req: SignCredentialRequest = {
      unsignedCredential: '{"type": "VerifiableCredential"}',
      keyId: "key-1",
    };
    expect(req.unsignedCredential).toBeDefined();
    expect(req.keyId).toBe("key-1");
  });

  it("SignCredentialResponse should indicate success or error", () => {
    const resp: SignCredentialResponse = {
      success: true,
      signedCredential: "{}",
    };
    expect(resp.success).toBe(true);
  });

  it("BuildAndSignRequest should require schemaId, issuerDid, credentialSubject, validFrom, keyId", () => {
    const req: BuildAndSignRequest = {
      schemaId: "education",
      issuerDid: "did:web:test.example",
      credentialSubject: { name: "Test" },
      validFrom: "2025-01-01T00:00:00Z",
      keyId: "key-1",
    };
    expect(req.schemaId).toBe("education");
    expect(req.keyId).toBe("key-1");
  });

  it("BuildAndSignResponse should support packaged outputs", () => {
    const resp: BuildAndSignResponse = {
      success: true,
      signedCredential: "{}",
      packagedOutputs: [{ format: "json-ld", data: "{}", mimeType: "application/ld+json", suggestedFileName: "cred.jsonld" }],
    };
    expect(resp.packagedOutputs).toHaveLength(1);
  });

  it("VerifyCredentialRequest should require a credential string", () => {
    const req: VerifyCredentialRequest = { credential: "{}" };
    expect(req.credential).toBe("{}");
  });

  it("VerifyCredentialResponse should include valid and message on success", () => {
    const resp: VerifyCredentialResponse = {
      success: true,
      valid: true,
      message: "All checks passed.",
    };
    expect(resp.valid).toBe(true);
    expect(resp.message).toBe("All checks passed.");
  });

  it("PackageCredentialRequest should require credential and formats", () => {
    const req: PackageCredentialRequest = {
      credential: "{}",
      formats: ["json-ld", "qr-png"],
    };
    expect(req.formats).toHaveLength(2);
  });

  it("RevocationQueueRequest should require credentialId and registryUrl", () => {
    const req: RevocationQueueRequest = {
      credentialId: "urn:uuid:test",
      registryUrl: "https://dedi.example/revocations/test",
    };
    expect(req.credentialId).toBe("urn:uuid:test");
  });

  it("FileOpenRequest should accept optional title and filters", () => {
    const req: FileOpenRequest = {
      title: "Open",
      filters: [{ name: "JSON", extensions: ["json"] }],
    };
    expect(req.title).toBe("Open");
    expect(req.filters).toHaveLength(1);
  });

  it("FileOpenResponse should have content and filePath (nullable)", () => {
    const cancelled: FileOpenResponse = { content: null, filePath: null };
    expect(cancelled.content).toBeNull();

    const opened: FileOpenResponse = { content: "{}", filePath: "/a/b.json" };
    expect(opened.content).toBe("{}");
  });

  it("FileSaveRequest should require defaultName and content", () => {
    const req: FileSaveRequest = {
      defaultName: "credential.json",
      content: "{}",
    };
    expect(req.defaultName).toBe("credential.json");
    expect(req.content).toBe("{}");
  });

  it("FileSaveResponse should have filePath (nullable)", () => {
    const resp: FileSaveResponse = { filePath: "/saved.json" };
    expect(resp.filePath).toBe("/saved.json");
  });

  it("ConfigGetRequest should require a key", () => {
    const req: ConfigGetRequest = { key: "theme" };
    expect(req.key).toBe("theme");
  });

  it("ConfigSetRequest should require a key and value", () => {
    const req: ConfigSetRequest = { key: "theme", value: "dark" };
    expect(req.key).toBe("theme");
    expect(req.value).toBe("dark");
  });

  it("OpenCredDesktopAPI should define all required methods", () => {
    // Create a mock implementation to verify the shape.
    const api: OpenCredDesktopAPI = {
      importKey: async () => ({ success: true }),
      listKeys: async () => ({ keys: [] }),
      listSchemas: async () => ({ schemas: [] }),
      getSchema: async () => ({ id: "test", schema: {} }),
      signCredential: async () => ({ success: false, error: "stub" }),
      buildAndSign: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
      packageCredential: async () => ({ success: true }),
      queueRevocation: async () => ({ success: true }),
      getRevocationStatus: async () => ({ items: [] }),
      publishRevocations: async () => ({ results: [] }),
      openFile: async () => ({ content: null, filePath: null }),
      saveFile: async () => ({ filePath: null }),
      getOfflineStatus: async () => false,
      getConfig: async () => undefined,
      setConfig: async () => {},
    };

    expect(typeof api.importKey).toBe("function");
    expect(typeof api.listKeys).toBe("function");
    expect(typeof api.listSchemas).toBe("function");
    expect(typeof api.getSchema).toBe("function");
    expect(typeof api.signCredential).toBe("function");
    expect(typeof api.buildAndSign).toBe("function");
    expect(typeof api.verifyCredential).toBe("function");
    expect(typeof api.packageCredential).toBe("function");
    expect(typeof api.queueRevocation).toBe("function");
    expect(typeof api.getRevocationStatus).toBe("function");
    expect(typeof api.publishRevocations).toBe("function");
    expect(typeof api.openFile).toBe("function");
    expect(typeof api.saveFile).toBe("function");
    expect(typeof api.getOfflineStatus).toBe("function");
    expect(typeof api.getConfig).toBe("function");
    expect(typeof api.setConfig).toBe("function");

    // Exactly 16 methods.
    expect(Object.keys(api)).toHaveLength(16);
  });
});
