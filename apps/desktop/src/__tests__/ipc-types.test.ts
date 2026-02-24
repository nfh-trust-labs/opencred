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
  SignCredentialRequest,
  SignCredentialResponse,
  VerifyCredentialRequest,
  VerifyCredentialResponse,
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

  it("KeyMetadata should accept an optional label", () => {
    const meta: KeyMetadata = {
      id: "abc123",
      fingerprint: "deadbeef",
      algorithm: "EC P-256",
      importedAt: "2026-01-01T00:00:00Z",
      label: "My signing key",
    };
    expect(meta.label).toBe("My signing key");
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
      signCredential: async () => ({ success: false, error: "stub" }),
      verifyCredential: async () => ({ success: true, valid: true }),
      openFile: async () => ({ content: null, filePath: null }),
      saveFile: async () => ({ filePath: null }),
      getOfflineStatus: async () => false,
      getConfig: async () => undefined,
      setConfig: async () => {},
    };

    expect(typeof api.importKey).toBe("function");
    expect(typeof api.listKeys).toBe("function");
    expect(typeof api.signCredential).toBe("function");
    expect(typeof api.verifyCredential).toBe("function");
    expect(typeof api.openFile).toBe("function");
    expect(typeof api.saveFile).toBe("function");
    expect(typeof api.getOfflineStatus).toBe("function");
    expect(typeof api.getConfig).toBe("function");
    expect(typeof api.setConfig).toBe("function");

    // Exactly 9 methods.
    expect(Object.keys(api)).toHaveLength(9);
  });
});
