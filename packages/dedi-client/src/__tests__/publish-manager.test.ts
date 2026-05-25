import { describe, it, expect, vi, beforeEach } from "vitest";
import { DeDiPublishManager, createPublishManager } from "../publish-manager.js";
import { DeDiClient } from "../adapter/client.js";
import type { SchemaRecord, PublishResult } from "../adapter/types.js";

// Mock DeDiClient
vi.mock("../adapter/client.js", () => {
  const MockDeDiClient = vi.fn();
  MockDeDiClient.prototype.publishSchema = vi.fn();
  MockDeDiClient.prototype.publishDID = vi.fn();
  MockDeDiClient.prototype.ensureRegistries = vi.fn();
  MockDeDiClient.prototype.rotateDIDWeb = vi.fn();
  MockDeDiClient.prototype.logger = { info() {}, debug() {}, warn() {}, error() {} };
  return { DeDiClient: MockDeDiClient };
});

function createMockClient(): DeDiClient {
  return new DeDiClient({
    baseUrl: "https://dedi.example.com",
    timeoutMs: 5000,
    maxRetries: 0,
    circuitBreakerThreshold: 5,
    auth: { type: "api-key", apiKey: "dk_test" },
  });
}

const testSchema: SchemaRecord = {
  schemaId: "functional-identity/v1",
  version: "1",
  schema: { type: "object" },
  checksum: "abc",
  publishedAt: "2026-03-25T00:00:00Z",
};

const publishResult: PublishResult = {
  published: true,
  recordName: "functional-identity-v1",
  namespace: "example.com",
};

describe("DeDiPublishManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("ensureSchemaPublished", () => {
    it("publishes schema on first call", async () => {
      const client = createMockClient();
      vi.mocked(client.publishSchema).mockResolvedValue(publishResult);

      const manager = new DeDiPublishManager(client);
      const result = await manager.ensureSchemaPublished(testSchema);

      expect(result).toEqual(publishResult);
      expect(client.publishSchema).toHaveBeenCalledTimes(1);
    });

    it("skips publish on second call (cached)", async () => {
      const client = createMockClient();
      vi.mocked(client.publishSchema).mockResolvedValue(publishResult);

      const manager = new DeDiPublishManager(client);
      await manager.ensureSchemaPublished(testSchema);
      const result2 = await manager.ensureSchemaPublished(testSchema);

      expect(result2).toBeNull();
      expect(client.publishSchema).toHaveBeenCalledTimes(1);
    });

    it("skips if schema was in alreadyPublished list", async () => {
      const client = createMockClient();

      const manager = new DeDiPublishManager(client, ["functional-identity-v1"]);
      const result = await manager.ensureSchemaPublished(testSchema);

      expect(result).toBeNull();
      expect(client.publishSchema).not.toHaveBeenCalled();
    });

    it("swallows errors (fire-and-forget)", async () => {
      const client = createMockClient();
      vi.mocked(client.publishSchema).mockRejectedValue(new Error("network error"));

      const manager = new DeDiPublishManager(client);
      const result = await manager.ensureSchemaPublished(testSchema);

      expect(result).toBeNull();
      // No error thrown
    });
  });

  describe("publishDIDDocument", () => {
    it("publishes DID document", async () => {
      const client = createMockClient();
      const didResult: PublishResult = {
        published: true,
        recordName: "did-web-example.com",
        namespace: "example.com",
      };
      vi.mocked(client.publishDID).mockResolvedValue(didResult);

      const manager = new DeDiPublishManager(client);
      const result = await manager.publishDIDDocument("did:web:example.com", {
        id: "did:web:example.com",
      });

      expect(result).toEqual(didResult);
    });

    it("swallows errors (fire-and-forget)", async () => {
      const client = createMockClient();
      vi.mocked(client.publishDID).mockRejectedValue(new Error("timeout"));

      const manager = new DeDiPublishManager(client);
      const result = await manager.publishDIDDocument("did:web:x.com", {});

      expect(result).toBeNull();
    });
  });

  describe("rotateDIDWeb", () => {
    // The publish-manager wraps the adapter's `rotateDIDWeb` so DeDi
    // outages don't crash callers. Successful rotations surface the
    // adapter's RotateResult unchanged; failures collapse to `null`
    // and the error is logged, mirroring the contract of every other
    // method on this class.
    const rotatedResult = {
      rotated: true as const,
      did: "did:web:issuer.example.org",
      currentKeyId: "did:web:issuer.example.org#key-2",
      superseded: ["did:web:issuer.example.org#key-1"],
      namespace: "example.com",
    };
    const noopResult = {
      rotated: false as const,
      did: "did:web:issuer.example.org",
      currentKeyId: "did:web:issuer.example.org#key-1",
      reason: "already-current" as const,
      namespace: "example.com",
    };
    const newKeyJwk = { kty: "EC", crv: "P-256", x: "abc", y: "def" };

    it("returns the adapter's RotateResult on success", async () => {
      const client = createMockClient();
      vi.mocked(client.rotateDIDWeb).mockResolvedValue(rotatedResult);

      const manager = new DeDiPublishManager(client);
      const result = await manager.rotateDIDWeb(
        "did:web:issuer.example.org",
        newKeyJwk,
        "example.com",
      );

      expect(result).toEqual(rotatedResult);
      expect(client.rotateDIDWeb).toHaveBeenCalledWith(
        "did:web:issuer.example.org",
        newKeyJwk,
        "example.com",
      );
    });

    it("passes through the idempotent no-op (rotated:false) shape", async () => {
      const client = createMockClient();
      vi.mocked(client.rotateDIDWeb).mockResolvedValue(noopResult);

      const manager = new DeDiPublishManager(client);
      const result = await manager.rotateDIDWeb("did:web:issuer.example.org", newKeyJwk);

      expect(result).toEqual(noopResult);
    });

    it("returns null on adapter failure (fire-and-forget logging)", async () => {
      const client = createMockClient();
      vi.mocked(client.rotateDIDWeb).mockRejectedValue(new Error("DeDi 502"));

      const manager = new DeDiPublishManager(client);
      const result = await manager.rotateDIDWeb("did:web:issuer.example.org", newKeyJwk);

      expect(result).toBeNull();
    });
  });

  describe("ensureRegistries", () => {
    it("delegates to client and returns true on success", async () => {
      const client = createMockClient();
      vi.mocked(client.ensureRegistries).mockResolvedValue(undefined);

      const manager = new DeDiPublishManager(client);
      const result = await manager.ensureRegistries("example.com");

      expect(result).toBe(true);
      expect(client.ensureRegistries).toHaveBeenCalledWith("example.com");
    });

    it("returns false on error (fire-and-forget)", async () => {
      const client = createMockClient();
      vi.mocked(client.ensureRegistries).mockRejectedValue(new Error("fail"));

      const manager = new DeDiPublishManager(client);
      const result = await manager.ensureRegistries("example.com");

      expect(result).toBe(false);
    });
  });

  describe("getPublishedSchemaIds", () => {
    it("returns IDs of published schemas", async () => {
      const client = createMockClient();
      vi.mocked(client.publishSchema).mockResolvedValue(publishResult);

      const manager = new DeDiPublishManager(client);
      await manager.ensureSchemaPublished(testSchema);

      expect(manager.getPublishedSchemaIds()).toEqual(["functional-identity-v1"]);
    });

    it("includes pre-loaded IDs", () => {
      const client = createMockClient();
      const manager = new DeDiPublishManager(client, ["existing-v1"]);

      expect(manager.getPublishedSchemaIds()).toContain("existing-v1");
    });
  });
});

describe("createPublishManager", () => {
  it("returns null when config is null", () => {
    const result = createPublishManager(null);
    expect(result).toBeNull();
  });

  it("returns DeDiPublishManager when config and logger are provided", () => {
    const testLogger = { info() {}, debug() {}, warn() {}, error() {} };
    const result = createPublishManager(
      {
        baseUrl: "https://dedi.example.com",
        timeoutMs: 5000,
        maxRetries: 0,
        circuitBreakerThreshold: 5,
        auth: { type: "api-key", apiKey: "dk_test" },
      },
      undefined,
      testLogger,
    );
    expect(result).toBeInstanceOf(DeDiPublishManager);
  });

  it("throws when config is provided but logger is missing", () => {
    expect(() =>
      createPublishManager({
        baseUrl: "https://dedi.example.com",
        timeoutMs: 5000,
        maxRetries: 0,
        circuitBreakerThreshold: 5,
        auth: { type: "api-key", apiKey: "dk_test" },
      }),
    ).toThrow("requires a logger");
  });
});
