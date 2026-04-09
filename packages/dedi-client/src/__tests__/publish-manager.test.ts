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
  MockDeDiClient.prototype.logger = { debug() {}, warn() {}, error() {} };
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
    const testLogger = { debug() {}, warn() {}, error() {} };
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
