import { DeDiClient } from "./adapter/client.js";
import type {
  DeDiClientConfig,
  SchemaRecord,
  ContextRecord,
  PublishResult,
} from "./adapter/types.js";
import type { DeDiLogger } from "./logger.js";

export class DeDiPublishManager {
  private readonly client: DeDiClient;
  private readonly publishedSchemas: Set<string>;
  private readonly logger: DeDiLogger;

  constructor(client: DeDiClient, alreadyPublished?: string[]) {
    this.client = client;
    this.publishedSchemas = new Set(alreadyPublished);
    this.logger = client.logger;
  }

  /**
   * Lazily publish a schema to DeDi if not already published.
   * Fire-and-forget: errors are logged, never thrown.
   */
  async ensureSchemaPublished(
    schema: SchemaRecord,
    namespace?: string,
  ): Promise<PublishResult | null> {
    const key = `${schema.schemaId}-v${schema.version}`;
    if (this.publishedSchemas.has(key)) {
      return null;
    }

    try {
      const result = await this.client.publishSchema(schema, namespace);
      this.publishedSchemas.add(key);
      this.logger.debug("Schema published to DeDi", {
        schemaId: schema.schemaId,
        version: schema.version,
        recordName: result.recordName,
      });
      return result;
    } catch (error) {
      this.logger.error("Failed to publish schema to DeDi (non-fatal)", {
        schemaId: schema.schemaId,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  /**
   * Publish a JSON-LD context to DeDi.
   * Fire-and-forget: errors are logged, never thrown.
   */
  async publishContext(
    record: ContextRecord,
    namespace?: string,
  ): Promise<PublishResult | null> {
    try {
      const result = await this.client.publishContext(record, namespace);
      this.logger.debug("Context published to DeDi", {
        schemaId: record.schemaId,
        version: record.version,
        recordName: result.recordName,
      });
      return result;
    } catch (error) {
      this.logger.error("Failed to publish context to DeDi (non-fatal)", {
        schemaId: record.schemaId,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  /**
   * Publish a DID document to DeDi.
   * Fire-and-forget: errors are logged, never thrown.
   */
  async publishDIDDocument(
    did: string,
    document: unknown,
    namespace?: string,
  ): Promise<PublishResult | null> {
    try {
      const result = await this.client.publishDID(did, document, namespace);
      this.logger.debug("DID document published to DeDi", {
        did,
        recordName: result.recordName,
      });
      return result;
    } catch (error) {
      this.logger.error("Failed to publish DID document to DeDi (non-fatal)", {
        did,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  /**
   * Ensure all required registries exist in the namespace.
   * Fire-and-forget: errors are logged, never thrown.
   */
  async ensureRegistries(namespace: string): Promise<boolean> {
    try {
      await this.client.ensureRegistries(namespace);
      this.logger.debug("DeDi registries ensured", { namespace });
      return true;
    } catch (error) {
      this.logger.error("Failed to ensure DeDi registries (non-fatal)", {
        namespace,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  getPublishedSchemaIds(): string[] {
    return [...this.publishedSchemas];
  }
}

/**
 * Factory that returns null when config is absent — the optionality guard.
 * All callers use `manager?.method()` to handle the unconfigured case.
 */
export function createPublishManager(
  config: DeDiClientConfig | null,
  alreadyPublished?: string[],
  logger?: DeDiLogger,
): DeDiPublishManager | null {
  if (!config) return null;
  if (!logger) {
    throw new Error("DeDiPublishManager requires a logger — silent error swallowing without logging is unsafe");
  }
  const client = new DeDiClient({ ...config, logger });
  return new DeDiPublishManager(client, alreadyPublished);
}
