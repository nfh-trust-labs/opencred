import { DeDiClient } from "./adapter/client.js";
import { schemaToRecordName } from "./adapter/registry-names.js";
import type {
  DeDiClientConfig,
  SchemaRecord,
  ContextRecord,
  PublishResult,
  KeyRecord,
  KeyStatus,
  SetKeyStatusResult,
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
   * The underlying DeDi client.
   *
   * Read-only access for consumers that need to perform DeDi operations
   * outside the publish-manager's lazy-publish workflow — primarily
   * verification paths that need `resolveDidWebDocument()` for did:web
   * fallback (see `createDeDiDIDWebFallback`). Reusing the manager's client
   * preserves the shared circuit breaker, retry state, and auth token
   * cache rather than spinning up a parallel client.
   */
  get rawClient(): DeDiClient {
    return this.client;
  }

  /**
   * Lazily publish a schema to DeDi if not already published.
   * Fire-and-forget: errors are logged, never thrown.
   */
  async ensureSchemaPublished(
    schema: SchemaRecord,
    namespace?: string,
  ): Promise<PublishResult | null> {
    const key = schemaToRecordName(schema.schemaId, schema.version);
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
  async publishContext(record: ContextRecord, namespace?: string): Promise<PublishResult | null> {
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
   * Publish a signing key to the `opencred-key-registry`.
   * Fire-and-forget: errors are logged, never thrown.
   *
   * The manager only ever sees the public `publicKeyJwk` carried in the
   * {@link KeyRecord}; private key material never reaches DeDi.
   */
  async publishKey(key: KeyRecord, namespace?: string): Promise<PublishResult | null> {
    try {
      const result = await this.client.publishKey(key, namespace);
      this.logger.debug("Key published to DeDi", {
        keyId: key.keyId,
        recordName: result.recordName,
      });
      return result;
    } catch (error) {
      this.logger.error("Failed to publish key to DeDi (non-fatal)", {
        keyId: key.keyId,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  /**
   * Advance a key's lifecycle status (`active → rotated → revoked`) in the
   * `opencred-key-registry`. Delegates to {@link DeDiClient.setKeyStatus} —
   * see that method for the monotone-transition semantics.
   *
   * The publish-manager is the boundary where DeDi failures are downgraded
   * from "throws" to "returns null / logged". A user-triggered
   * rotate/revoke should be able to surface failure to the UI, so this
   * returns the {@link SetKeyStatusResult} on success or `null` when DeDi
   * was unreachable / the key was never published. Callers must treat
   * `null` as "status not changed" — never as silent success.
   */
  async setKeyStatus(
    verificationMethod: string,
    status: KeyStatus,
    namespace?: string,
  ): Promise<SetKeyStatusResult | null> {
    try {
      const result = await this.client.setKeyStatus(verificationMethod, status, namespace);
      this.logger.debug("Key status transition in DeDi", {
        keyId: verificationMethod,
        status,
        changed: result.changed,
      });
      return result;
    } catch (error) {
      this.logger.error("Failed to set key status in DeDi (non-fatal)", {
        keyId: verificationMethod,
        status,
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
    throw new Error(
      "DeDiPublishManager requires a logger — silent error swallowing without logging is unsafe",
    );
  }
  const client = new DeDiClient({ ...config, logger });
  return new DeDiPublishManager(client, alreadyPublished);
}
