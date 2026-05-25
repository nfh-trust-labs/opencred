import { DeDiClient } from "./adapter/client.js";
import { schemaToRecordName } from "./adapter/registry-names.js";
import type {
  DeDiClientConfig,
  SchemaRecord,
  ContextRecord,
  PublishResult,
  RotateResult,
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
   * verification paths that need `resolveDID()` for did:web fallback
   * (see `createDeDiDIDWebFallback`). Reusing the manager's client
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
   * Mark a previously-published DID as rotated in DeDi (sets
   * `keyStatus: "rotated"` on the record).
   *
   * Fire-and-forget: errors are logged, never thrown — same rationale
   * as `publishDIDDocument`. A 404 (record never existed) and a 502
   * (DeDi outage) both surface as `false` so callers can decide whether
   * to alert; key generation itself is never blocked by a DeDi failure.
   */
  async markDIDRotated(did: string, namespace?: string): Promise<boolean> {
    try {
      await this.client.markDIDRotated(did, namespace);
      this.logger.debug("DID marked as rotated in DeDi", { did });
      return true;
    } catch (error) {
      this.logger.error("Failed to mark DID as rotated in DeDi (non-fatal)", {
        did,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Rotate a `did:web` issuer's signing key inside its existing DID
   * Document. Delegates to `DeDiClient.rotateDIDWeb` — see that method's
   * docstring for the full semantics (read-merge-write,
   * `supersededAt`-stamping the prior verificationMethod entries,
   * appending the new VM, repointing `assertionMethod`, idempotent
   * short-circuit when the active key already matches the latest VM).
   *
   * Why this lives here and not just as a `rawClient.rotateDIDWeb()`
   * call: the publish-manager is the boundary where DeDi failures are
   * downgraded from "throws" to "returns null / logged warn". User-
   * triggered rotation should surface failure to the UI (so we don't
   * blanket-swallow as `markDIDRotated` does), but the manager still
   * owns the logging contract — a DeDi outage shouldn't crash the
   * desktop, it should return `null` and let the IPC handler decide
   * whether to show an error toast.
   *
   * Returns the {@link RotateResult} from the adapter on success, or
   * `null` when DeDi was unreachable / the record was missing /
   * `rotateDIDWeb` rejected. Callers should treat `null` as "rotation
   * not applied" — never as silent success.
   */
  async rotateDIDWeb(
    did: string,
    newKeyJwk: Record<string, unknown>,
    namespace?: string,
  ): Promise<RotateResult | null> {
    try {
      const result = await this.client.rotateDIDWeb(did, newKeyJwk, namespace);
      this.logger.debug("did:web key rotated in DeDi", {
        did,
        rotated: result.rotated,
        currentKeyId: result.currentKeyId,
      });
      return result;
    } catch (error) {
      this.logger.error("Failed to rotate did:web key in DeDi (non-fatal)", {
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
    throw new Error(
      "DeDiPublishManager requires a logger — silent error swallowing without logging is unsafe",
    );
  }
  const client = new DeDiClient({ ...config, logger });
  return new DeDiPublishManager(client, alreadyPublished);
}
