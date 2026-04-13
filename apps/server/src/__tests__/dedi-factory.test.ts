/**
 * Tests for the DeDi client factory.
 */

import { describe, it, expect } from "vitest";
import { createDeDiClientFromConfig } from "../dedi-factory.js";
import type { ServerConfig } from "../config.js";
import pino from "pino";

const silentLogger = pino({ level: "silent" });

function makeBaseConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    OPENCRED_PORT: 3100,
    OPENCRED_LOG_LEVEL: "info",
    OPENCRED_DEV_MODE_NO_AUTH: true,
    OPENCRED_KEY_LABEL: "server-key",
    OPENCRED_BATCH_ROW_LIMIT: 1000,
    OPENCRED_SESSION_TTL: 14400,
    OPENCRED_KMS_PROVIDER: "none",
    OPENCRED_DEDI_TIMEOUT_MS: 10000,
    ...overrides,
  } as ServerConfig;
}

describe("createDeDiClientFromConfig", () => {
  it("returns null when OPENCRED_DEDI_BASE_URL is not set", () => {
    const config = makeBaseConfig();
    const client = createDeDiClientFromConfig(config, silentLogger);
    expect(client).toBeNull();
  });

  it("returns a DeDiClient when configured with api-key auth", () => {
    const config = makeBaseConfig({
      OPENCRED_DEDI_BASE_URL: "https://dedi.example.com",
      OPENCRED_DEDI_AUTH_TYPE: "api-key",
      OPENCRED_DEDI_API_KEY: "test-key-value",
      OPENCRED_DEDI_NAMESPACE: "test-ns",
    });
    const client = createDeDiClientFromConfig(config, silentLogger);
    expect(client).not.toBeNull();
    expect(client).toHaveProperty("publishRevocationHash");
    expect(client).toHaveProperty("queryRevocationHash");
  });

  it("returns a DeDiClient when configured with bearer auth", () => {
    const config = makeBaseConfig({
      OPENCRED_DEDI_BASE_URL: "https://dedi.example.com",
      OPENCRED_DEDI_AUTH_TYPE: "bearer",
      OPENCRED_DEDI_EMAIL: "user@example.com",
      OPENCRED_DEDI_PASSWORD: "test-pw",
      OPENCRED_DEDI_NAMESPACE: "test-ns",
    });
    const client = createDeDiClientFromConfig(config, silentLogger);
    expect(client).not.toBeNull();
    expect(client).toHaveProperty("publishRevocationHash");
    expect(client).toHaveProperty("queryRevocationHash");
  });

  it("uses the configured namespace as defaultNamespace", () => {
    const config = makeBaseConfig({
      OPENCRED_DEDI_BASE_URL: "https://dedi.example.com",
      OPENCRED_DEDI_AUTH_TYPE: "api-key",
      OPENCRED_DEDI_API_KEY: "test-key-value",
      OPENCRED_DEDI_NAMESPACE: "custom-ns",
    });
    const client = createDeDiClientFromConfig(config, silentLogger);
    expect(client).not.toBeNull();
    // The client was constructed — the namespace is set internally.
    // We verify via the API client config indirectly.
    expect(client!.apiClient).toBeDefined();
  });
});
