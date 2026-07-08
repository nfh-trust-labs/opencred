/**
 * SSRF regression tests for the SCHEMA_FETCH_URL IPC handler.
 *
 * Verifies that the handler validates every resolved A/AAAA record via
 * `resolveDnsForSsrf` (canonical SSRF helper) rather than a single-address
 * `dns.lookup`, so hostnames that round-robin between public and private
 * records cannot be used to bypass SSRF.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import * as os from "node:os";

// ---------------------------------------------------------------------------
// Mocks — must be installed before importing ipc-handlers
// ---------------------------------------------------------------------------

const registeredHandlers: Record<string, (...args: unknown[]) => unknown> = {};

vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      registeredHandlers[channel] = handler;
    }),
  },
  app: {
    getPath: vi.fn(() => os.tmpdir()),
    getVersion: vi.fn(() => "0.1.0-test"),
    getName: vi.fn(() => "opencred-test"),
    isPackaged: false,
  },
  dialog: { showOpenDialog: vi.fn(), showSaveDialog: vi.fn() },
  safeStorage: {
    isEncryptionAvailable: vi.fn(() => false),
    encryptString: vi.fn((s: string) => Buffer.from(s)),
    decryptString: vi.fn((b: Buffer) => b.toString()),
  },
  BrowserWindow: vi.fn(),
}));

const storeData: Record<string, unknown> = {
  recentTemplates: [],
  dediPublishedSchemas: [],
  credentialHistory: [],
};
vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => ({
    get: vi.fn((key: string) => storeData[key]),
    set: vi.fn((key: string, value: unknown) => {
      storeData[key] = value;
    }),
    store: {},
  })),
}));

vi.mock("electron-updater", () => ({
  default: { autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() } },
  autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() },
}));

vi.mock("@opencred/dedi-client", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    createPublishManager: vi.fn(() => ({
      ensureSchemaPublished: vi.fn(),
      publishKey: vi.fn(),
      setKeyStatus: vi.fn(),
      ensureRegistries: vi.fn(),
      getPublishedSchemaIds: () => [],
    })),
    DeDiPublishManager: vi.fn(),
  };
});

vi.mock("../signing/os-cert-provider", () => ({
  listOsCertificates: vi.fn(async () => []),
  signWithOsCert: vi.fn(),
}));

// Mock the node:dns module that `resolveDnsForSsrf` consumes. We mock it at
// this layer (rather than the shared helper) so we exercise the full fetch
// handler → resolveDnsForSsrf → DNS resolution path end-to-end.
const mockResolve4 = vi.fn();
const mockResolve6 = vi.fn();
vi.mock("node:dns", () => ({
  promises: {
    resolve4: (...args: unknown[]) => mockResolve4(...args),
    resolve6: (...args: unknown[]) => mockResolve6(...args),
  },
}));

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ---------------------------------------------------------------------------
// Import under test — after all mocks are installed
// ---------------------------------------------------------------------------

const { registerIpcHandlers } = await import("../main/ipc-handlers");
registerIpcHandlers();

const schemaFetchUrlHandler = registeredHandlers["schema:fetch-url"] as (
  event: unknown,
  request: { url: string },
) => Promise<{ success: boolean; error?: string }>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function enodata(): Error {
  return Object.assign(new Error("queryA ENODATA"), { code: "ENODATA" });
}

function validJsonSchemaResponse(): {
  ok: boolean;
  status: number;
  statusText: string;
  json: () => Promise<unknown>;
} {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: () =>
      Promise.resolve({
        title: "Test",
        properties: { name: { type: "string" } },
      }),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SCHEMA_FETCH_URL SSRF protection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("rejects when DNS resolves to a mix of public A and private AAAA records", async () => {
    // This is the regression that the old dns.lookup-based implementation
    // could not catch: getaddrinfo may return the first public record and
    // leave the private AAAA unchecked. resolveDnsForSsrf validates both.
    mockResolve4.mockResolvedValue(["93.184.216.34"]);
    mockResolve6.mockResolvedValue(["fd00::1"]);

    const result = await schemaFetchUrlHandler(
      {},
      { url: "https://mixed.example.org/schema.json" },
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("URL resolves to a private or unreachable IP");
    // Never reaches fetch when the SSRF check fails.
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("rejects when all A records are public but an AAAA record is private", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34", "1.1.1.1"]);
    mockResolve6.mockResolvedValue(["::1"]);

    const result = await schemaFetchUrlHandler(
      {},
      { url: "https://rebind.example.org/schema.json" },
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("URL resolves to a private or unreachable IP");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("rejects when an A record is private even though AAAA is absent", async () => {
    mockResolve4.mockResolvedValue(["10.0.0.1"]);
    mockResolve6.mockRejectedValue(enodata());

    const result = await schemaFetchUrlHandler(
      {},
      { url: "https://private-only.example.org/schema.json" },
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("URL resolves to a private or unreachable IP");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("fails closed when DNS resolution fails with a transient error", async () => {
    // ETIMEOUT / ESERVFAIL / network errors must fail closed — we cannot
    // verify the address is public, so the fetch must not proceed.
    mockResolve4.mockRejectedValue(Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" }));
    mockResolve6.mockRejectedValue(enodata());

    const result = await schemaFetchUrlHandler(
      {},
      { url: "https://dns-timeout.example.org/schema.json" },
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("URL resolves to a private or unreachable IP");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("fails closed when no DNS records are returned (NXDOMAIN)", async () => {
    mockResolve4.mockRejectedValue(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    mockResolve6.mockRejectedValue(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));

    const result = await schemaFetchUrlHandler(
      {},
      { url: "https://nxdomain.example.org/schema.json" },
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("URL resolves to a private or unreachable IP");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("accepts hostnames that resolve only to public IPs", async () => {
    mockResolve4.mockResolvedValue(["93.184.216.34"]);
    mockResolve6.mockResolvedValue(["2606:2800:220:1:248:1893:25c8:1946"]);
    mockFetch.mockResolvedValue(validJsonSchemaResponse());

    const result = await schemaFetchUrlHandler(
      {},
      { url: "https://public.example.org/schema.json" },
    );

    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("rejects HTTP URLs before any DNS resolution runs", async () => {
    const result = await schemaFetchUrlHandler({}, { url: "http://example.org/schema.json" });

    expect(result.success).toBe(false);
    expect(result.error).toBe("URL must use HTTPS");
    expect(mockResolve4).not.toHaveBeenCalled();
    expect(mockResolve6).not.toHaveBeenCalled();
  });
});
