import { describe, it, expect } from "vitest";
import { loadConfig } from "../config.js";

describe("loadConfig", () => {
  it("returns defaults for minimal env", () => {
    const config = loadConfig({});
    expect(config.NODE_ENV).toBe("development");
    expect(config.PORT).toBe(3000);
    expect(config.LOG_LEVEL).toBe("info");
    expect(config.SESSION_TTL_MS).toBe(4 * 60 * 60 * 1000);
    expect(config.SESSION_SWEEP_INTERVAL_MS).toBe(60 * 1000);
  });

  it("parses valid env values", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      PORT: "8080",
      LOG_LEVEL: "debug",
      DEDI_API_URL: "https://dedi.example.com",
      DEDI_AUTH_TYPE: "api-key",
      DEDI_API_KEY: "test-placeholder-value",
      // Required in production — see P3-02.
      CORS_ORIGIN: "https://app.example.com",
    });
    expect(config.NODE_ENV).toBe("production");
    expect(config.PORT).toBe(8080);
    expect(config.LOG_LEVEL).toBe("debug");
    expect(config.DEDI_API_URL).toBe("https://dedi.example.com");
    expect(config.DEDI_AUTH_TYPE).toBe("api-key");
    expect(config.CORS_ORIGIN).toBe("https://app.example.com");
  });

  it("throws on invalid NODE_ENV", () => {
    expect(() => loadConfig({ NODE_ENV: "invalid" })).toThrow("Invalid environment configuration");
  });

  it("throws on invalid PORT", () => {
    expect(() => loadConfig({ PORT: "-1" })).toThrow("Invalid environment configuration");
  });

  it("requires DEDI_API_KEY when auth type is api-key and DEDI_API_URL is set", () => {
    expect(() =>
      loadConfig({ DEDI_API_URL: "https://dedi.example.com", DEDI_AUTH_TYPE: "api-key" }),
    ).toThrow("DEDI_API_KEY");
  });

  it("requires DEDI_EMAIL and DEDI_PASSWORD when auth type is bearer and DEDI_API_URL is set", () => {
    expect(() =>
      loadConfig({ DEDI_API_URL: "https://dedi.example.com", DEDI_AUTH_TYPE: "bearer" }),
    ).toThrow("DEDI_EMAIL");
  });

  it("does not require DeDi auth fields when DEDI_API_URL is not set", () => {
    const config = loadConfig({});
    expect(config.DEDI_API_URL).toBeUndefined();
    expect(config.DEDI_AUTH_TYPE).toBe("api-key");
  });

  it("rejects empty DEDI_PASSWORD", () => {
    expect(() =>
      loadConfig({
        DEDI_API_URL: "https://dedi.example.com",
        DEDI_AUTH_TYPE: "bearer",
        DEDI_EMAIL: "user@example.com",
        DEDI_PASSWORD: "",
      }),
    ).toThrow("Invalid environment configuration");
  });

  // Anand's P3-02: the Vite dev-server port as a production default
  // silently broke cross-origin requests. Fail loud in production.
  describe("CORS_ORIGIN (P3-02)", () => {
    it("dev: defaults to http://localhost:5173 when unset", () => {
      const config = loadConfig({});
      expect(config.NODE_ENV).toBe("development");
      expect(config.CORS_ORIGIN).toBe("http://localhost:5173");
    });

    it("production + unset: refuses to load with a clear error", () => {
      expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(
        /CORS_ORIGIN must be set to the production frontend origin/,
      );
    });

    it("production + explicit origin: loads successfully", () => {
      const config = loadConfig({
        NODE_ENV: "production",
        CORS_ORIGIN: "https://issuer.example.com",
      });
      expect(config.CORS_ORIGIN).toBe("https://issuer.example.com");
    });

    it("test: inherits the dev default (test envs rarely exercise CORS)", () => {
      const config = loadConfig({ NODE_ENV: "test" });
      expect(config.CORS_ORIGIN).toBe("http://localhost:5173");
    });
  });
});
