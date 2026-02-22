import { describe, it, expect } from "vitest";
import { loadConfig } from "@opencred/shared";

describe("Startup config validation", () => {
  it("returns valid config with all defaults", () => {
    const config = loadConfig({});
    expect(config.NODE_ENV).toBe("development");
    expect(config.PORT).toBe(3000);
    expect(config.LOG_LEVEL).toBe("info");
    expect(config.CORS_ORIGIN).toBe("http://localhost:5173");
    expect(config.SESSION_TTL_MS).toBe(4 * 60 * 60 * 1000);
  });

  it("accepts valid environment overrides", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      PORT: "8080",
      LOG_LEVEL: "error",
      CORS_ORIGIN: "https://app.example.com",
    });
    expect(config.NODE_ENV).toBe("production");
    expect(config.PORT).toBe(8080);
    expect(config.LOG_LEVEL).toBe("error");
    expect(config.CORS_ORIGIN).toBe("https://app.example.com");
  });

  it("throws on invalid NODE_ENV", () => {
    expect(() => loadConfig({ NODE_ENV: "staging" })).toThrow("Invalid environment configuration");
  });

  it("throws on invalid PORT (non-numeric)", () => {
    expect(() => loadConfig({ PORT: "abc" })).toThrow("Invalid environment configuration");
  });

  it("throws on invalid LOG_LEVEL", () => {
    expect(() => loadConfig({ LOG_LEVEL: "verbose" })).toThrow("Invalid environment configuration");
  });

  it("coerces string PORT to number", () => {
    const config = loadConfig({ PORT: "9090" });
    expect(config.PORT).toBe(9090);
    expect(typeof config.PORT).toBe("number");
  });

  it("uses default JWT settings when not provided", () => {
    const config = loadConfig({});
    expect(config.JWT_ISSUER).toBe("opencred");
    expect(config.JWT_EXPIRY_SECONDS).toBe(3600);
  });
});
