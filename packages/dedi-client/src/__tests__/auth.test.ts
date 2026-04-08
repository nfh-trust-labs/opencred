import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DeDiTokenManager } from "../api/auth.js";
import type { DeDiAuthConfig } from "../api/auth.js";

function createBearerConfig(
  overrides?: Partial<Pick<DeDiAuthConfig, "baseUrl">> & {
    auth?: Partial<Extract<DeDiAuthConfig["auth"], { type: "bearer" }>>;
  },
): DeDiAuthConfig {
  return {
    baseUrl: overrides?.baseUrl ?? "https://dedi.example.com",
    auth: {
      type: "bearer",
      email: "user@test.com",
      password: "s3cret",
      refreshBufferMs: 60_000,
      ...overrides?.auth,
    },
  };
}

function createApiKeyConfig(): DeDiAuthConfig {
  return {
    baseUrl: "https://dedi.example.com",
    auth: { type: "api-key", apiKey: "dk_test_abc123" },
  };
}

/** Helper: creates a fake JWT with a given exp claim (seconds since epoch). */
function fakeJwt(expSeconds: number): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(JSON.stringify({ exp: expSeconds }));
  return `${header}.${payload}.fake-signature`;
}

/** Helper: creates a JWT expiring N seconds from "now" (using vi.now). */
function jwtExpiringIn(seconds: number): string {
  const nowSec = Math.floor(Date.now() / 1000);
  return fakeJwt(nowSec + seconds);
}

describe("DeDiTokenManager", () => {
  const originalFetch = globalThis.fetch;
  let mockFetch: ReturnType<typeof vi.fn<typeof globalThis.fetch>>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn<typeof globalThis.fetch>();
    globalThis.fetch = mockFetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
  });

  // ── API key mode ─────────────────────────────────────────────────

  describe("API key mode", () => {
    it("returns the API key directly without any HTTP call", async () => {
      const tm = new DeDiTokenManager(createApiKeyConfig());
      const token = await tm.getToken();

      expect(token).toBe("dk_test_abc123");
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("always returns the same API key on repeated calls", async () => {
      const tm = new DeDiTokenManager(createApiKeyConfig());
      const t1 = await tm.getToken();
      const t2 = await tm.getToken();

      expect(t1).toBe(t2);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ── Bearer mode — login ──────────────────────────────────────────

  describe("bearer mode — login", () => {
    it("logs in via POST /dedi/register with action login", async () => {
      const jwt = jwtExpiringIn(3600);
      mockFetch.mockResolvedValue(
        new Response(
          JSON.stringify({ access_token: jwt, refresh_token: "rt_abc", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      const token = await tm.getToken();

      expect(token).toBe(jwt);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://dedi.example.com/dedi/register");
      const body = JSON.parse(init?.body as string);
      expect(body).toEqual({
        email: "user@test.com",
        password: "s3cret",
        action: "login",
      });
    });

    it("returns cached token on subsequent calls when not expired", async () => {
      const jwt = jwtExpiringIn(3600);
      mockFetch.mockResolvedValue(
        new Response(
          JSON.stringify({ access_token: jwt, refresh_token: "rt_abc", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await tm.getToken();
      await tm.getToken();

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("throws on invalid credentials (401)", async () => {
      mockFetch.mockResolvedValue(new Response("Unauthorized", { status: 401 }));

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow("DeDi authentication failed: 401");
    });
  });

  // ── Bearer mode — refresh ────────────────────────────────────────

  describe("bearer mode — refresh", () => {
    it("refreshes token before expiry based on buffer", async () => {
      // Token expires in 90 seconds, buffer is 60s, so it's "expiring soon"
      const soonJwt = jwtExpiringIn(50);
      const freshJwt = jwtExpiringIn(3600);

      // First call: login returns soon-expiring token
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      // Second call: refresh returns fresh token
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: freshJwt, refresh_token: "rt_2", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken(); // triggers login
      const token = await tm.getToken(); // token expires within buffer → refresh

      expect(token).toBe(freshJwt);
      expect(mockFetch).toHaveBeenCalledTimes(2);
      const [refreshUrl, refreshInit] = mockFetch.mock.calls[1]!;
      expect(refreshUrl).toBe("https://dedi.example.com/dedi/token/refresh");
      const refreshBody = JSON.parse(refreshInit?.body as string);
      expect(refreshBody).toEqual({ refresh_token: "rt_1" });
    });

    it("falls back to login if refresh fails", async () => {
      const soonJwt = jwtExpiringIn(50);
      const freshJwt = jwtExpiringIn(3600);

      // Login
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      // Refresh fails
      mockFetch.mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));
      // Fallback login succeeds
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: freshJwt, refresh_token: "rt_2", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken(); // login
      const token = await tm.getToken(); // refresh fails → login again

      expect(token).toBe(freshJwt);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });

  // ── Promise coalescing ───────────────────────────────────────────

  describe("promise coalescing", () => {
    it("shares a single in-flight login across concurrent getToken calls", async () => {
      const jwt = jwtExpiringIn(3600);
      mockFetch.mockResolvedValue(
        new Response(
          JSON.stringify({ access_token: jwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      const [t1, t2, t3] = await Promise.all([tm.getToken(), tm.getToken(), tm.getToken()]);

      expect(t1).toBe(jwt);
      expect(t2).toBe(jwt);
      expect(t3).toBe(jwt);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("clears coalesced promise on failure so next call retries fresh", async () => {
      mockFetch.mockResolvedValueOnce(new Response("Server Error", { status: 500 }));
      const jwt = jwtExpiringIn(3600);
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: jwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());

      // First call fails
      await expect(tm.getToken()).rejects.toThrow();

      // Second call should retry (not use cached rejection)
      const token = await tm.getToken();
      expect(token).toBe(jwt);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  // ── Token zeroing ────────────────────────────────────────────────

  describe("token zeroing", () => {
    it("does not retain old access token after refresh", async () => {
      const oldJwt = jwtExpiringIn(50);
      const newJwt = jwtExpiringIn(3600);

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: oldJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: newJwt, refresh_token: "rt_2", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      const first = await tm.getToken();
      expect(first).toBe(oldJwt);

      const second = await tm.getToken();
      expect(second).toBe(newJwt);

      // Verify the token manager no longer holds the old token
      // (getToken should always return the new token)
      const third = await tm.getToken();
      expect(third).toBe(newJwt);
      expect(third).not.toBe(oldJwt);
    });
  });

  // ── No-logging invariant ─────────────────────────────────────────

  describe("no-logging invariant", () => {
    it("never logs passwords, API keys, or JWT tokens", async () => {
      const jwt = jwtExpiringIn(3600);
      const password = "s3cret";
      const apiKey = "dk_test_abc123";

      // Spy on all console methods
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
      const debugSpy = vi.spyOn(console, "debug").mockImplementation(() => {});

      // Bearer flow
      mockFetch.mockResolvedValue(
        new Response(
          JSON.stringify({ access_token: jwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      const bearerTm = new DeDiTokenManager(createBearerConfig());
      await bearerTm.getToken();

      // API key flow
      const apiKeyTm = new DeDiTokenManager(createApiKeyConfig());
      await apiKeyTm.getToken();

      // Check no sensitive values in any console output
      const allCalls = [
        ...logSpy.mock.calls,
        ...warnSpy.mock.calls,
        ...errorSpy.mock.calls,
        ...infoSpy.mock.calls,
        ...debugSpy.mock.calls,
      ];
      const allOutput = JSON.stringify(allCalls);

      expect(allOutput).not.toContain(password);
      expect(allOutput).not.toContain(apiKey);
      expect(allOutput).not.toContain(jwt);
      expect(allOutput).not.toContain("rt_1");

      logSpy.mockRestore();
      warnSpy.mockRestore();
      errorSpy.mockRestore();
      infoSpy.mockRestore();
      debugSpy.mockRestore();
    });
  });

  // ── Non-JSON response handling ──────────────────────────────────

  describe("non-JSON response handling", () => {
    it("throws DeDiClientError (not SyntaxError) when login returns HTML body", async () => {
      mockFetch.mockResolvedValueOnce(
        new Response("<html><body>Bad Gateway</body></html>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        }),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow("DeDi auth endpoint returned non-JSON response");
      await expect(tm.getToken.bind(tm)).rejects.not.toBeInstanceOf(SyntaxError);
    });

    it("throws DeDiClientError (not SyntaxError) when refresh returns HTML body", async () => {
      const soonJwt = jwtExpiringIn(50);

      // Login succeeds
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      // Refresh returns HTML
      mockFetch.mockResolvedValueOnce(
        new Response("<html><body>Bad Gateway</body></html>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        }),
      );

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken(); // login
      await expect(tm.getToken()).rejects.toThrow("DeDi auth endpoint returned non-JSON response");
    });

    it("throws DeDiClientError when login returns empty body", async () => {
      mockFetch.mockResolvedValueOnce(new Response("", { status: 200 }));

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow("DeDi auth endpoint returned non-JSON response");
    });
  });

  // ── decodeExp error handling ────────────────────────────────────

  describe("decodeExp error handling", () => {
    it("throws on malformed JWT (fewer than 2 parts)", async () => {
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "not-a-jwt",
            refresh_token: "rt_1",
            token_type: "bearer",
          }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow("DeDi API returned a malformed JWT");
    });

    it("throws on JWT without exp claim", async () => {
      const header = btoa(JSON.stringify({ alg: "HS256" }));
      const payload = btoa(JSON.stringify({ sub: "user" })); // no exp
      const noExpJwt = `${header}.${payload}.sig`;

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: noExpJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow("DeDi API returned a JWT without an exp claim");
    });

    it("throws on JWT with undecodable payload", async () => {
      const header = btoa(JSON.stringify({ alg: "HS256" }));
      const badJwt = `${header}.%%%not-base64%%%.sig`;

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: badJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow(
        "DeDi API returned a JWT with an undecodable payload",
      );
    });
  });

  // ── acquireToken selective catch ──────────────────────────────────

  describe("acquireToken selective catch", () => {
    it("re-throws 429 rate limit from refresh instead of falling back to login", async () => {
      const soonJwt = jwtExpiringIn(50);

      // First call: login returns soon-expiring token
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      // Second call: refresh returns 429
      mockFetch.mockResolvedValueOnce(new Response("Too Many Requests", { status: 429 }));

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken(); // login
      await expect(tm.getToken()).rejects.toThrow("DeDi token refresh failed: 429");
      // Should NOT have attempted a fallback login (only 2 fetch calls total)
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("re-throws 500 server error from refresh instead of falling back to login", async () => {
      const soonJwt = jwtExpiringIn(50);

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      mockFetch.mockResolvedValueOnce(new Response("Internal Server Error", { status: 500 }));

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken();
      await expect(tm.getToken()).rejects.toThrow("DeDi token refresh failed: 500");
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("falls back to login on 401 refresh rejection", async () => {
      const soonJwt = jwtExpiringIn(50);
      const freshJwt = jwtExpiringIn(3600);

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      mockFetch.mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: freshJwt, refresh_token: "rt_2", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken();
      const token = await tm.getToken();

      expect(token).toBe(freshJwt);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it("falls back to login on 403 refresh rejection", async () => {
      const soonJwt = jwtExpiringIn(50);
      const freshJwt = jwtExpiringIn(3600);

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      mockFetch.mockResolvedValueOnce(new Response("Forbidden", { status: 403 }));
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: freshJwt, refresh_token: "rt_2", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken();
      const token = await tm.getToken();

      expect(token).toBe(freshJwt);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });

  // ── Response validation ───────────────────────────────────────────

  describe("response shape validation", () => {
    it("throws on login response missing access_token", async () => {
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ refresh_token: "rt_1", token_type: "bearer" }), {
          status: 200,
        }),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow(
        "DeDi API returned an unexpected auth response format",
      );
    });

    it("throws on login response missing refresh_token", async () => {
      const jwt = jwtExpiringIn(3600);
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: jwt, token_type: "bearer" }), { status: 200 }),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow(
        "DeDi API returned an unexpected auth response format",
      );
    });

    it("throws on login response with non-string access_token", async () => {
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: 12345, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await expect(tm.getToken()).rejects.toThrow(
        "DeDi API returned an unexpected auth response format",
      );
    });

    it("throws on refresh response with unexpected shape", async () => {
      const soonJwt = jwtExpiringIn(50);

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: soonJwt, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      // Refresh returns invalid shape
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "unexpected" }), { status: 200 }),
      );

      const tm = new DeDiTokenManager(createBearerConfig({ auth: { refreshBufferMs: 60_000 } }));
      await tm.getToken();
      await expect(tm.getToken()).rejects.toThrow(
        "DeDi API returned an unexpected auth response format",
      );
    });
  });

  // ── Force login / refresh ────────────────────────────────────────

  describe("force login and refresh", () => {
    it("login() forces a fresh login even with a valid token", async () => {
      const jwt1 = jwtExpiringIn(3600);
      const jwt2 = jwtExpiringIn(7200);

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: jwt1, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: jwt2, refresh_token: "rt_2", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await tm.getToken();
      await tm.login();
      const token = await tm.getToken();

      expect(token).toBe(jwt2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("refresh() refreshes the current token", async () => {
      const jwt1 = jwtExpiringIn(3600);
      const jwt2 = jwtExpiringIn(7200);

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: jwt1, refresh_token: "rt_1", token_type: "bearer" }),
          { status: 200 },
        ),
      );
      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: jwt2, refresh_token: "rt_2", token_type: "bearer" }),
          { status: 200 },
        ),
      );

      const tm = new DeDiTokenManager(createBearerConfig());
      await tm.getToken();
      await tm.refresh();
      const token = await tm.getToken();

      expect(token).toBe(jwt2);
    });
  });
});
