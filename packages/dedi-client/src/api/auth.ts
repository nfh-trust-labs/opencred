import { DeDiClientError } from "@opencred/shared";
import type { DeDiLogger } from "../logger.js";
import { noopLogger } from "../logger.js";
import type { DeDiAuthTokens } from "./types.js";

export interface DeDiAuthConfig {
  baseUrl: string;
  auth:
    | { type: "api-key"; apiKey: string }
    | { type: "bearer"; email: string; password: string; refreshBufferMs?: number };
  logger?: DeDiLogger;
}

const DEFAULT_REFRESH_BUFFER_MS = 60_000;

export class DeDiTokenManager {
  private readonly config: DeDiAuthConfig;
  private readonly refreshBufferMs: number;
  private readonly logger: DeDiLogger;

  private accessToken = "";
  private refreshToken = "";
  private expiresAt = 0; // milliseconds since epoch

  private pendingPromise: Promise<string> | null = null;

  constructor(config: DeDiAuthConfig) {
    this.config = config;
    this.logger = config.logger ?? noopLogger;
    this.refreshBufferMs =
      config.auth.type === "bearer"
        ? (config.auth.refreshBufferMs ?? DEFAULT_REFRESH_BUFFER_MS)
        : DEFAULT_REFRESH_BUFFER_MS;
  }

  async getToken(): Promise<string> {
    if (this.config.auth.type === "api-key") {
      return this.config.auth.apiKey;
    }

    // If token is valid and not expiring soon, return it
    if (this.accessToken && !this.isExpiringSoon()) {
      return this.accessToken;
    }

    // Coalesce concurrent calls
    if (this.pendingPromise) {
      return this.pendingPromise;
    }

    this.pendingPromise = this.acquireToken();
    try {
      const token = await this.pendingPromise;
      return token;
    } finally {
      this.pendingPromise = null;
    }
  }

  async login(): Promise<void> {
    await this.performLogin();
  }

  async refresh(): Promise<void> {
    await this.performRefresh();
  }

  private async acquireToken(): Promise<string> {
    if (this.accessToken && this.refreshToken) {
      // Try refresh first
      try {
        await this.performRefresh();
        return this.accessToken;
      } catch (error) {
        if (
          error instanceof DeDiClientError &&
          (error.statusCode === 401 || error.statusCode === 403)
        ) {
          // Refresh token rejected — fall back to full login
        } else {
          throw error;
        }
      }
    }

    await this.performLogin();
    return this.accessToken;
  }

  private async performLogin(): Promise<void> {
    if (this.config.auth.type !== "bearer") {
      throw new DeDiClientError("Login requires bearer auth config", 400);
    }

    const url = `${this.config.baseUrl}/dedi/register`;
    const response = await globalThis.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: this.config.auth.email,
        password: this.config.auth.password,
        action: "login",
      }),
    });

    if (!response.ok) {
      this.logger.error(
        `DeDi authentication failed with status ${response.status}`,
      );
      throw new DeDiClientError(
        `DeDi authentication failed: ${response.status}`,
        response.status,
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new DeDiClientError(
        "DeDi auth endpoint returned non-JSON response",
        502,
      );
    }
    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as Record<string, unknown>).access_token !== "string" ||
      typeof (body as Record<string, unknown>).refresh_token !== "string"
    ) {
      throw new DeDiClientError(
        "DeDi API returned an unexpected auth response format",
        502,
      );
    }
    const tokens = body as DeDiAuthTokens;
    this.setTokens(tokens);
    this.logger.debug("DeDi login successful");
  }

  private async performRefresh(): Promise<void> {
    const url = `${this.config.baseUrl}/dedi/token/refresh`;
    const response = await globalThis.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: this.refreshToken }),
    });

    if (!response.ok) {
      throw new DeDiClientError(
        `DeDi token refresh failed: ${response.status}`,
        response.status,
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new DeDiClientError(
        "DeDi auth endpoint returned non-JSON response",
        502,
      );
    }
    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as Record<string, unknown>).access_token !== "string" ||
      typeof (body as Record<string, unknown>).refresh_token !== "string"
    ) {
      throw new DeDiClientError(
        "DeDi API returned an unexpected auth response format",
        502,
      );
    }
    const tokens = body as DeDiAuthTokens;
    this.setTokens(tokens);
    this.logger.debug("DeDi token refresh successful");
  }

  private setTokens(tokens: DeDiAuthTokens): void {
    // Zero old token before assigning new one
    this.accessToken = "";
    this.refreshToken = "";

    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token;
    this.expiresAt = this.decodeExp(tokens.access_token);
  }

  private isExpiringSoon(): boolean {
    return Date.now() >= this.expiresAt - this.refreshBufferMs;
  }

  private decodeExp(jwt: string): number {
    const parts = jwt.split(".");
    if (parts.length < 2) {
      throw new DeDiClientError("DeDi API returned a malformed JWT", 502);
    }
    try {
      const payload = JSON.parse(atob(parts[1]!)) as { exp?: number };
      if (payload.exp === undefined) {
        throw new DeDiClientError(
          "DeDi API returned a JWT without an exp claim",
          502,
        );
      }
      return payload.exp * 1000;
    } catch (error) {
      if (error instanceof DeDiClientError) throw error;
      throw new DeDiClientError(
        "DeDi API returned a JWT with an undecodable payload",
        502,
      );
    }
  }
}
