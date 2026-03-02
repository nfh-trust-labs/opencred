import { DeDiClientError } from "@opencred/shared";
import type { DeDiAuthTokens } from "./types.js";

export interface DeDiAuthConfig {
  baseUrl: string;
  auth:
    | { type: "api-key"; apiKey: string }
    | { type: "bearer"; email: string; password: string };
  refreshBufferMs?: number;
}

const DEFAULT_REFRESH_BUFFER_MS = 60_000;

export class DeDiTokenManager {
  private readonly config: DeDiAuthConfig;
  private readonly refreshBufferMs: number;

  private accessToken = "";
  private refreshToken = "";
  private expiresAt = 0; // milliseconds since epoch

  private pendingPromise: Promise<string> | null = null;

  constructor(config: DeDiAuthConfig) {
    this.config = config;
    this.refreshBufferMs = config.refreshBufferMs ?? DEFAULT_REFRESH_BUFFER_MS;
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
      } catch {
        // Refresh failed — fall back to full login
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
      throw new DeDiClientError(
        `DeDi authentication failed: ${response.status}`,
        response.status,
      );
    }

    const tokens = (await response.json()) as DeDiAuthTokens;
    this.setTokens(tokens);
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

    const tokens = (await response.json()) as DeDiAuthTokens;
    this.setTokens(tokens);
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
    try {
      const parts = jwt.split(".");
      if (parts.length < 2) return 0;
      const payload = JSON.parse(atob(parts[1]!)) as { exp?: number };
      return (payload.exp ?? 0) * 1000; // convert seconds to ms
    } catch {
      return 0;
    }
  }
}
