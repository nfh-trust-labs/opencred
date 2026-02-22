/**
 * API client for OpenCred backend endpoints.
 */

export interface BuildRequest {
  schema: string;
  issuer: string;
  publicKey: string;
  credentialSubject: Record<string, unknown>;
  validFrom: string;
  validUntil?: string;
  revocationRegistryUrl: string;
}

export interface BuildResponse {
  sessionId: string;
  unsignedCredential: Record<string, unknown>;
  dataToSign: string; // base64url
  proofConfig: Record<string, unknown>;
}

export interface PackageRequest {
  sessionId: string;
  signature: string; // base64url
}

export interface PackageResponse {
  credential: Record<string, unknown>;
  formats: {
    jsonld: Record<string, unknown>;
  };
}

interface CheckResult {
  passed: boolean;
  detail?: string;
}

export interface VerifyResponse {
  status: "VALID" | "REVOKED" | "EXPIRED" | "INVALID" | "UNRESOLVABLE";
  checks: {
    signature: CheckResult;
    expiry: CheckResult;
    revocation: CheckResult;
    dscChain?: CheckResult;
  };
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    validationErrors?: Array<{ field: string; message: string }>;
  };
}

export class OpenCredClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token?: string,
  ) {}

  private async request<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    const json = await res.json();

    if (!res.ok) {
      const apiErr = json as ApiError;
      throw new Error(apiErr.error?.message ?? `Request failed: ${res.status}`);
    }

    return json as T;
  }

  async buildCredential(req: BuildRequest): Promise<BuildResponse> {
    return this.request<BuildResponse>("/credentials/build", req);
  }

  async packageCredential(req: PackageRequest): Promise<PackageResponse> {
    return this.request<PackageResponse>("/credentials/package", req);
  }

  async verifyCredential(credential: unknown): Promise<VerifyResponse> {
    return this.request<VerifyResponse>("/verify", { credential });
  }
}
