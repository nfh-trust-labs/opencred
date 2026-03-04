/**
 * API client for OpenCred backend endpoints.
 */

export type ProofFormatOption = "data-integrity" | "eddsa-di" | "jws" | "vc-jwt" | "sd-jwt-vc";

export interface BuildRequest {
  schema: string;
  issuer: string;
  publicKey: string;
  credentialSubject: Record<string, unknown>;
  validFrom: string;
  validUntil?: string;
  revocationRegistryUrl: string;
  keyAlgorithm?: "P-256" | "P-384" | "RSA-2048" | "RSA-3072" | "RSA-4096" | "Ed25519";
  dscCertificateChain?: string[];
  proofFormat?: ProofFormatOption;
  selectiveDisclosureClaims?: string[];
  vct?: string;
}

export interface BuildResponse {
  sessionId: string;
  unsignedCredential: Record<string, unknown>;
  dataToSign: string; // base64url
  proofConfig?: Record<string, unknown>;
  proofMechanism: ProofFormatOption;
  protectedHeader?: Record<string, unknown>;
  disclosures?: string[];
}

export interface PackageRequest {
  sessionId: string;
  signature: string; // base64url
}

export interface PackageResponse {
  credential: Record<string, unknown> | string;
  formats: {
    jsonld?: Record<string, unknown>;
  };
  dscCertificateChain?: string[];
}

interface CheckResult {
  passed: boolean;
  detail?: string;
}

export interface VerifyResponse {
  status: "VALID" | "REVOKED" | "EXPIRED" | "INVALID" | "UNRESOLVABLE" | "DELEGATION_INVALID";
  checks: {
    signature: CheckResult;
    expiry: CheckResult;
    revocation: CheckResult;
    dscChain?: CheckResult;
    delegation?: CheckResult;
  };
  delegationChain?: Array<{
    delegationId: string;
    issuer: string;
    scope: string[];
    validFrom: string;
    validUntil: string;
  }>;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    validationErrors?: Array<{ field: string; message: string }>;
  };
}

// --- Onboarding Types ---

export interface OnboardTypeARequest {
  dscChain: string;
}

export interface OnboardTypeAResponse {
  issuerId: string;
  status: string;
}

export interface OnboardDomainVerifyRequest {
  domain: string;
  method: "dns" | "http";
}

export interface OnboardDomainVerifyResponse {
  challengeId: string;
  challengeType: string;
  challengeValue: string;
  instructions: string;
}

export interface OnboardDomainConfirmResponse {
  verified: boolean;
  issuerId?: string;
  error?: string;
}

export interface OnboardBusinessVcRequest {
  businessCredential: Record<string, unknown>;
  signingPreference: "delegated" | "interface";
  publicKey?: string;
}

export interface OnboardBusinessVcResponse {
  delegationId: string;
  issuerId: string;
  capabilityToken: string;
  scope: string[];
  validFrom: string;
  validUntil: string;
}

// --- Delegated Issuance Types ---

export interface IssueDelegatedRequest {
  delegationId: string;
  schema: string;
  credentialSubject: Record<string, unknown>;
  validFrom?: string;
  validUntil?: string;
}

export interface IssueDelegatedResponse {
  credential: Record<string, unknown>;
  credentialHash: string;
}

// --- Revocation Hash Types ---

export interface RevocationHashResponse {
  hash: string;
}

export interface RevocationHashBatchResponse {
  hashes: Array<{ hash: string; index: number }>;
}

// --- Batch Issuance Types ---

export interface BatchSubmitRequest {
  schema: string;
  signingFlow: "interface" | "delegated";
  credentials: Array<Record<string, unknown>>;
  publicKey?: string;
  delegationId?: string;
}

export interface BatchSubmitResponse {
  jobId: string;
  totalCredentials: number;
  status: string;
}

export interface BatchStatusResponse {
  jobId: string;
  status: "pending" | "processing" | "awaiting_signatures" | "completed" | "failed";
  progress: number;
  totalCredentials: number;
  processedCredentials: number;
  failedCredentials: number;
}

export interface BatchResultsResponse {
  jobId: string;
  results: Array<{
    index: number;
    status: "success" | "failed";
    credential?: Record<string, unknown>;
    credentialHash?: string;
    dataToSign?: string;
    error?: string;
  }>;
}

export interface BatchSignaturesRequest {
  signatures: Array<{
    index: number;
    signature: string;
  }>;
}

export interface BatchSignaturesResponse {
  processed: number;
  results: Array<{
    index: number;
    status: "success" | "failed";
    credential?: Record<string, unknown>;
    error?: string;
  }>;
}

export class OpenCredClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token?: string,
  ) {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.token) {
      h["Authorization"] = `Bearer ${this.token}`;
    }
    return h;
  }

  private async request<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });

    const json = await res.json();

    if (!res.ok) {
      const apiErr = json as ApiError;
      throw new Error(apiErr.error?.message ?? `Request failed: ${res.status}`);
    }

    return json as T;
  }

  private async requestGet<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: this.headers(),
    });

    const json = await res.json();

    if (!res.ok) {
      const apiErr = json as ApiError;
      throw new Error(apiErr.error?.message ?? `Request failed: ${res.status}`);
    }

    return json as T;
  }

  private async requestFormData<T>(path: string, formData: FormData): Promise<T> {
    const h: Record<string, string> = {};
    if (this.token) {
      h["Authorization"] = `Bearer ${this.token}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: h,
      body: formData,
    });

    const json = await res.json();

    if (!res.ok) {
      const apiErr = json as ApiError;
      throw new Error(apiErr.error?.message ?? `Request failed: ${res.status}`);
    }

    return json as T;
  }

  // --- Existing Endpoints ---

  async buildCredential(req: BuildRequest): Promise<BuildResponse> {
    return this.request<BuildResponse>("/credentials/build", req);
  }

  async packageCredential(req: PackageRequest): Promise<PackageResponse> {
    return this.request<PackageResponse>("/credentials/package", req);
  }

  async verifyCredential(
    credential: unknown,
    dscCertificateChain?: string[],
  ): Promise<VerifyResponse> {
    return this.request<VerifyResponse>("/verify", { credential, dscCertificateChain });
  }

  // --- Onboarding ---

  async onboardTypeA(dscChain: string): Promise<OnboardTypeAResponse> {
    return this.request<OnboardTypeAResponse>("/onboarding/type-a", { dscChain });
  }

  async onboardDomainVerify(
    domain: string,
    method: "dns" | "http",
  ): Promise<OnboardDomainVerifyResponse> {
    return this.request<OnboardDomainVerifyResponse>("/onboarding/domain-verify", {
      domain,
      method,
    });
  }

  async onboardDomainConfirm(challengeId: string): Promise<OnboardDomainConfirmResponse> {
    return this.request<OnboardDomainConfirmResponse>("/onboarding/domain-verify/confirm", {
      challengeId,
    });
  }

  async onboardBusinessVc(
    businessCredential: Record<string, unknown>,
    signingPreference: "delegated" | "interface",
    publicKey?: string,
  ): Promise<OnboardBusinessVcResponse> {
    return this.request<OnboardBusinessVcResponse>("/onboarding/business-vc", {
      businessCredential,
      signingPreference,
      publicKey,
    });
  }

  // --- Delegated Issuance ---

  async issueDelegated(
    delegationId: string,
    schema: string,
    credentialSubject: Record<string, unknown>,
    validFrom?: string,
    validUntil?: string,
  ): Promise<IssueDelegatedResponse> {
    return this.request<IssueDelegatedResponse>("/credentials/issue-delegated", {
      delegationId,
      schema,
      credentialSubject,
      validFrom,
      validUntil,
    });
  }

  // --- Revocation Hash Computation ---

  async computeRevocationHash(
    credential: Record<string, unknown>,
  ): Promise<RevocationHashResponse> {
    return this.request<RevocationHashResponse>("/credentials/revocation-hash", { credential });
  }

  async computeRevocationHashBatch(
    credentials: Record<string, unknown>[],
  ): Promise<RevocationHashBatchResponse> {
    return this.request<RevocationHashBatchResponse>("/credentials/revocation-hash/batch", {
      credentials,
    });
  }

  // --- Batch Issuance ---

  async batchSubmit(req: BatchSubmitRequest): Promise<BatchSubmitResponse> {
    return this.request<BatchSubmitResponse>("/credentials/batch", req);
  }

  async batchSubmitCsv(formData: FormData): Promise<BatchSubmitResponse> {
    return this.requestFormData<BatchSubmitResponse>("/credentials/batch/csv", formData);
  }

  async batchStatus(jobId: string): Promise<BatchStatusResponse> {
    return this.requestGet<BatchStatusResponse>(`/credentials/batch/${jobId}`);
  }

  async batchResults(jobId: string): Promise<BatchResultsResponse> {
    return this.requestGet<BatchResultsResponse>(`/credentials/batch/${jobId}/results`);
  }

  async batchSignatures(
    jobId: string,
    signatures: Array<{ index: number; signature: string }>,
  ): Promise<BatchSignaturesResponse> {
    return this.request<BatchSignaturesResponse>(`/credentials/batch/${jobId}/signatures`, {
      signatures,
    });
  }
}
