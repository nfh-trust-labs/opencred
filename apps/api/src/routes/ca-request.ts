import { Hono } from "hono";
import type { Context } from "hono";
import { z } from "zod";
import { ValidationError, NotImplementedError } from "@opencred/shared";

export interface DscRequestParams { csr: string; countryCode: string; organisation: string; commonName: string; keyAlgorithm?: string; validityDays?: number; }
export interface DscRequestResult { requestId: string; status: DscRequestStatusCode; estimatedCompletion?: string; }
export type DscRequestStatusCode = "pending" | "approved" | "rejected" | "issued";
export interface DscRequestStatus { requestId: string; status: DscRequestStatusCode; certificateChain?: string[]; rejectionReason?: string; updatedAt?: string; }
export interface CertificateAuthorityAdapter { requestDSC(params: DscRequestParams): Promise<DscRequestResult>; checkStatus(requestId: string): Promise<DscRequestStatus>; }

const caRequestSchema = z.object({
  csr: z.string().min(1, "csr must be a non-empty PEM string"),
  countryCode: z.string().length(2, "countryCode must be a 2-letter ISO 3166-1 code").regex(/^[A-Z]{2}$/, "countryCode must be uppercase letters"),
  organisation: z.string().min(1, "organisation must not be empty"),
  commonName: z.string().min(1, "commonName must not be empty"),
  keyAlgorithm: z.string().optional(),
  validityDays: z.number().int().positive().optional(),
});

const caStatusSchema = z.object({ requestId: z.string().min(1, "requestId must not be empty") });

export interface CaRequestRoutesDeps { caAdapter?: CertificateAuthorityAdapter; }

export function createCaRequestRoutes(deps: CaRequestRoutesDeps) {
  const { caAdapter } = deps;
  const caRequest = new Hono();

  const handleCaRequest = async (c: Context) => {
    if (!caAdapter) throw new NotImplementedError("Certificate Authority adapter is not configured. Type C onboarding requires a CA adapter to be registered at startup.");
    const rawBody = await c.req.json();
    const parsed = caRequestSchema.safeParse(rawBody);
    if (!parsed.success) { const firstError = parsed.error.issues[0]; throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`); }
    const result = await caAdapter.requestDSC(parsed.data);
    return c.json({ requestId: result.requestId, status: result.status, ...(result.estimatedCompletion && { estimatedCompletion: result.estimatedCompletion }) }, 202);
  };

  const handleCaStatus = async (c: Context) => {
    if (!caAdapter) throw new NotImplementedError("Certificate Authority adapter is not configured. Type C onboarding requires a CA adapter to be registered at startup.");
    const rawBody = await c.req.json();
    const parsed = caStatusSchema.safeParse(rawBody);
    if (!parsed.success) { const firstError = parsed.error.issues[0]; throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`); }
    const status = await caAdapter.checkStatus(parsed.data.requestId);
    return c.json({ requestId: status.requestId, status: status.status, ...(status.certificateChain && { certificateChain: status.certificateChain }), ...(status.rejectionReason && { rejectionReason: status.rejectionReason }), ...(status.updatedAt && { updatedAt: status.updatedAt }) });
  };

  caRequest.post("/ca-request", handleCaRequest);
  caRequest.post("/ca-request/status", handleCaStatus);
  caRequest.post("/type-c", handleCaRequest);
  caRequest.post("/type-c/status", handleCaStatus);

  return caRequest;
}
