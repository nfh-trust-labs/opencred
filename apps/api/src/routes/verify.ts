import { Hono } from "hono";
import { z } from "zod";
import { verifyCredential, type VerificationResultCode } from "@opencred/verification";
import { DIDKeyResolver, DIDJwkResolver } from "@opencred/did";
import type { DIDResolver, DIDResolutionResult } from "@opencred/did";
import type { DeDiClient } from "@opencred/dedi-client";
import { ValidationError } from "@opencred/shared";
import { validateDscChain, type TrustStore, type DscChainCheck } from "../dsc-chain.js";

// --- Zod schema for request validation ---

const verifyRequestSchema = z.object({
  credential: z.union([z.record(z.unknown()), z.string().min(1)], {
    message: "credential must be an object or non-empty string",
  }),
  dscCertificateChain: z.array(z.string().min(1)).optional(),
});

// --- Response types ---

interface CheckResult {
  passed: boolean;
  detail?: string;
}

interface VerifyResponse {
  status: VerificationResultCode;
  checks: {
    signature: CheckResult;
    expiry: CheckResult;
    revocation: CheckResult;
    dscChain?: CheckResult;
  };
}

// --- Factory ---

export interface VerifyRoutesDeps {
  trustStore?: TrustStore;
  dediClient?: DeDiClient;
}

/**
 * Composite DID resolver that delegates to did:key or did:jwk resolvers
 * based on the DID method prefix.
 */
class CompositeDidResolver implements DIDResolver {
  private keyResolver = new DIDKeyResolver();
  private jwkResolver = new DIDJwkResolver();

  async resolve(did: string): Promise<DIDResolutionResult> {
    if (did.startsWith("did:jwk:")) {
      return this.jwkResolver.resolve(did);
    }
    return this.keyResolver.resolve(did);
  }
}

export function createVerifyRoutes(deps: VerifyRoutesDeps = {}) {
  const { trustStore, dediClient } = deps;
  const didResolver = new CompositeDidResolver();
  const verify = new Hono();

  verify.post("/", async (c) => {
    const rawBody = await c.req.json();
    const parsed = verifyRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { credential, dscCertificateChain } = parsed.data;

    // Run credential verification (signature + dates + revocation)
    const result = await verifyCredential(credential, {
      didResolver,
      dediClient,
    });

    // Map verification checks to API response format
    const signatureCheck = result.checks.find((ch) => ch.name === "signature");
    const dateCheck = result.checks.find((ch) => ch.name === "date");
    const revocationCheck = result.checks.find(
      (ch) => ch.name === "revocation" || ch.name === "bitstringStatus",
    );

    const checks: VerifyResponse["checks"] = {
      signature: signatureCheck
        ? {
            passed: signatureCheck.passed,
            ...(signatureCheck.detail && { detail: signatureCheck.detail }),
          }
        : { passed: false, detail: "Signature check was not performed" },
      expiry: dateCheck
        ? { passed: dateCheck.passed, ...(dateCheck.detail && { detail: dateCheck.detail }) }
        : { passed: false, detail: "Expiry check was not performed" },
      revocation: revocationCheck
        ? {
            passed: revocationCheck.passed,
            ...(revocationCheck.detail && { detail: revocationCheck.detail }),
          }
        : { passed: false, detail: "Revocation check was not performed" },
    };

    // DSC/CSCA chain validation (optional)
    let dscChainResult: DscChainCheck | undefined;
    if (dscCertificateChain && dscCertificateChain.length > 0) {
      if (!trustStore || trustStore.size === 0) {
        dscChainResult = {
          passed: false,
          detail: "No trusted CSCA certificates loaded",
        };
      } else {
        dscChainResult = validateDscChain(dscCertificateChain, trustStore);
      }
      checks.dscChain = dscChainResult;
    }

    // Determine overall status
    let status: VerificationResultCode = result.code;
    if (status === "VALID" && dscChainResult && !dscChainResult.passed) {
      status = "INVALID";
    }

    return c.json({ status, checks } satisfies VerifyResponse);
  });

  return verify;
}
