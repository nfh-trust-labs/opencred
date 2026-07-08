import type {
  CertificateAuthorityAdapter,
  DscRequest,
  DscRequestResult,
  DscRequestStatus,
} from "./types.js";
import { CaAdapterNotConfiguredError } from "./errors.js";

/**
 * A no-op CA adapter that always throws CaAdapterNotConfiguredError.
 *
 * This serves as:
 * - The default adapter when no CA is configured
 * - A reference implementation / template for real adapters
 * - A test double for verifying error handling paths
 *
 * No real CA implementations ship in v2 — this is the only built-in adapter.
 */
export class NoopCaAdapter implements CertificateAuthorityAdapter {
  readonly name = "No-Op";

  async requestDSC(_request: DscRequest): Promise<DscRequestResult> {
    throw new CaAdapterNotConfiguredError(
      "No Certificate Authority is configured. CA integration is an extension point — provide a CertificateAuthorityAdapter implementation to enable DSC requests.",
    );
  }

  async checkStatus(_requestId: string): Promise<DscRequestStatus> {
    throw new CaAdapterNotConfiguredError(
      "No Certificate Authority is configured. CA integration is an extension point — provide a CertificateAuthorityAdapter implementation to enable DSC status checks.",
    );
  }
}
