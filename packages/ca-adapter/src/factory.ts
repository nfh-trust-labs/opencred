import type { CaAdapterConfig, CertificateAuthorityAdapter } from "./types.js";
import { CaAdapterError } from "./errors.js";
import { NoopCaAdapter } from "./noop-adapter.js";

/**
 * Create a CertificateAuthorityAdapter from configuration.
 *
 * Currently only the "noop" adapter type is supported. Third-party or
 * custom adapters should implement CertificateAuthorityAdapter directly
 * and be provided to the system without going through this factory.
 *
 * @param config - Adapter configuration specifying the type
 * @returns A configured CertificateAuthorityAdapter instance
 * @throws CaAdapterError if the adapter type is unknown
 */
export function createCaAdapter(config?: CaAdapterConfig): CertificateAuthorityAdapter {
  if (!config || config.type === "noop") {
    return new NoopCaAdapter();
  }

  throw new CaAdapterError(
    `Unknown CA adapter type: "${config.type}". Only "noop" is built in. Provide a custom CertificateAuthorityAdapter implementation for other CA integrations.`,
    400,
  );
}
