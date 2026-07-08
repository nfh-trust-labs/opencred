import { OpenCredError } from "@opencred/shared";

/**
 * Error thrown by CA adapter operations.
 *
 * Extends OpenCredError to ensure error responses never leak secrets,
 * internal paths, or key material (security invariant).
 */
export class CaAdapterError extends OpenCredError {
  constructor(message: string, statusCode: number = 502) {
    super(message, "CA_ADAPTER_ERROR", statusCode);
    this.name = "CaAdapterError";
  }
}

/**
 * Error thrown when a CA adapter is not configured or unavailable.
 */
export class CaAdapterNotConfiguredError extends CaAdapterError {
  constructor(message: string = "CA adapter is not configured") {
    super(message, 501);
    this.name = "CaAdapterNotConfiguredError";
  }
}

/**
 * Error thrown when a DSC request is not found.
 */
export class CaRequestNotFoundError extends CaAdapterError {
  constructor(requestId: string) {
    super(`DSC request not found: ${requestId}`, 404);
    this.name = "CaRequestNotFoundError";
  }
}
