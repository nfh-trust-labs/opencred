export class OpenCredError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number = 500) {
    super(message);
    this.name = "OpenCredError";
    this.code = code;
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
      },
    };
  }
}

export class ValidationError extends OpenCredError {
  constructor(message: string) {
    super(message, "VALIDATION_ERROR", 400);
    this.name = "ValidationError";
  }
}

export class AuthenticationError extends OpenCredError {
  constructor(message: string = "Authentication required") {
    super(message, "AUTHENTICATION_ERROR", 401);
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends OpenCredError {
  constructor(message: string = "Insufficient permissions") {
    super(message, "AUTHORIZATION_ERROR", 403);
    this.name = "AuthorizationError";
  }
}

export class NotFoundError extends OpenCredError {
  constructor(message: string = "Resource not found") {
    super(message, "NOT_FOUND", 404);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends OpenCredError {
  constructor(message: string) {
    super(message, "CONFLICT", 409);
    this.name = "ConflictError";
  }
}

export class PayloadTooLargeError extends OpenCredError {
  constructor(message: string = "Payload too large") {
    super(message, "PAYLOAD_TOO_LARGE", 413);
    this.name = "PayloadTooLargeError";
  }
}

export class RateLimitError extends OpenCredError {
  constructor(message: string = "Rate limit exceeded") {
    super(message, "RATE_LIMIT_EXCEEDED", 429);
    this.name = "RateLimitError";
  }
}

export class CryptoError extends OpenCredError {
  constructor(message: string) {
    super(message, "CRYPTO_ERROR", 500);
    this.name = "CryptoError";
  }
}

export class DIDResolutionError extends OpenCredError {
  constructor(message: string) {
    super(message, "DID_RESOLUTION_ERROR", 500);
    this.name = "DIDResolutionError";
  }
}

export class SchemaValidationError extends OpenCredError {
  public readonly validationErrors: unknown[];

  constructor(message: string, validationErrors: unknown[] = []) {
    super(message, "SCHEMA_VALIDATION_ERROR", 400);
    this.name = "SchemaValidationError";
    this.validationErrors = validationErrors;
  }

  override toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        validationErrors: this.validationErrors,
      },
    };
  }
}

export class DelegationError extends OpenCredError {
  constructor(message: string) {
    super(message, "DELEGATION_ERROR", 400);
    this.name = "DelegationError";
  }
}

export class DeDiClientError extends OpenCredError {
  constructor(message: string, statusCode: number = 502) {
    super(message, "DEDI_CLIENT_ERROR", statusCode);
    this.name = "DeDiClientError";
  }
}

export class SessionExpiredError extends OpenCredError {
  constructor(message: string = "Session expired") {
    super(message, "SESSION_EXPIRED", 410);
    this.name = "SessionExpiredError";
  }
}

export class VerificationError extends OpenCredError {
  constructor(message: string) {
    super(message, "VERIFICATION_ERROR", 400);
    this.name = "VerificationError";
  }
}

export class NotImplementedError extends OpenCredError {
  constructor(message: string = "Not implemented") {
    super(message, "NOT_IMPLEMENTED", 501);
    this.name = "NotImplementedError";
  }
}
