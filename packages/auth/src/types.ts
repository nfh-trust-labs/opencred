import type { KeyLike } from "jose";

export interface CapabilityTokenPayload {
  sub: string;
  iss: string;
  aud?: string;
  exp: number;
  iat: number;
  jti: string;
  scope: string[];
  namespace: string;
}

export interface CapabilityTokenOptions {
  subject: string;
  issuer: string;
  audience?: string;
  expiresInSeconds: number;
  scope: string[];
  namespace: string;
  signingKey: Uint8Array | KeyLike;
  algorithm?: string;
}

export interface TokenValidationOptions {
  token: string;
  verificationKey: Uint8Array | KeyLike;
  issuer?: string;
  audience?: string;
  algorithms?: string[];
}

export interface TokenValidationResult {
  valid: boolean;
  payload?: CapabilityTokenPayload;
  error?: string;
}
