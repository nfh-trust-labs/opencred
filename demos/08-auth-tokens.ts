import { createCapabilityToken, validateCapabilityToken, checkScope } from "@opencred/auth";
import type { CapabilityTokenPayload } from "@opencred/auth";
import { header, success, info, warn, json, separator, step, error } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 08: Capability Tokens (Auth)");

  // Step 1: Create a shared secret for HMAC signing
  step(1, "Create a shared secret for HMAC-based tokens");
  const secret = new TextEncoder().encode("demo-secret-key-at-least-32-bytes-long!!");
  info("Using HS256 (HMAC-SHA256) for demo purposes");
  success("Secret key ready");

  separator();

  // Step 2: Create a capability token
  step(2, "Create a capability token");
  const token = await createCapabilityToken({
    subject: "did:web:university.example",
    issuer: "https://opencred.example",
    audience: "https://api.opencred.example",
    expiresInSeconds: 3600,
    scope: ["credential:issue", "credential:revoke", "delegation:create"],
    namespace: "education",
    signingKey: secret,
    algorithm: "HS256",
  });

  info(`Token (first 60 chars): ${token.slice(0, 60)}...`);
  info(`Token length: ${token.length} chars`);
  success("Capability token created");

  separator();

  // Step 3: Validate the token
  step(3, "Validate the capability token");
  const result = await validateCapabilityToken({
    token,
    verificationKey: secret,
    issuer: "https://opencred.example",
    audience: "https://api.opencred.example",
  });

  json("Validation result", result);
  if (result.valid && result.payload) {
    success("Token is valid");
    info(`Subject: ${result.payload.sub}`);
    info(`Scopes: ${result.payload.scope.join(", ")}`);
    info(`Namespace: ${result.payload.namespace}`);
    info(`Expires: ${new Date(result.payload.exp * 1000).toISOString()}`);
  }

  separator();

  // Step 4: Check specific scopes
  step(4, "Check specific scope permissions");
  if (result.valid && result.payload) {
    const payload: CapabilityTokenPayload = result.payload;

    const canIssue = checkScope(payload, "credential:issue");
    const canRevoke = checkScope(payload, "credential:revoke");
    const canDelete = checkScope(payload, "credential:delete");

    if (canIssue) success("credential:issue — GRANTED");
    if (canRevoke) success("credential:revoke — GRANTED");
    if (!canDelete) warn("credential:delete — DENIED (not in scope)");
  }

  separator();

  // Step 5: Demonstrate token rejection (wrong issuer)
  step(5, "Validate with wrong issuer — should fail");
  const wrongIssuerResult = await validateCapabilityToken({
    token,
    verificationKey: secret,
    issuer: "https://wrong-issuer.example",
  });
  if (!wrongIssuerResult.valid) {
    success(`Correctly rejected: ${wrongIssuerResult.error}`);
  }

  separator();

  // Step 6: Demonstrate expired token
  step(6, "Create and validate an already-expired token");
  const expiredToken = await createCapabilityToken({
    subject: "did:web:expired.example",
    issuer: "https://opencred.example",
    expiresInSeconds: -1,
    scope: ["credential:issue"],
    namespace: "education",
    signingKey: secret,
    algorithm: "HS256",
  });

  const expiredResult = await validateCapabilityToken({
    token: expiredToken,
    verificationKey: secret,
  });
  if (!expiredResult.valid) {
    success(`Expired token rejected: ${expiredResult.error}`);
  }

  separator();
  success("Demo 08 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
