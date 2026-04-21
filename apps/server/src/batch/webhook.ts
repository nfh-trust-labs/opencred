/**
 * Webhook delivery for batch completion notifications.
 *
 * SECURITY: The webhook payload contains only metadata (counts, status).
 * Credential content (signed VCs) is NEVER included — this prevents
 * credential exfiltration via rogue webhook URLs. See CLAUDE.md rule 7
 * for SSRF protection requirements.
 */

import { createHmac } from "node:crypto";
import { resolve as dnsResolve } from "node:dns/promises";
import { isPrivateIP } from "@opencred/shared";

export interface WebhookPayload {
  jobId: string;
  status: "completed" | "cancelled";
  total: number;
  successCount: number;
  errorCount: number;
  skippedCount: number;
}

/**
 * Deliver a webhook notification to the given URL.
 *
 * 1. Resolves the hostname and validates it is not a private IP (SSRF).
 * 2. Requires HTTPS.
 * 3. Rewrites the URL to the validated IP to prevent DNS rebinding (TOCTOU).
 * 4. Computes HMAC-SHA256 signature of the JSON body. `secret` must be a
 *    non-empty string — the caller is responsible for rejecting webhook
 *    requests that lack a configured secret (see LOW-04). Passing an empty
 *    string is treated as a programming error.
 * 5. Retries up to 3 total attempts with exponential backoff (1s, 4s).
 * 6. Any 2xx response is treated as success.
 *
 * Throws on final failure — the caller catches and logs.
 */
export async function deliverWebhook(
  url: string,
  payload: WebhookPayload,
  secret: string,
): Promise<void> {
  if (!secret) {
    // LOW-04: caller must reject webhook requests with no configured secret
    // at the route boundary. Reaching this throw means that guard was
    // bypassed — fail loudly rather than fall back to an unsigned payload.
    throw new Error(
      "deliverWebhook requires a non-empty secret; configure OPENCRED_WEBHOOK_SECRET",
    );
  }

  // SSRF: HTTPS only
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`Webhook URL must use HTTPS (got ${parsed.protocol})`);
  }

  // SSRF: resolve hostname and check all IPs are public
  const addresses = await dnsResolve(parsed.hostname);
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      throw new Error(`Webhook URL resolves to private IP: ${addr}`);
    }
  }

  // SSRF: rewrite URL to use validated IP directly, preventing DNS rebinding
  // (TOCTOU: DNS could resolve differently between our check and fetch)
  const validatedIp = addresses[0];
  const rewritten = new URL(url);
  const originalHost = rewritten.hostname;
  rewritten.hostname = validatedIp.includes(":") ? `[${validatedIp}]` : validatedIp;

  const body = JSON.stringify(payload);

  // Compute HMAC-SHA256 signature. `secret` is guaranteed non-empty by the
  // guard at the top of this function.
  const signature = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-OpenCred-Signature": signature,
    "X-OpenCred-Event": "batch.completed",
    "User-Agent": "OpenCred-Server",
    Host: originalHost,
  };

  const delays = [0, 1000, 4000]; // 3 attempts: immediate, 1s, 4s backoff
  let lastError: Error | undefined;

  for (let attempt = 0; attempt < delays.length; attempt++) {
    if (delays[attempt] > 0) {
      await new Promise((r) => setTimeout(r, delays[attempt]));
    }

    try {
      const res = await fetch(rewritten.toString(), {
        method: "POST",
        headers,
        body,
        signal: AbortSignal.timeout(10_000),
        redirect: "error",
      });

      if (res.status >= 200 && res.status < 300) {
        return; // Success
      }

      lastError = new Error(`Webhook returned HTTP ${res.status}`);
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }

  throw lastError ?? new Error("Webhook delivery failed");
}
