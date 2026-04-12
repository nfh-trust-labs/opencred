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
 * 3. Computes HMAC-SHA256 signature of the JSON body.
 * 4. Retries up to 3 total attempts with exponential backoff (1s, 4s).
 * 5. Any 2xx response is treated as success.
 *
 * Throws on final failure — the caller catches and logs.
 */
export async function deliverWebhook(
  url: string,
  payload: WebhookPayload,
  secret: string,
): Promise<void> {
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

  const body = JSON.stringify(payload);

  // Compute HMAC-SHA256 signature
  const signature = secret
    ? `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`
    : "sha256=unsigned";

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-OpenCred-Signature": signature,
    "X-OpenCred-Event": "batch.completed",
    "User-Agent": "OpenCred-Server",
  };

  const delays = [0, 1000, 4000]; // 3 attempts: immediate, 1s, 4s backoff
  let lastError: Error | undefined;

  for (let attempt = 0; attempt < delays.length; attempt++) {
    if (delays[attempt] > 0) {
      await new Promise((r) => setTimeout(r, delays[attempt]));
    }

    try {
      const res = await fetch(url, {
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
