/**
 * Webhook delivery queue (Tier 3 #8 of #446).
 *
 * Today the in-process `webhook.ts` ships a synchronous
 * `deliverWebhook()` helper that the inline-mode batch path calls
 * after the engine settles. That stays — single-instance deployments
 * don't need a separate worker fleet.
 *
 * When `OPENCRED_BATCH_DISPATCH=queue` the model changes: webhook
 * delivery moves into its own BullMQ queue with retry + DLQ. The
 * BATCH worker process enqueues the delivery (see `worker.ts`); a
 * webhook consumer (also in `worker.ts`) handles signing + HTTP.
 *
 * This module is the thin producer-side abstraction for code that
 * needs to enqueue a webhook delivery from somewhere OTHER than the
 * batch worker — e.g., a future route that delivers ad-hoc webhooks
 * outside the batch pipeline. It is NOT used by the inline path
 * (which calls `deliverWebhook` directly) or by the batch worker
 * (which holds its own BullMQ Queue handle for the same purpose).
 *
 * Kept as a separate module so the inline `webhook.ts` stays free of
 * BullMQ imports — operators running inline mode never load the
 * queue stack.
 *
 * ---------------------------------------------------------------------------
 * SECURITY
 * ---------------------------------------------------------------------------
 *
 *  - The webhook signing secret is NEVER part of the queue payload. The
 *    consumer (`worker.ts`) reads `OPENCRED_WEBHOOK_SECRET` from its
 *    own env and signs locally.
 *  - This module is the ONLY way the API process should enqueue webhook
 *    work — `webhook.ts` does the in-process delivery, this module
 *    does the queue enqueue. Keep them disjoint.
 */

import type { WebhookDeliveryJob } from "@opencred/shared";

/**
 * Producer-side surface for the webhook queue. Mirrors the producer
 * shape of `BatchQueue` in `queue.ts`.
 */
export interface WebhookQueueClient {
  /** Add a webhook delivery job. See `worker.ts` for retry semantics. */
  add(payload: WebhookDeliveryJob): Promise<void>;
  /** Release the underlying connection. Idempotent. */
  close(): Promise<void>;
}
