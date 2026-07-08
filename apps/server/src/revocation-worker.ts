/**
 * Background revocation driver (#718 / opencred-releases#11).
 *
 * DeDi's two-step publish (`save-record-as-draft` → `publish-records`) anchors
 * to CORD, and BOTH steps can exceed the client's hard 10s per-request ceiling
 * (measured live: a fresh `save-record-as-draft` ≈ 30s; `publish-records` can
 * also exceed 10s). So a *synchronous* revoke can 504 even with the dedi-client
 * self-heal + bounded retry. The writes are eventually consistent, though — a
 * step that times out client-side still lands on CORD — so `/credentials/revoke`
 * accepts the request (202) and this worker drives the (idempotent, self-healing)
 * publish in the background until the record is confirmed LIVE via lookup.
 *
 * In-process and best-effort: a server restart loses an in-flight task, but
 * revocation is idempotent and self-healing — re-POSTing `/credentials/revoke`
 * (or the client seeing `revoked:false` on a status poll) re-drives a stranded
 * draft to LIVE.
 */

import { DeDiRecordExistsError } from "@opencred/shared";
import type { DeDiClient } from "@opencred/dedi-client";
import type { Logger } from "pino";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Hashes with a background driver already running — dedups concurrent revokes. */
const inFlight = new Set<string>();
const keyFor = (hash: string, namespace?: string): string => `${namespace ?? ""}:${hash}`;

export interface DriveOptions {
  /** Max drive attempts before giving up (default 12). */
  maxAttempts?: number;
  /** Delay between attempts in ms (default 5000). */
  delayMs?: number;
}

/** True when a background driver is already running for this hash/namespace. */
export function isRevocationInFlight(hash: string, namespace?: string): boolean {
  return inFlight.has(keyFor(hash, namespace));
}

/**
 * Drive the revocation of `hash` to LIVE in the background. The returned promise
 * resolves when the loop finishes (LIVE-confirmed or attempts exhausted) — the
 * route calls this fire-and-forget (does not await); tests await it. A second
 * call for the same hash while one is running is a no-op (resolves immediately).
 *
 * The loop is self-healing by construction: each iteration first checks whether
 * the record is already LIVE (catching a `publish-records` that landed after a
 * prior client-side timeout), then drives `publishRevocationHash` — which itself
 * does save-draft → on-409 lookup → publish-records. It never rejects.
 */
export function driveRevocationToLive(
  dediClient: DeDiClient,
  hash: string,
  namespace: string | undefined,
  reason: string | undefined,
  logger: Logger,
  opts: DriveOptions = {},
): Promise<void> {
  const key = keyFor(hash, namespace);
  if (inFlight.has(key)) return Promise.resolve();
  inFlight.add(key);

  const maxAttempts = opts.maxAttempts ?? 12;
  const delayMs = opts.delayMs ?? 5000;

  return (async () => {
    try {
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        // Already LIVE? Also catches a publish-records that landed on CORD after
        // a prior attempt's client-side timeout.
        try {
          const status = await dediClient.queryRevocationHash(hash, namespace);
          if (status.revoked) {
            logger.info({ hash, attempt }, "Background revocation confirmed LIVE");
            return;
          }
        } catch {
          // Lookup hiccup — keep driving.
        }
        // Drive the self-healing publish. Any step may time out; we retry.
        try {
          await dediClient.publishRevocationHash(hash, namespace, reason);
        } catch (err) {
          if (err instanceof DeDiRecordExistsError) {
            logger.info({ hash, attempt }, "Background revocation already in registry (LIVE)");
            return;
          }
          logger.debug(
            { hash, attempt, err: err instanceof Error ? err.message : "unknown" },
            "Background revocation attempt incomplete; retrying",
          );
        }
        if (attempt < maxAttempts) await sleep(delayMs);
      }
      logger.warn(
        { hash, maxAttempts },
        "Background revocation not confirmed LIVE; the CORD write may still settle — " +
          "re-poll revocation-status or re-POST /credentials/revoke to confirm",
      );
    } finally {
      inFlight.delete(key);
    }
  })();
}
