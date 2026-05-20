/**
 * Job store abstraction for batch jobs (Tier 2 #5 of nfh-trust-labs/opencred#446).
 *
 * Today batch jobs live in an in-process `Map<string, BatchJobEntry>` in
 * `routes/batch.ts`. That map is the single biggest blocker for horizontal
 * scale: multiple replicas can't share visibility into in-flight jobs, and
 * the unbounded growth was implicated in the RSS 2.94 GB → 4.16 GB leak
 * observed during 90 s of small batch submissions (see #446).
 *
 * This abstraction moves the *serializable* portion of a batch job (the
 * progress record) into a pluggable store. The live `BatchEngine` instance
 * — which is not JSON-serializable and is bound to the Node process that
 * received the POST — stays in-process. The result is:
 *
 *   - Replica A receives a `POST /credentials/batch`. It writes a `JobRecord`
 *     into the JobStore, then runs the engine locally. Every progress
 *     transition syncs the record back to the store.
 *   - Replica B receives a `GET /credentials/batch/:jobId` for the same job
 *     ID. It reads the record from the store and returns the most recent
 *     progress snapshot. Replica B does NOT need to know whether Replica A
 *     is still alive — the record's `status` and `progress` are the source
 *     of truth.
 *
 * Cross-replica WORK STEALING is out of scope here (that's Tier 3 #8 — an
 * external job queue with BullMQ/SQS). Execution stays pinned to the
 * receiving replica; only *visibility* is shared.
 *
 * ---------------------------------------------------------------------------
 * SECURITY (CLAUDE.md)
 * ---------------------------------------------------------------------------
 *
 *  - Job records contain credential drafts (PII-bearing). Every implementation
 *    MUST honour the `ttlSeconds` argument — entries older than the configured
 *    `OPENCRED_SESSION_TTL` (default 4 h) must not be readable. The Redis
 *    implementation relies on Redis-managed TTL via `SET ... EX`. The memory
 *    implementation runs its own purge sweep.
 *  - Private key material NEVER enters a job record. Signing happens server-
 *    side after the record is created; only signed credentials (and per-row
 *    `error` strings) are written back.
 *  - The Redis URL may carry credentials (`redis://user:pass@host:6379/0`).
 *    Implementations MUST NEVER log the full URL — only host/port or a
 *    redacted "is set" marker.
 */

import type { BatchProgress } from "../batch-engine.js";

/**
 * Canonical batch-job status. Mirrors the values emitted by
 * `GET /credentials/batch/:jobId` after the PRD §5.4.2 status-enum migration.
 *
 *  - `queued`      — accepted, engine has not yet produced any progress
 *  - `running`     — engine has completed >= 1 row, still active
 *  - `completed`   — engine finished, at least one row succeeded
 *  - `cancelled`   — engine was cancelled before completing
 *  - `failed`      — engine completed but produced 0 successes and >0 errors
 *  - `interrupted` — process received SIGTERM/SIGINT mid-batch. New status:
 *                     a downstream observer (operator, retry pipeline) can
 *                     distinguish "the host died" from "the work failed".
 */
export type JobStatus = "queued" | "running" | "completed" | "cancelled" | "failed" | "interrupted";

/**
 * Serializable representation of a single batch job.
 *
 * The original `BatchJobEntry` held a live `BatchEngine` reference; that
 * reference is intentionally NOT part of the store record (engines stay
 * in-process, the store holds only what can be JSON-encoded).
 *
 * Field semantics:
 *
 *  - `jobId`        — opaque UUID; the store key in every implementation
 *  - `status`       — canonical status enum, updated as the engine runs
 *  - `progress`     — most recent `BatchProgress` snapshot, or `null` if
 *                     the engine hasn't published a frame yet
 *  - `createdAt`    — ISO-8601 timestamp, set when the record is first
 *                     written. Used as the TTL anchor for orphaned jobs.
 *  - `completedAt`  — ISO-8601 timestamp, set when the engine settles
 *                     (success / cancel / failure / interruption)
 *  - `webhookUrl`   — optional HTTPS URL for batch-completion delivery;
 *                     never logged
 *  - `ownerReplica` — best-effort identifier (`process.pid` + hostname) of
 *                     the replica running the engine. Diagnostic only.
 *  - `lastSeenAt`   — ISO-8601 timestamp written by the owning replica every
 *                     `OPENCRED_HEARTBEAT_INTERVAL_SEC` while the engine is
 *                     running. A stale value (older than 2× the heartbeat
 *                     interval) is the signal a remote observer uses to
 *                     decide the owning replica has died mid-batch. The
 *                     observer does NOT auto-transition the record —
 *                     work-stealing is an external-queue concern (Tier 3
 *                     #8 / #583). This field only reports liveness.
 *                     Optional because pre-heartbeat records may not carry
 *                     it; readers must treat `undefined` as "no signal".
 */
export interface JobRecord {
  jobId: string;
  status: JobStatus;
  progress: BatchProgress | null;
  createdAt: string;
  completedAt?: string;
  webhookUrl?: string;
  ownerReplica?: string;
  lastSeenAt?: string;
}

/**
 * Lightweight summary for list operations. Avoids shipping the full
 * `progress.rows[]` array (which can be 1 000+ entries) when the caller
 * only needs a directory view.
 *
 * `lastSeenAt` is included so {@link findStaleRunningJobs} can decide
 * liveness from a single `list()` call without a second per-record GET.
 */
export interface JobSummary {
  jobId: string;
  status: JobStatus;
  createdAt: string;
  completedAt?: string;
  total: number;
  completed: number;
  lastSeenAt?: string;
  ownerReplica?: string;
}

/**
 * Mutator passed to {@link JobStore.update}. Must NOT mutate the input —
 * implementations may rely on the returned value to detect changes.
 * Returning `null` aborts the update without writing.
 */
export type JobMutator = (current: JobRecord) => JobRecord | null;

/**
 * Pluggable backing store for batch jobs.
 *
 * Implementations MUST be safe to call concurrently from a single Node
 * process (multiple `pMap` workers may write progress frames simultaneously).
 *
 *  - The memory implementation is safe by virtue of the single-threaded
 *    JS event loop — no two awaits land between read and write inside one
 *    method invocation.
 *  - The Redis implementation of {@link update} is last-writer-wins: it
 *    reads, applies the mutator in JS, then writes back via `SET ... EX`,
 *    retrying only on transient SET failures. Safe in practice because
 *    progress writes are monotonic per-record and pinned to the owning
 *    replica (other replicas read but do not write the same job's progress).
 *    `finalizeAllRunningJobs` interleaving on SIGTERM is benign — both
 *    writers produce the same `"interrupted"` state. If a future caller
 *    violates the single-writer invariant, switch this to WATCH/MULTI or
 *    a Lua script.
 */
export interface JobStore {
  /**
   * Fetch a single job record by id. Returns `null` if the id is unknown
   * or the entry has been purged by TTL.
   */
  get(id: string): Promise<JobRecord | null>;

  /**
   * Write the full record. Implementations MUST set the entry's TTL to
   * exactly `ttlSeconds` from now — there is no separate "extend TTL" call.
   */
  set(id: string, record: JobRecord, ttlSeconds: number): Promise<void>;

  /**
   * Atomic read-modify-write. Reads the current record (or `null` if
   * missing/expired), passes it to `mutator`, and writes the result back.
   * Returns the new record (or `null` if the mutator returned `null` /
   * the record was missing).
   *
   * `ttlSeconds` is applied on every successful write, mirroring the
   * "re-arm the clock on every progress update" semantics of the old
   * in-process Map (which never expired).
   *
   * Cross-replica safety: the Redis implementation uses optimistic
   * concurrency. If a concurrent writer changed the record between the
   * GET and the SET, the implementation MAY retry internally a small
   * number of times before giving up. Implementations MUST NOT silently
   * drop writes — a permanent failure to update is surfaced as a thrown
   * error so the caller can decide whether to fall back to memory.
   */
  update(id: string, mutator: JobMutator, ttlSeconds: number): Promise<JobRecord | null>;

  /**
   * Enumerate known job summaries. May return a "best-effort" view in
   * the Redis case (SCAN is not snapshot-consistent across cursors).
   * Diagnostic-grade only — do not rely on this for hot-path lookups.
   */
  list(filter?: { status?: JobStatus }): Promise<JobSummary[]>;

  /**
   * Delete a record. No-op if the id is unknown.
   */
  delete(id: string): Promise<void>;

  /**
   * Release any held resources (e.g. Redis socket, in-process timer).
   * Idempotent.
   */
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Stale-job detection (Tier 2 #6 of nfh-trust-labs/opencred#446)
// ---------------------------------------------------------------------------

/**
 * Options accepted by {@link findStaleRunningJobs}.
 */
export interface StaleJobDetectionOptions {
  /**
   * The owning replica refreshes `lastSeenAt` every `heartbeatIntervalSeconds`.
   * The default observer threshold treats a job as stale when its
   * `lastSeenAt` is older than `2 × heartbeatIntervalSeconds`. That window
   * is wide enough to tolerate one missed write (e.g. a slow GC pause or
   * a Redis blip) without false-positives, and tight enough that an
   * actually-dead replica is detected within ~10 s at the default 5 s
   * interval.
   *
   * Defaults to `5` (the same default as `OPENCRED_HEARTBEAT_INTERVAL_SEC`).
   */
  heartbeatIntervalSeconds?: number;

  /**
   * Override the staleness multiplier. Defaults to `2`. Larger values are
   * more forgiving; smaller values flag dead replicas faster but risk
   * marking healthy-but-slow replicas as stale.
   */
  staleMultiplier?: number;

  /**
   * Test seam for the observer's clock. Defaults to `Date.now()`.
   */
  now?: () => number;
}

/**
 * Diagnostic record returned by {@link findStaleRunningJobs}.
 *
 * The detection is observation-only: callers MUST NOT auto-transition the
 * job record on the basis of this signal. Cross-replica work-stealing is
 * a queue-engine concern (Tier 3 #8 / #583). This helper exists so an
 * operator dashboard, a Prometheus exporter, or a future cleanup job can
 * surface "the owning replica appears to have died" without conflating
 * that with the existing `"interrupted"` / `"failed"` statuses (which the
 * owning replica writes on its own way out — by definition, a dead
 * replica can't update its own record).
 */
export interface StaleJobReport {
  jobId: string;
  status: JobStatus;
  /** ms since the replica last wrote `lastSeenAt`. */
  staleForMs: number;
  ownerReplica?: string;
}

/**
 * Returns the subset of currently-running (or still-queued) jobs whose
 * `lastSeenAt` heartbeat is older than `staleMultiplier × heartbeatIntervalSeconds`.
 *
 * Behaviour:
 *  - Jobs without a `lastSeenAt` field at all are ignored. A record may
 *    legitimately lack one if it was created by an older code path or if
 *    the engine hadn't yet emitted its first heartbeat. The caller is the
 *    one who knows whether to treat "no signal" as suspicious.
 *  - Only `running` and `queued` statuses are considered — settled records
 *    (`completed` / `failed` / `cancelled` / `interrupted`) carry no
 *    liveness contract.
 *  - The owning replica's own clock writes `lastSeenAt`; the observer
 *    compares it against the observer's clock. Modest clock skew between
 *    replicas (NTP-bounded, typically < 1 s) is absorbed by the
 *    `staleMultiplier` window.
 *
 * Diagnostic-grade: backed by `store.list()`, which in the Redis
 * implementation is a SCAN — not a snapshot. Treat the result as
 * eventually-consistent.
 */
export async function findStaleRunningJobs(
  store: JobStore,
  opts: StaleJobDetectionOptions = {},
): Promise<StaleJobReport[]> {
  const heartbeatIntervalSeconds = opts.heartbeatIntervalSeconds ?? 5;
  const staleMultiplier = opts.staleMultiplier ?? 2;
  const now = opts.now ?? (() => Date.now());

  const thresholdMs = heartbeatIntervalSeconds * staleMultiplier * 1000;
  const nowMs = now();
  const out: StaleJobReport[] = [];

  // We only need `running` + `queued` summaries; ask the store for each.
  // (Two cheap calls instead of one big list-and-filter is roughly the
  // same Redis cost — SCAN sees every key either way — but it keeps the
  // payload tighter when the running set is small.)
  const candidates: JobSummary[] = [
    ...(await store.list({ status: "running" })),
    ...(await store.list({ status: "queued" })),
  ];

  for (const summary of candidates) {
    if (!summary.lastSeenAt) continue;
    const lastSeenMs = Date.parse(summary.lastSeenAt);
    if (Number.isNaN(lastSeenMs)) continue;
    const staleForMs = nowMs - lastSeenMs;
    if (staleForMs <= thresholdMs) continue;
    const report: StaleJobReport = {
      jobId: summary.jobId,
      status: summary.status,
      staleForMs,
    };
    if (summary.ownerReplica !== undefined) report.ownerReplica = summary.ownerReplica;
    out.push(report);
  }
  return out;
}
