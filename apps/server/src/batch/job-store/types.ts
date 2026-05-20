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
export type JobStatus =
  | "queued"
  | "running"
  | "completed"
  | "cancelled"
  | "failed"
  | "interrupted";

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
 */
export interface JobRecord {
  jobId: string;
  status: JobStatus;
  progress: BatchProgress | null;
  createdAt: string;
  completedAt?: string;
  webhookUrl?: string;
  ownerReplica?: string;
}

/**
 * Lightweight summary for list operations. Avoids shipping the full
 * `progress.rows[]` array (which can be 1 000+ entries) when the caller
 * only needs a directory view.
 */
export interface JobSummary {
  jobId: string;
  status: JobStatus;
  createdAt: string;
  completedAt?: string;
  total: number;
  completed: number;
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
