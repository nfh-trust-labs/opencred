/**
 * In-process job store. Preserves the pre-Tier-2 behaviour for single-
 * instance deployments where Redis would be operational overhead.
 *
 * SECURITY: This implementation is the only path that doesn't have a
 * Redis-managed TTL, so we run an internal purge sweep on every write
 * AND on a recurring timer. The sweep guarantees the
 * "session data is ephemeral" CLAUDE.md invariant even if the operator
 * never calls `list()` or `delete()` explicitly.
 */

import type { JobMutator, JobRecord, JobStatus, JobStore, JobSummary } from "./types.js";

interface MemoryEntry {
  record: JobRecord;
  /**
   * Absolute deadline (epoch ms) after which the entry is considered
   * expired. `Number.POSITIVE_INFINITY` is allowed (effectively "no TTL"),
   * but the factory always wires a finite TTL so this is just a defensive
   * default.
   */
  expiresAt: number;
}

export interface MemoryJobStoreOptions {
  /**
   * Optional clock injection for tests. Returns epoch ms. Defaults to
   * `Date.now()` in production.
   */
  now?: () => number;

  /**
   * How often the internal purge timer runs. Defaults to 60 s — frequent
   * enough that expired entries don't linger long between reads,
   * infrequent enough that a stale-but-popular jobId can't churn the
   * loop. Set to 0 to disable the timer (tests drive the purge manually).
   */
  purgeIntervalMs?: number;
}

export class MemoryJobStore implements JobStore {
  private readonly store = new Map<string, MemoryEntry>();
  private readonly now: () => number;
  private readonly purgeTimer: NodeJS.Timeout | null;

  constructor(opts: MemoryJobStoreOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    const interval = opts.purgeIntervalMs ?? 60_000;
    if (interval > 0) {
      this.purgeTimer = setInterval(() => this.purge(), interval);
      // Allow the process to exit even if this timer is still pending.
      this.purgeTimer.unref?.();
    } else {
      this.purgeTimer = null;
    }
  }

  async get(id: string): Promise<JobRecord | null> {
    const entry = this.store.get(id);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      // Lazy purge on read so callers never observe an expired record.
      this.store.delete(id);
      return null;
    }
    // Return a structural clone so callers can't mutate stored state by
    // holding the returned reference.
    return cloneRecord(entry.record);
  }

  async set(id: string, record: JobRecord, ttlSeconds: number): Promise<void> {
    this.store.set(id, {
      record: cloneRecord(record),
      expiresAt: this.now() + ttlSeconds * 1000,
    });
  }

  async update(
    id: string,
    mutator: JobMutator,
    ttlSeconds: number,
  ): Promise<JobRecord | null> {
    const current = await this.get(id);
    if (!current) return null;
    const next = mutator(current);
    if (next === null) return null;
    await this.set(id, next, ttlSeconds);
    return cloneRecord(next);
  }

  async list(filter?: { status?: JobStatus }): Promise<JobSummary[]> {
    const out: JobSummary[] = [];
    const now = this.now();
    for (const [, entry] of this.store) {
      if (entry.expiresAt <= now) continue;
      if (filter?.status && entry.record.status !== filter.status) continue;
      out.push(summaryOf(entry.record));
    }
    return out;
  }

  async delete(id: string): Promise<void> {
    this.store.delete(id);
  }

  async close(): Promise<void> {
    if (this.purgeTimer !== null) clearInterval(this.purgeTimer);
    this.store.clear();
  }

  /**
   * Synchronous purge of expired entries. Exposed publicly so the route
   * module can drive it directly (avoiding a separate timer when the
   * legacy `startBatchJobCleanup` is still wired in).
   * Returns the count of evicted entries for logging.
   */
  purge(): number {
    const now = this.now();
    let deleted = 0;
    for (const [id, entry] of this.store) {
      if (entry.expiresAt <= now) {
        this.store.delete(id);
        deleted += 1;
      }
    }
    return deleted;
  }
}

function cloneRecord(record: JobRecord): JobRecord {
  // `structuredClone` is sufficient — all fields are plain data.
  return structuredClone(record);
}

function summaryOf(record: JobRecord): JobSummary {
  const summary: JobSummary = {
    jobId: record.jobId,
    status: record.status,
    createdAt: record.createdAt,
    total: record.progress?.total ?? 0,
    completed: record.progress?.completed ?? 0,
  };
  if (record.completedAt !== undefined) summary.completedAt = record.completedAt;
  return summary;
}
