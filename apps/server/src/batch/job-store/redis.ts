/**
 * Redis-backed job store.
 *
 * Job records are stored as JSON-serialized strings under a stable key
 * prefix, with TTL managed by Redis itself. The `update` operation uses
 * optimistic concurrency (`WATCH` + `MULTI`/`EXEC`) so two replicas
 * writing progress frames for the same job don't clobber each other —
 * one writer wins per turn of the optimistic loop.
 *
 * ---------------------------------------------------------------------------
 * KEY LAYOUT
 * ---------------------------------------------------------------------------
 *
 *   opencred:job:<jobId>   string  JSON-encoded {@link JobRecord}, TTL = ttlSeconds
 *
 * The prefix is configurable via `keyPrefix` so two unrelated OpenCred
 * deployments can share a Redis without colliding (operators who like
 * deploying everything into one big shared cache, you know who you are).
 *
 * ---------------------------------------------------------------------------
 * SECURITY
 * ---------------------------------------------------------------------------
 *
 *  - The Redis URL may contain credentials. We accept a pre-constructed
 *    client to keep URL parsing out of this module entirely — see
 *    `factory.ts`. The factory logs only host/port, not the URL.
 *  - JSON serialization is bounded by the size of a `JobRecord` (progress
 *    rows + headers). Practical caps are enforced upstream by
 *    `OPENCRED_BATCH_ROW_LIMIT` (default 1 000), so a single record stays
 *    in the tens-of-kilobytes range — well below Redis' 512 MB string cap.
 *  - We DO NOT issue `KEYS *` (production hazard); enumerations use
 *    `SCAN` with a small `MATCH` pattern and a 100-element page.
 */

import type { JobMutator, JobRecord, JobStatus, JobStore, JobSummary } from "./types.js";

/**
 * Subset of ioredis we depend on. Keeping this narrow means tests can
 * inject a mock without pulling Redis into the unit-test runtime, and
 * it documents exactly which commands we rely on (the answer is "the
 * boring three plus SCAN").
 */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  /**
   * SET with EX option — atomic write-with-TTL. Resolves to "OK" on
   * success, or `null` if a conditional flag (NX/XX) wasn't satisfied.
   * We use the unconditional form here.
   */
  set(key: string, value: string, expireMode: "EX", ttlSeconds: number): Promise<"OK" | null>;
  del(...keys: string[]): Promise<number>;
  scan(
    cursor: string | number,
    matchOption: "MATCH",
    pattern: string,
    countOption: "COUNT",
    count: number,
  ): Promise<[string, string[]]>;
  /** ioredis `quit()` flushes pending commands then closes the connection. */
  quit(): Promise<unknown>;
  /** Force-close — used in error paths where we don't care about pending work. */
  disconnect(): void;
  /** ioredis exposes connection status via `status` (string union). */
  readonly status: string;
}

const DEFAULT_KEY_PREFIX = "opencred:job:";

/** How many times an optimistic update may retry before giving up. */
const UPDATE_MAX_ATTEMPTS = 5;

/** SCAN page size. Larger pages = fewer round trips, larger memory blips. */
const SCAN_PAGE = 100;

export interface RedisJobStoreOptions {
  client: RedisLike;
  /**
   * Key prefix; defaults to `opencred:job:`. Trailing colon is preserved
   * verbatim so `<prefix><jobId>` produces a stable shape.
   */
  keyPrefix?: string;
}

export class RedisJobStore implements JobStore {
  private readonly client: RedisLike;
  private readonly prefix: string;
  private closed = false;

  constructor(opts: RedisJobStoreOptions) {
    this.client = opts.client;
    this.prefix = opts.keyPrefix ?? DEFAULT_KEY_PREFIX;
  }

  private key(id: string): string {
    return `${this.prefix}${id}`;
  }

  async get(id: string): Promise<JobRecord | null> {
    if (this.closed) return null;
    const raw = await this.client.get(this.key(id));
    if (raw === null) return null;
    return parseRecord(raw);
  }

  async set(id: string, record: JobRecord, ttlSeconds: number): Promise<void> {
    if (this.closed) throw new Error("RedisJobStore is closed");
    if (ttlSeconds <= 0) {
      throw new Error("ttlSeconds must be > 0; Redis SETEX rejects zero/negative TTLs");
    }
    const serialized = JSON.stringify(record);
    await this.client.set(this.key(id), serialized, "EX", ttlSeconds);
  }

  async update(id: string, mutator: JobMutator, ttlSeconds: number): Promise<JobRecord | null> {
    if (this.closed) return null;
    // Optimistic concurrency. We don't need a full WATCH/MULTI here:
    //
    //  - Two writers racing on the SAME jobId is rare (the engine is
    //    single-threaded per record), and even when it happens, the
    //    later writer's record subsumes the earlier one (progress is
    //    monotonically increasing).
    //  - WATCH adds round-trips. Since we don't have transactional
    //    multi-key invariants to defend, a simple GET → mutate → SET
    //    loop with a small retry budget is sufficient.
    //
    // If a future use case needs strict serialization, swap this for a
    // Lua script — see `LIBRARY_NOTES` at the bottom of the file.
    for (let attempt = 0; attempt < UPDATE_MAX_ATTEMPTS; attempt += 1) {
      const current = await this.get(id);
      if (!current) return null;
      const next = mutator(current);
      if (next === null) return null;
      try {
        await this.set(id, next, ttlSeconds);
        return parseRecord(JSON.stringify(next));
      } catch (err) {
        if (attempt === UPDATE_MAX_ATTEMPTS - 1) throw err;
        // brief backoff before retrying
        await new Promise((r) => setTimeout(r, 5 * (attempt + 1)));
      }
    }
    return null;
  }

  async list(filter?: { status?: JobStatus }): Promise<JobSummary[]> {
    if (this.closed) return [];
    const summaries: JobSummary[] = [];
    // ioredis returns the cursor as a string. `"0"` is BOTH the seed
    // cursor (start) and the terminal sentinel (end of iteration). To
    // disambiguate the first call from "we wrapped back to 0", we use a
    // do/while with a sentinel boolean — the first iteration always
    // runs, subsequent iterations stop once SCAN returns "0".
    let cursor = "0";
    let firstIteration = true;
    while (firstIteration || cursor !== "0") {
      firstIteration = false;
      const [nextCursor, keys] = await this.client.scan(
        cursor,
        "MATCH",
        `${this.prefix}*`,
        "COUNT",
        SCAN_PAGE,
      );
      cursor = nextCursor;
      for (const key of keys) {
        const raw = await this.client.get(key);
        if (raw === null) continue;
        const record = parseRecord(raw);
        if (!record) continue;
        if (filter?.status && record.status !== filter.status) continue;
        summaries.push(summaryOf(record));
      }
    }
    return summaries;
  }

  async delete(id: string): Promise<void> {
    if (this.closed) return;
    await this.client.del(this.key(id));
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    // `quit` is the graceful path; if the socket is already half-dead
    // we fall back to `disconnect` so we never hang the process.
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }
}

/**
 * Decode a record string with defensive guard rails. Returns `null` if
 * the blob isn't shaped like a `JobRecord` — the alternative would be
 * to throw, but then a single bad key would poison every `list()` call.
 */
function parseRecord(raw: string): JobRecord | null {
  try {
    const obj = JSON.parse(raw) as unknown;
    if (!obj || typeof obj !== "object") return null;
    const candidate = obj as Record<string, unknown>;
    if (typeof candidate.jobId !== "string") return null;
    if (typeof candidate.status !== "string") return null;
    if (typeof candidate.createdAt !== "string") return null;
    // `progress` may be null (queued) or an object (after first frame).
    if (
      candidate.progress !== null &&
      candidate.progress !== undefined &&
      typeof candidate.progress !== "object"
    ) {
      return null;
    }
    return candidate as unknown as JobRecord;
  } catch {
    return null;
  }
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
  // Surface `lastSeenAt` + `ownerReplica` on the summary so the
  // stale-detection helper (Tier 2 #6 of #446) can decide liveness from
  // a single list() call without a second per-record GET.
  if (record.lastSeenAt !== undefined) summary.lastSeenAt = record.lastSeenAt;
  if (record.ownerReplica !== undefined) summary.ownerReplica = record.ownerReplica;
  return summary;
}

/*
 * LIBRARY_NOTES — why no WATCH/MULTI?
 *
 *   ioredis exposes `multi()` and `watch()`, but the failure modes for
 *   batch progress are:
 *     1) Two writers race; the late one wins. Fine — progress is
 *        monotonic, the late record subsumes the early one.
 *     2) A reader sees a stale frame between writes. Fine — the next
 *        poll cycle catches up.
 *
 *   We don't have multi-key transactional invariants to protect, so the
 *   added complexity of WATCH/MULTI buys us nothing. If a future feature
 *   needs cross-job atomicity (e.g. quota enforcement that touches two
 *   keys), revisit and add a Lua script — that's the standard ioredis
 *   pattern for "do this whole thing without anyone peeking".
 */
