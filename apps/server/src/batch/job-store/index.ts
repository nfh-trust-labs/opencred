/**
 * Job-store barrel — see `./types.ts` for the design rationale.
 */

export type {
  JobMutator,
  JobRecord,
  JobStatus,
  JobStore,
  JobSummary,
} from "./types.js";
export { MemoryJobStore } from "./memory.js";
export { RedisJobStore, type RedisLike } from "./redis.js";
export { createJobStore, safeRedisInfo } from "./factory.js";
