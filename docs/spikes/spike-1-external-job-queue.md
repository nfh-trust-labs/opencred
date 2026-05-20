# Spike 1 — External Job Queue (BullMQ vs SQS)

**Status:** Recommendation
**Parent issue:** [#446 — Scale & memory roadmap](https://github.com/nfh-trust-labs/opencred/issues/446) (Tier 3 item #8)
**Spike protocol:** `CLAUDE.md` → "Spike Protocol"
**Author:** Spike branch `spike/external-job-queue`
**Date:** 2026-05-20

## TL;DR

**Recommendation: BullMQ + Redis.** OpenCred is shipped as a self-deployed Docker image, not a hosted SaaS — adopting AWS SQS would force every operator onto AWS, even those running on Cloud Run, on-prem, or in a private cluster. BullMQ ships as a regular npm dependency, reuses the Redis we already require for the `JobStore` (#575), and works on any Redis-compatible backend (AWS ElastiCache, GCP Memorystore, Azure Cache, plain Redis Sentinel, Valkey, KeyDB, Upstash). This spike defines the message shape, the worker process, the migration path, and the operational guard-rails. **No production wiring lands in this PR** — that is the impl PR's job.

This doc fulfils acceptance criteria items 1–8 from the spike brief.

---

## 1. BullMQ vs SQS — comparative analysis

| Dimension | **BullMQ + Redis** | **AWS SQS** |
| --- | --- | --- |
| Deployment portability | Any Redis (managed or self-hosted) on any cloud, on-prem, k8s, Docker Compose | AWS only (or AWS-compatible IAM stack) |
| Coupling to existing infra | **Zero new infra** — reuses `OPENCRED_REDIS_URL` from #575 | New AWS account, IAM policies, VPC NAT for non-AWS deployments |
| Worker model | Node consumer pool, in-process via `Worker` class, pulls jobs via BRPOPLPUSH | HTTP long-poll (`ReceiveMessage`), 20 s max per poll cycle |
| Retry / DLQ | First-class (`attempts`, `backoff`, `failed` set, `removeOnFail`) | First-class (`maxReceiveCount`, redrive policy → DLQ) |
| Delayed jobs | Native (`delay` option) | Native (`DelaySeconds`, FIFO timer queues) |
| Priorities | Native (per-job `priority`) | FIFO queues = strict ordering; no priorities |
| Concurrency control | Built-in (`concurrency` per worker) | Caller-managed (poll N at a time) |
| Visibility into in-flight work | `getJobs`, `getJobCounts`, BullMQ UI (`bull-board`) | CloudWatch metrics, no built-in browser |
| Throughput ceiling | Bound by Redis throughput (≥10k jobs/s on a small node) | Effectively unbounded (managed AWS) |
| Cost (small deployment) | Same Redis we already pay for | $0.40 per million msgs after free tier; minimal at our volume but a new line item |
| Operational primitives we'd lose by going SQS | None | Job-level priorities; in-process worker scaling primitives |
| Onboarding friction | `npm i bullmq` + worker entry point | AWS account, IAM, VPC config, possibly Terraform |
| Audit / replay | Job history retained in Redis with `removeOnComplete: { age }` | DLQ + CloudWatch only |

**Conclusion.** SQS is an excellent fit for hosted-SaaS architectures with a fixed AWS footprint. OpenCred is the opposite — `apps/server` is consumed as a Docker image deployed by the issuer into *their* environment. Forcing them onto AWS-only infra contradicts the project's deployment story. BullMQ also lets us avoid a second backing store: the same Redis configured for `JobStore` (#575) becomes the queue broker. Operationally, we get a single piece of infra to harden, monitor, and TLS-terminate.

**When would we revisit SQS?** If OpenCred ever offers a managed service tier on AWS, the managed tier can layer SQS atop a separate worker pool without affecting the self-deployed Docker image. The `BatchJob` message contract (§ 4) is provider-agnostic by design.

---

## 2. API-side changes — what the route does after migration

Today `POST /credentials/batch` (`apps/server/src/routes/batch.ts:161`) does all of:

1. Parse + validate CSV up-front.
2. Construct an in-process `StreamingBatchEngine`.
3. Call `engine.start()` in the background (`void engine.start().then(...)`).
4. Write progress frames into `JobStore` as the engine runs.
5. Deliver webhook on completion.

**After the queue migration, the route is intentionally thin:**

1. Parse + validate CSV up-front (unchanged — this still produces the 202 response shape).
2. Persist the parsed rows + signing context as a `BatchJob` message.
3. Enqueue the `BatchJob` onto the `batch` queue.
4. Write the initial `JobRecord` with `status: "queued"` (unchanged).
5. Return `202 { jobId, status: "queued", ... }` — exact same response shape, no API contract change.

The `localEngines` `Map` in `routes/batch.ts` goes away in queue mode. Engines run inside the worker process, not the API process. `GET /credentials/batch/:jobId` becomes pure `jobStore.get(jobId)` since there is no local engine to consult on the API process.

**The `JobStore` from #575 is unchanged.** Queue is for *dispatch*, store is for *status*. They are separate concerns and the queue does not replace the store.

---

## 3. Worker process design

New entry point: `apps/server/src/worker.ts`. Sketch:

```ts
// apps/server/src/worker.ts — NOT WIRED IN THIS SPIKE PR.
import { Worker, type Job } from "bullmq";
import { loadConfig } from "./config.js";
import { loadSigningKey, getActiveSigner } from "./signing/key-manager.js";
import { createSignerFromConfig } from "./signing/cloud-hsm/factory.js";
import { createJobStore } from "./batch/job-store/factory.js";
import { createStreamingBatchEngine } from "./batch/batch-engine.js";
import { deliverWebhook } from "./batch/webhook.js";
import { createLogger } from "./logger.js";
import type { BatchJob } from "@opencred/shared";

const config = loadConfig();
const logger = createLogger();
const jobStore = await createJobStore(config, logger);

// Same signing-key loading as the API process.
const cloudSigner = await createSignerFromConfig();
if (cloudSigner) { /* setActiveSigner */ } else { loadSigningKey(); }
const signer = getActiveSigner()!;

const worker = new Worker<BatchJob>(
  "batch",
  async (job: Job<BatchJob>) => {
    const engine = createStreamingBatchEngine(signer, job.data.config, {
      source: arrayToAsyncIterable(job.data.rows),
    });
    const onProgress = (frame) =>
      jobStore.update(job.data.jobId, c => ({ ...c, progress: frame, status: deriveStatus(frame) }), config.OPENCRED_SESSION_TTL);
    engine.onProgress(onProgress);   // hook to be added to engine

    const final = await engine.start();
    await jobStore.update(job.data.jobId, c => ({ ...c, progress: final, status: deriveStatus(final), completedAt: new Date().toISOString() }), config.OPENCRED_SESSION_TTL);

    // Enqueue webhook delivery to its own queue (see § 4).
    if (job.data.webhookUrl) {
      await webhookQueue.add("webhook", { jobId: job.data.jobId, webhookUrl: job.data.webhookUrl, payload: { … } });
    }
  },
  {
    connection: { url: config.OPENCRED_REDIS_URL! },
    concurrency: config.OPENCRED_WORKER_CONCURRENCY,
  },
);

worker.on("failed", (job, err) => logger.warn({ jobId: job?.data.jobId, err }, "batch job failed"));
worker.on("error", (err) => logger.warn({ err }, "worker error"));

// SIGTERM graceful drain — see § 7.
process.on("SIGTERM", async () => {
  logger.info("SIGTERM — stop consuming, finish current job");
  await worker.close();   // stops new jobs; current job runs to completion
  await jobStore.close();
  process.exit(0);
});
```

**Properties:**

* Reuses *every* existing module — config, logger, signer factories, engine, webhook delivery, store. No new business logic.
* Same signing-key loading code path. **Critical security invariant:** the worker container runs in the same trust boundary as the API container — both load the same private key from the same source (file, Cloud HSM, etc.). CLAUDE.md rule 1 ("never touch issuer private keys") is unchanged: keys never enter a request, never enter a queue message, never leave the container. The queue message carries only public credential data + the configured `issuerDid`.
* Worker is a separate Node process. In Docker, this is a second container in the same Compose / k8s deployment. In Cloud Run, it's a second service with the same image (different entry point).

**Engine change required (small):** the engine currently keeps progress internal and lets `routes/batch.ts` poll via `engine.getProgress()`. To run cross-process, the worker needs to *push* frames to the store as they arrive. Add an `onProgress(cb)` hook to the engine. Throttle pushes to once per ~500 ms to avoid hammering Redis on fast batches. Tracked as a follow-up sub-task in the impl PR.

---

## 4. Webhook delivery — separate queue

Today `deliverWebhook` runs synchronously after the engine settles (`routes/batch.ts:348`). Failures are logged and dropped — the retry policy is built into the function itself (3 attempts, exponential backoff). This is fine for single-instance, but in the queue model it ties webhook retries to worker liveness.

**After migration:** a second queue called `webhook` (separate from `batch`). The batch worker enqueues a `WebhookDeliveryJob` on completion; a `webhook` worker consumes it.

```ts
// apps/server/src/webhook-worker.ts — sketch
new Worker<WebhookDeliveryJob>("webhook", async (job) => {
  await deliverWebhook(job.data.webhookUrl, job.data.payload, config.OPENCRED_WEBHOOK_SECRET!);
}, {
  connection: { url: config.OPENCRED_REDIS_URL! },
  concurrency: config.OPENCRED_WEBHOOK_WORKER_CONCURRENCY,
});
```

BullMQ configuration on enqueue:

```ts
webhookQueue.add("webhook", payload, {
  attempts: 5,
  backoff: { type: "exponential", delay: 2000 },   // 2s, 4s, 8s, 16s, 32s
  removeOnComplete: { age: 3600 },                  // 1 h history for debug
  removeOnFail: false,                               // DLQ retention — operator inspects
});
```

This addresses **API-007** ("webhook retry is in-process, dies with the replica") from #446 directly. A worker can be re-deployed, scaled out, or paused independently of the batch pipeline. Failed webhooks land in BullMQ's `failed` set (the durable DLQ) where they remain until manually inspected or redriven.

**Webhook secret invariant unchanged.** The worker reads `OPENCRED_WEBHOOK_SECRET` from its own env; the secret never enters the queue payload. Caller (`routes/batch.ts`) still rejects requests at LOW-04 gate when a `webhookUrl` is supplied without a configured secret.

---

## 5. Failure domains

| Failure | Today (in-process) | After queue migration |
| --- | --- | --- |
| API replica OOM mid-batch | Job marked `interrupted` via SIGTERM handler; client must re-submit | Job stays `running` in queue; *worker* picks it up. API process is no longer responsible for in-flight work. |
| Worker crash mid-batch | n/a | BullMQ marks stalled jobs after `lockDuration` (default 30 s) and re-queues. Engine restarts from row 0 — see § 8 limitation. |
| Worker pool exhausted | n/a | Jobs back up in queue; `queueDepth` metric (§ 7) alerts operators. API still accepts POSTs (returns `queued`). |
| Webhook receiver down | All 3 retries burn within ~5 s, job marked `completed` regardless | Webhook job retries up to 5× over ~62 s, then lands in DLQ for manual redrive. Batch is unaffected. |
| Redis down | `JobStore` writes fail; route still returns 202; engine runs but progress writes log warnings | Queue enqueue fails. API returns 503. Existing in-flight jobs (running in workers) lose progress visibility until Redis recovers. |
| Slow signing key (Cloud HSM throttle) | Bottlenecks the API event loop, every request gets slower | Bottleneck is contained to worker pool. API stays responsive — `POST /credentials/batch` returns immediately with `jobId`. |

**Key win:** API failures and worker failures become independent. The API can be auto-scaled by request rate; the worker pool can be auto-scaled by `queueDepth`. They are no longer the same process.

---

## 6. Migration story

This is the part most likely to break existing deployments, so it gets explicit handling.

**Feature flag:** `OPENCRED_BATCH_DISPATCH=inline|queue`, defaulting to **`inline`**. Inline mode is bit-identical to today's behaviour — same code path, no queue. `queue` opts an operator into the new pipeline.

```ts
// apps/server/src/config.ts — addition
OPENCRED_BATCH_DISPATCH: z.enum(["inline", "queue"]).default("inline"),
OPENCRED_WORKER_CONCURRENCY: z.coerce.number().int().min(1).default(4),
OPENCRED_WEBHOOK_WORKER_CONCURRENCY: z.coerce.number().int().min(1).default(8),
```

Cross-field validation (fail-closed):

* `OPENCRED_BATCH_DISPATCH=queue` ⇒ `OPENCRED_REDIS_URL` must be set (same rule as `OPENCRED_JOB_STORE=redis`).
* `OPENCRED_BATCH_DISPATCH=queue` ⇒ recommend `OPENCRED_JOB_STORE=redis` (warn loudly otherwise — memory store + queue is technically valid for a single-API + single-worker deployment but is a footgun).

**Rollout plan:**

1. **Default `inline`.** No existing deployment changes anything; behaviour is identical to today. Spike doc + scaffolding land first (this PR).
2. **Opt-in `queue` for new deployments.** Impl PR ships the worker, both flag values are usable, no in-place migration required.
3. **`queue` becomes recommended in docs** once we've burned-in a real multi-replica deployment.
4. **`inline` deprecated** (not removed) after a release cycle. Single-instance operators keep `inline` indefinitely — it's strictly simpler.
5. **`inline` removal** is a separate decision and explicitly out of scope here.

**Docker / Compose impact (impl PR concerns):**

* `docker-compose.yml` adds a `worker` service from the same image with `command: ["node", "dist/worker.js"]`.
* Helm chart / Cloud Run service definition adds a worker deployment with horizontal-pod-autoscaler keyed on a `queueDepth` Prometheus metric.

---

## 7. Operational concerns

### Monitoring

Add Prometheus gauges (impl PR):

```
opencred_batch_queue_depth     gauge  current jobs in "batch" queue (waiting + delayed)
opencred_batch_queue_active    gauge  jobs currently being processed by workers
opencred_batch_queue_failed    gauge  jobs in DLQ
opencred_webhook_queue_depth   gauge  same set, for webhook queue
opencred_webhook_queue_failed  gauge
```

BullMQ exposes `getJobCounts({ states })` — a 5-second sampler is enough, since these gauges drive HPA decisions, not per-request alerting.

### Graceful drain

BullMQ's `worker.close()` is the entire story. It:

1. Stops fetching new jobs from the queue.
2. Lets the current job's promise resolve naturally.
3. Releases the job's lock so another worker (or the next deployment) can pick it up if it didn't finish.

The worker process should respond to SIGTERM by calling `worker.close()`, then closing `jobStore`, then `process.exit(0)`. **Important:** the API process's `finalizeAllRunningJobs()` (`routes/batch.ts:526`) does NOT run in queue mode — there are no local engines on the API process anymore. The hook is no-op in queue mode and stays in place for `inline` back-compat.

If the SIGTERM-to-SIGKILL grace period is shorter than the longest legal job (default Cloud Run = 10 minutes, max batch concurrency 4 × default 1 000-row cap ≈ minutes), the worker's lock expires while the job is mid-flight; BullMQ marks it stalled and another worker picks it up. This is *good* — the alternative is silent loss. The downside is partial work re-execution; see § 8.

### DLQ inspection

`bull-board` (`@bull-board/api`) ships an Express middleware that renders a read-only HTML dashboard for queue state. **Do not bake this into the production server image** — it's an operator-only diagnostic. Recommended pattern:

* Ship a separate `apps/server/src/admin-ui.ts` entry point that runs the dashboard locally and connects to the same Redis. Operators run it on-demand:
  ```bash
  docker run --rm -p 3030:3030 -e OPENCRED_REDIS_URL=… opencred/server:tag node dist/admin-ui.js
  ```
* Alternatively, add a CLI command (`opencred queue list-failed --queue=batch`) that uses BullMQ's `getJobs("failed")` to dump DLQ entries as JSON for scripted redrive.

Decision is deferred to the impl PR; both options are tracked.

### Per-job size limits

Queue messages carry the parsed CSV rows. With `OPENCRED_BATCH_ROW_LIMIT` default 1 000 and typical row size ~500 bytes, payload is ~500 KB per job — well within Redis's 512 MB string cap and BullMQ's practical message size limit. **However:** if the row cap ever ramps to 10 000+ or rows ever include media bytes, the impl PR should switch to a "rows-by-reference" model where the queue message holds a `payloadKey` pointing to a separate Redis blob (still bounded by `OPENCRED_SESSION_TTL`). Flagged for the impl PR.

---

## 8. Out of scope for the first implementation PR

Listed explicitly so the impl PR's review doesn't expand scope:

1. **Cross-region queue replication.** Single Redis primary per deployment. Multi-region disaster recovery is a separate cell to crack — likely involves Redis Streams + a cross-region replicator, or migration to a managed queue with built-in regional failover. Out of scope.
2. **Exactly-once delivery.** BullMQ (like SQS Standard) is at-least-once. A worker can complete a job, crash before acking, and another worker picks the same job up. The current `BatchEngine` is **not idempotent at the row level** — re-running the same job risks duplicate VCs being signed. Mitigation: the impl PR can add a `processedRowIds` set in the JobRecord and have the engine skip already-signed rows on resume. This is non-trivial and is deferred. Document the "if a worker dies mid-batch, expect at-least-once row processing" caveat in the docs delta.
3. **Priority queues.** All batches are equal. Premium customers / priority lanes can be added later by either: (a) adding `priority` to `BatchJob.add()` calls, or (b) running separate workers consuming separate queues. Trivial to add when needed; out of scope for v1.
4. **Batch chunking inside a single job.** Today one CSV → one job → one worker processes all rows sequentially with internal `p-map` concurrency. A future optimisation could split a 10 000-row CSV into 10 jobs of 1 000 rows each for true horizontal parallelism. Not needed at current throughput; flagged as a Tier-4 future.
5. **Redis Streams instead of BullMQ.** A more bare-metal approach. BullMQ is built on Lua scripts + LIST primitives; Streams would give us better consumer-group semantics for free. Not worth the swap — BullMQ is mature, well-documented, and we don't have specific Streams-only requirements.
6. **Worker UI / admin endpoints in the API process.** Keep them separate so a leaked admin endpoint can't reveal queue contents.

---

## 9. Acceptance check

| Spike-brief acceptance item | Where |
| --- | --- |
| `docs/spikes/spike-<n>-external-job-queue.md` exists, all 8 questions answered | This doc, §§ 1–8 |
| Recommendation concrete | § 1 TL;DR — BullMQ + Redis |
| Sample worker entry-point sketched | § 3 — `apps/server/src/worker.ts` sketch + § 4 webhook-worker sketch |
| `BatchJob` message type in `packages/shared` | `packages/shared/src/batch-job.ts` (this PR) |
| PR includes only the doc + optional scaffolding | This PR contains the doc, the `BatchJob` type, and nothing wired into routes |

---

## 10. Migration risks worth calling out in the impl PR

These are not blockers, but they need conscious decisions when implementation lands.

1. **Engine progress hook.** The engine doesn't currently emit progress callbacks; today the route polls `engine.getProgress()`. Adding an `onProgress(cb)` API is small but touches a tested boundary; needs its own unit test.
2. **Webhook signing in the worker context.** `deliverWebhook` is pure (URL + payload + secret in, side-effect-only out) so calling it from the worker is mechanical, but the worker process must independently validate that `OPENCRED_WEBHOOK_SECRET` is present *if any pending webhook job exists*. If the worker boots with no secret configured, those jobs should fail loudly into the DLQ rather than silently dropping — the impl PR should add a startup probe.
3. **TTL alignment.** `JobRecord` TTL is `OPENCRED_SESSION_TTL` (default 4 h). Queue jobs need an *upper bound* on time-in-queue or stalled jobs can pile up. Set `removeOnComplete: { age: OPENCRED_SESSION_TTL }` and `removeOnFail: { age: 24 * 60 * 60 }` (24 h DLQ retention) at minimum.
4. **Stalled-job re-execution under at-least-once semantics.** Without idempotency keys, a worker crash mid-batch causes the next worker to re-sign every row. Two paths:
   * Accept it (current `inline` behaviour does the same when SIGTERM hits mid-batch — the job is marked `interrupted` and re-submission re-signs everything anyway).
   * Add a per-row `signedAt` marker that gets persisted to the `JobRecord` after each sign. Then the engine skips rows where `signedAt` is set on resume.
   The spike recommends the first path for the impl PR — simpler, matches existing semantics — and a follow-up issue for resume support. Flagged as **deviation worth highlighting in the impl PR's review.**
5. **Configuration sprawl.** This spike adds 3 new env vars (`OPENCRED_BATCH_DISPATCH`, `OPENCRED_WORKER_CONCURRENCY`, `OPENCRED_WEBHOOK_WORKER_CONCURRENCY`). All have sensible defaults and the back-compat default keeps every existing deployment working as-is, but the docs delta needs to surface these clearly in the deployment guide.
6. **CLAUDE.md security audit.** Worker process inherits the same rules as the API process: no key material in logs, no key material in queue payloads, ephemeral storage TTL respected. The impl PR should re-run the security review skill on the worker code specifically.

---

## 11. Decision summary (for the parent issue's tracking comment)

* **Adopt:** BullMQ + Redis. Reuses existing Redis infra (#575), portable across all deployment targets.
* **Reject:** AWS SQS — deployment-model mismatch.
* **Migration path:** `OPENCRED_BATCH_DISPATCH=inline|queue` feature flag, defaults to `inline`. Zero impact on existing deployments.
* **Adds:** `BatchJob` message type in `@opencred/shared` (this PR), `apps/server/src/worker.ts` worker entry (impl PR), `apps/server/src/webhook-worker.ts` webhook-worker entry (impl PR), separate `webhook` queue.
* **Defers:** exactly-once / row-level idempotency, cross-region replication, priority queues, payload-by-reference. Filed as follow-up issues from the impl PR.

This spike is finished; the impl PR can now be scoped and split into a single tracked work unit.
