# Grafana dashboards

Sample Grafana dashboards for the OpenCred server's OpenTelemetry
critical-path instrumentation (see #581 / #446 Tier 3 #10).

## Dashboards

- `opencred-overview.json` — top-level latency and error view. Panels
  cover HTTP server p50/p95/p99, `batch.row.process` distribution,
  `signer.sign` by algorithm and kind, `verify.credential` outcomes,
  `verify.did_resolve` latency by DID method, DeDi adapter latency,
  and error rate by span name.

## Import

1. In Grafana → Dashboards → New → Import.
2. Upload the JSON file or paste its contents.
3. Pick your Tempo (or Jaeger) data source for the `tempo` variable.
4. Save.

## Wiring up the server

Set the following env vars on the server:

```
OPENCRED_OTEL_ENABLED=true
OTEL_SERVICE_NAME=opencred-server
OTEL_EXPORTER_OTLP_ENDPOINT=http://your-collector:4318
# Sampling — defaults to 100%. Production load typically wants:
OTEL_TRACES_SAMPLER=parentbased_traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1
```

The server falls back to a no-op exporter when
`OTEL_EXPORTER_OTLP_ENDPOINT` is unset; spans are still created but
nothing is shipped. Use this mode to validate the instrumentation
locally without a collector.

## Span inventory

| Span | Source | Key attributes |
|---|---|---|
| `<METHOD> <route>` | `tracingMiddleware` | `http.request.method`, `http.route`, `http.response.status_code` |
| `signer.sign` | `wrapSignerWithTracing` | `signer.algorithm`, `signer.kind`, `signer.fingerprint`, `signer.input_bytes`, `signer.signature_bytes` |
| `batch.run` | `createBatchEngine` / `createStreamingBatchEngine` | `batch.job_id`, `batch.proof_format`, `batch.total_rows` |
| `batch.row.process` | `createBatchEngine` / `createStreamingBatchEngine` | `batch.job_id`, `batch.row_index`, `batch.proof_format`, `batch.row_status` |
| `verify.credential` | `routes/credentials.ts` | `verify.format`, `verify.code`, `verify.verified` |
| `verify.did_resolve` | `wrapDidResolverWithTracing` | `did.method`, `did` |
| `verify.schema_validate` | `routes/credentials.ts` | `verify.schema_id`, `verify.inline_schema` |
| `dedi.lookup_record` | `wrapDeDiClientWithTracing` | `dedi.host`, `dedi.registry` |
| `dedi.publish_record` | `wrapDeDiClientWithTracing` | `dedi.host`, `dedi.registry` |
| `dedi.update_record` | `wrapDeDiClientWithTracing` | `dedi.host`, `dedi.registry` |

## Security

- No span carries key material, signing buffers, or credential subject
  PII. Span attributes are opaque ids (jobId UUID, fingerprint hash,
  DID string). See CLAUDE.md for the full contract.
- `dedi.host` is the HOST only; the path (which may carry record names)
  is never attached.
