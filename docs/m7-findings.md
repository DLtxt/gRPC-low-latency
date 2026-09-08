# M7 findings — observability

Status: **exit criterion met.** `docker compose up` brings up the proxy, Prometheus, and
Grafana, and the dashboard renders with live data and no manual steps.

## What was built

- Prometheus metrics on a **separate port** from gRPC (`:9090` in-container). Scraping
  should not require a client certificate, and the metrics endpoint must stay reachable
  while the gRPC service is shedding load — an observability endpoint that fails under
  overload is useless exactly when it is needed.
- An 8-panel Grafana dashboard, provisioned as JSON with its datasource, so first boot
  needs no clicks.
- Prometheus scraping at **1 s** rather than the default 15 s: a benchmark run lasts
  seconds, and at 15 s it would produce two or three points and no visible shape.

## The histogram buckets are the whole point

Default Prometheus buckets start at 5 ms. The entire latency budget here is 2 ms, so
every request would land in the first bucket and p99 would be unrecoverable from the
histogram — the dashboard would show a flat line at the bucket boundary regardless of
what the service was doing.

The buckets are therefore dense from 100 µs through 2 ms and sparse above it. Measured
over 2,000 requests, this gives real resolution across the budget:

| Bucket (≤) | Cumulative count |
|---|---|
| 250 µs | 278 |
| 500 µs | 1,049 |
| 750 µs | 1,584 |
| 1 ms | 1,805 |
| 1.5 ms | 1,935 |
| **2 ms (budget)** | **1,964 of 2,000** |
| 3 ms | 1,984 |

Queue wait and HSM service time get their own, finer buckets starting at 10 µs, because
their *ratio* is the graph that makes the pool legible: service time is what the token
costs, queue wait is what the design costs under load.

## Verified end to end

Driving 20,000 requests over mTLS through the composed stack:

| Panel | Live value |
|---|---|
| p99 latency | 1.10 ms — inside budget |
| p50 latency | 0.26 ms |
| queue wait p99 | 0.38 ms |
| HSM service p99 | 0.88 ms |
| workers | 8 |
| circuit breaker | closed |
| shed rate | 0 |

Throughput was 8,888 QPS with 20,000/20,000 OK. Grafana reports the dashboard
(`uid=grpc-low-latency`) and datasource as provisioned.

Labels are deliberately limited to operation and gRPC status code. Key labels and
identities are caller-controlled, and an unbounded label set is how a metrics endpoint
becomes an out-of-memory incident.

## Three bugs the container caught that local runs did not

**1. Two crypto providers.** Adding `ring` in M5 for fast in-process ECDSA verification
made two rustls providers reachable — tonic's `tls-ring` and the direct dependency — so
rustls refused to choose and panicked on startup with TLS enabled. Local benchmarking ran
with `PROXY_TLS=off`, so it never surfaced. Fixed by installing the provider explicitly.

**2. Declared metrics that were never recorded.** `hsm_queue_wait_seconds` and
`hsm_service_duration_seconds` had names, descriptions, and custom buckets, and no call
site. They returned `NO DATA` on the dashboard while looking entirely correct in the code.
The pool had been recording those durations into atomic counters for its own summary since
M3; the histograms needed wiring separately, from the worker thread — only the worker can
separate queue wait from service time, since from outside they are one number.

**3. A build that crashed rather than failed.** The image build died with
`frontend grpc server closed unexpectedly` — BuildKit running out of memory with eight
parallel `rustc` processes in an 8 GB VM, not a compile error. Capping `CARGO_BUILD_JOBS`
to 4 and adding cache mounts for the registry and target directory fixed it and cut
rebuilds from ~44 minutes to a few.

Note the shape of all three: each looked fine in the source and failed only when actually
run in the target environment.

## Using it

```bash
make up      # proxy + prometheus + grafana
make dash    # print the URLs and open Grafana
```

- Grafana: <http://localhost:3000> (anonymous admin — local demo only)
- Prometheus: <http://localhost:9090>
- Raw metrics: <http://localhost:9464/metrics>
