# M3 findings — the worker pool, and where the real ceiling is

Status: **M3 exit criterion met**, with a correction to what the curve actually measures.

The mutex is gone. N dedicated OS threads each own one PKCS#11 session for their entire
life, fed by a single bounded MPMC channel. `tokio::task::spawn_blocking` is not used:
its pool grows on demand, threads are not pinned, and — decisive here — its queue depth
is invisible, which is the one number this design has to expose.

## Headline

Measured back to back on the same machine within one minute, ECDSA P-256, median of three
runs per cell:

| Configuration | Max QPS at p99 < 2 ms | At concurrency |
|---|---|---|
| Single session behind a mutex (M2) | 3,302 | 4 |
| **Worker pool** | **~10,400** | 8–12 |

**≈3.1× more sustainable throughput inside the 2 ms budget.** Not peak QPS with the tail
quoted from a different run — the same run has to satisfy both.

The pool also improves latency at equal load rather than trading it away: at concurrency 4
the baseline runs p99 1.53 ms while the pool runs 0.73 ms.

## The measurement that reframes the project

The pool's ECDSA service time doubled every time the worker count doubled (68 → 108 → 215
→ 452 µs for 1 → 2 → 4 → 8 workers), while RSA scaled nearly linearly. That is what a
fixed *serialized section* inside the module looks like, so `hsm-ceiling` measures the
token directly — N threads, N sessions, tight sign loops, no gRPC, no Tokio, no proxy:

| Threads | ECDSA ops/s | scaling | RSA ops/s | scaling |
|---|---|---|---|---|
| 1 | 18,791 | 1.00× | 1,159 | 1.00× |
| 2 | 34,272 | 1.82× | 2,195 | 1.89× |
| 4 | 34,227 | 1.82× | 3,410 | 2.94× |
| 6 | 33,402 | 1.78× | 4,132 | 3.57× |
| 8 | 32,226 | 1.71× | 4,277 | 3.69× |
| 16 | 32,793 | 1.75× | 4,313 | 3.72× |

**SoftHSM2 stops scaling ECDSA after two threads and walls at ~34,000 ops/s.** RSA reaches
~3.7× because its 836 µs of computation dwarfs the serialized section. This is Amdahl's law
with a lock of roughly 50 µs: for RSA that is 6% of the work and barely matters; for ECDSA
it is nearly half, capping speedup near 2× no matter how many threads are added.

Three consequences:

1. **RSA through the proxy is already at the token's limit.** The proxy peaks at ~4,625
   QPS against a raw ceiling of ~4,300–4,400. There is nothing left to win on RSA by
   improving the proxy; the token is the constraint, which is exactly what plan.md §2
   claims for the RSA headline — now with the ceiling measured rather than assumed.
2. **Adding workers past the knee actively hurts the tail.** At fixed concurrency 32, RSA
   p99 goes 14.1 ms at 4 workers → 20.8 ms at 8 → 61.7 ms at 16, with throughput flat at
   ~3,720 QPS. More workers accept more concurrent work against a saturated resource.
3. **For ECDSA the proxy reaches roughly half the token ceiling** (~10,400 sustainable
   under budget, ~17,500 peak, against ~34,000). That gap is gRPC, protobuf, and the
   runtime — the remaining headroom is in the proxy, not the HSM.

## The handle cache works

Over a 20,000-request run with 8 workers: **19,992 cache hits, 8 misses** — exactly one
miss per worker, on first use. Object handles are session-scoped and cannot be shared
between workers, so per-worker caching is the only correct form. Without it every request
would pay a `C_FindObjects`, which M0 measured at ~57 µs, roughly the cost of the ECDSA
signature itself.

## A correction to how these numbers were produced

Two measurement errors were made and fixed; both would have produced a flattering and
wrong headline.

1. **Benchmarking the wrong server.** An early pool measurement reported 6,600–6,990 QPS.
   The native proxy had actually failed to bind (`Address already in use`) and the load
   went to a leftover Docker container — a different transport path entirely. The sweep
   harness now refuses to run when anything is already listening on the port.
2. **Counting shed load as throughput.** At concurrency 128 the pool reported 28,727 QPS,
   the best figure in the table. 8,959 of 20,000 requests had been rejected as
   `RESOURCE_EXHAUSTED`, and rejections are answered fast, so shedding *raises* measured
   QPS. The harness now prints an error column beside every row.

A third issue is inherent rather than a bug: p99 sits close enough to the 2 ms budget that
single runs land on either side of it by chance, and this laptop's throughput drifts
noticeably over a session. The harness now takes the median of three runs per cell and
prints the min–max spread, and comparisons are only made back to back. This is the
reproducibility problem the pinned reference hosts in plan.md §7 exist to solve.

## Tuning guidance

- `HSM_WORKERS` defaults to `available_parallelism()`. For ECDSA-dominant load, 2–4 is
  enough and 8 is oversubscribed; for RSA-dominant load, 6–8 is right. The default favours
  RSA, which is the headline workload.
- `HSM_QUEUE_DEPTH` defaults to `2 × workers`. Deeper queues raise peak throughput and
  destroy the tail — precisely the trade this project exists to refuse.
