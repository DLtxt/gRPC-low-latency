# Best results

The best numbers this project has achieved, with the conditions that produced them.

**This file is a record, not a snapshot.** After any benchmark run, compare against these
figures and update wherever one is beaten. A result only replaces an entry if it was
measured under conditions at least as trustworthy — see [Ranking rules](#ranking-rules).

Last updated: **2026-09-08** · commit `f9afbfd` · raw data in [`results/reference/`](results/reference/)

---

## Headline

> **20,000 requests/second at p99 = 1.15 ms**, zero errors.
> Capacity before the 2 ms budget breaks: **~22,000 QPS**.

Measured on two `c7g.2xlarge` instances (Graviton3, 8 cores) in `us-east-1f` — proxy on
one, load generator on the other — open loop at a fixed offered rate, ECDSA P-256 sign,
8 workers, queue depth 16, plaintext.

---

## Peak sustained throughput inside the 2 ms budget

Every row is a single run satisfying both constraints at once: the stated throughput
*with* p99 under 2 ms *and* zero errors. Not a peak throughput quoted beside a tail
measured somewhere else.

| Workload | Best | Where | Setup |
|---|---|---|---|
| **ECDSA P-256 sign** | **20,000 QPS @ p99 1.15 ms** | `c7g.2xlarge` ×2 | two-host, open loop |
| ECDSA P-256 sign | 11,915 QPS @ p99 1.75 ms | `c7g.2xlarge` | single-host (client shares CPU) |
| ECDSA P-256 sign | 11,538 QPS | `c7i.2xlarge` | single-host |
| **ECDSA verify (cached key)** | **17,260 QPS @ p99 1.69 ms** | `c7g.2xlarge` | single-host |
| ECDSA verify (cached key) | 15,827 QPS | `c7i.2xlarge` | single-host |
| RSA-2048 sign | 1,083 QPS | `c7g.2xlarge` | single-host |
| RSA-2048 sign | 761 QPS | `c7i.2xlarge` | single-host, **baseline** beat the pool |

The two-host ECDSA figure is the honest capacity number. The single-host figures are
~45% lower purely because `ghz` was competing with the proxy for the same eight cores;
they are kept for comparison, not as records.

### Latency at each offered rate (two-host, ECDSA sign)

| Offered | Accepted | Shed | p50 | p99 | Within budget |
|---|---|---|---|---|---|
| 4,000 | 24,000 | 0% | 0.29 ms | 0.48 ms | yes |
| 8,000 | 48,000 | 0% | 0.29 ms | 0.49 ms | yes |
| 12,000 | 72,000 | 0% | 0.31 ms | 0.56 ms | yes |
| 16,000 | 96,000 | 0% | 0.34 ms | 0.76 ms | yes |
| **20,000** | **119,978** | **0%** | **0.42 ms** | **1.15 ms** | **yes** |
| 25,000 | 136,376 | 9% | 1.08 ms | 2.13 ms | no |

p99 moves only 0.48 → 0.76 ms across a 4× range of offered load. The service is not
straining until it approaches capacity.

---

## Behaviour beyond capacity

| Offered | × capacity | Shed | Accepted throughput | p99 |
|---|---|---|---|---|
| 25,000 | 1.1× | 9% | ~22,700 QPS | 2.13 ms |
| 30,000 | 1.4× | 27% | ~21,900 QPS | 3.38 ms |
| 35,000 | 1.6× | 39% | ~21,300 QPS | 5.13 ms |
| 40,000 | 1.8× | 46% | ~21,700 QPS | 6.80 ms |
| 50,000 | 2.3× | 57% | ~21,500 QPS | 17.04 ms |

**Best property demonstrated: accepted throughput holds at 21,000–22,000 QPS across a
2.3× range of offered load.** The service refuses excess rather than collapsing. The
tail does degrade under sustained overload, so the load-shedding claim is "throughput and
error rate stay bounded", not "latency stays flat".

---

## Speedups over the naive baseline

| Comparison | Best factor | Where |
|---|---|---|
| ECDSA sign: worker pool vs single mutexed session | **2.60×** (4,590 → 11,915 QPS) | `c7g.2xlarge` |
| ECDSA sign: worker pool vs single session | 2.03× (5,675 → 11,538 QPS) | `c7i.2xlarge` |
| ECDSA verify: cached + `ring` vs `p256` | **1.84×** (4,076 → 7,505 QPS) | M2 laptop |
| RSA-2048 sign: worker pool vs single session | 2.02× (536 → 1,083 QPS) | `c7g.2xlarge` |

---

## Token ceilings (raw PKCS#11, no gRPC in the path)

The most the SoftHSM2 token itself can do, which bounds everything above.

| Workload | Best | Threads | Scaling | Host |
|---|---|---|---|---|
| **ECDSA P-256 sign** | **35,376 ops/s** | 4 | 2.53× | `c7g.2xlarge` |
| ECDSA P-256 sign | 28,257 ops/s | 4 | 1.51× | `c7i.2xlarge` |
| ECDSA P-256 sign | 34,272 ops/s | 2 | 1.82× | M2 laptop |
| **RSA-2048 sign** | **5,965 ops/s** | 8 | 4.32× | `c7i.2xlarge` |
| RSA-2048 sign | 5,331 ops/s | 8 | **7.93×** | `c7g.2xlarge` |

**Best scaling achieved: 7.93× on 8 threads** (RSA, Graviton3) — near linear. Scaling
tracks *full-performance physical cores*, not vCPUs: 8 real cores on `c7g` against 4
physical plus SMT on `c7i`, and 4 performance plus 4 efficiency on the M2.

ECDSA walls early on every machine — a serialized section inside the module caps it near
2× regardless of thread count.

---

## Best per-operation costs

Single-threaded, no gRPC.

| Operation | Best | Host |
|---|---|---|
| ECDSA sign (token) | **53.0 µs** | `c7i.2xlarge` |
| ECDSA verify (token, OpenSSL) | 96.5 µs | `c7i.2xlarge` |
| **ECDSA verify (in-process, `ring`)** | **62.8 µs** | `c7i.2xlarge` |
| ECDSA verify (in-process, `p256`) | 222.7 µs | `c7i.2xlarge` |
| RSA-2048 sign (token) | **725 µs** | `c7i.2xlarge` |

`ring` beats the token's own OpenSSL by 1.5–1.7× and the portable `p256` by 3.5–4.6× on
every machine tested. This is why `Verify` is faster than `Sign` despite doing more
cryptographic work.

---

## Cost of the security layer

| Measurement | Value | Host | Status |
|---|---|---|---|
| mTLS throughput cost | −13% (5,909 → 5,143 QPS) | M2 laptop | provisional |
| mTLS median latency cost | +50 µs (0.520 → 0.570 ms) | M2 laptop | provisional |
| Authorization cost | negligible (memoized cert parse + 2 hash probes) | — | — |

Provisional because it was measured on the laptop. The ratio is more trustworthy than the
absolutes — it was taken back to back on an otherwise quiet machine — but it has not been
confirmed on a reference host.

---

## Ranking rules

A new result replaces an entry only if measured under conditions at least as trustworthy.

1. **Reference host beats laptop.** `c7g.2xlarge` / `c7i.2xlarge` results supersede
   anything from the M2, which drifted ~25% within a single session on unchanged code.
2. **Two-host beats single-host for any overload or capacity figure.** With the load
   generator on the proxy's own machine, changing only client concurrency swung accepted
   p99 between 0.65 ms and 105 ms, and mean HSM service time rose 259 → 500 µs purely
   from CPU starvation.
3. **Open loop beats closed loop** for anything involving shedding. Closed-loop load
   refills as fast as the server rejects, so measured capacity becomes an artifact of how
   quickly the server says no.
4. **Zero errors, or it is not a record.** Shed requests are answered in microseconds, so
   a run that rejects most of its load reports a *higher* QPS than one that serves it.
5. **Median of at least 3 runs** for throughput-under-budget figures; p99 sits close
   enough to 2 ms that single runs land on either side by chance.

Every entry carries its host and setup for exactly this reason: a number without its
conditions cannot be compared against a later one.

## When a run is worse

Leave the record alone, but note the regression — a drop against a known best is a signal
worth investigating, not a result to discard.

## Reproducing

See [`docs/running-reference-benchmarks.md`](docs/running-reference-benchmarks.md) for
launch-to-teardown instructions. A full two-host pass is about 30 minutes of instance time
and well under a dollar.
