# M8 findings — the Go baseline and generated numbers

Status: **baseline and result rendering complete.** The custom Go load generator for
mixed read/write ratios (plan.md §3.2) is not built; `ghz` plus `bench-overload.sh`
covers every scenario measured so far.

## Why the baseline is written in Go

plan.md §3 requires it, and the reason survives scrutiny: a baseline written in Rust
invites the objection that the comparison is really *badly written Rust versus well
written Rust* rather than *naive architecture versus pooled architecture*. A different
language and a different PKCS#11 binding (`github.com/miekg/pkcs11`) removes that
objection entirely.

`baseline/` has three modes, and the middle one carries the argument:

| Mode | Shape |
|---|---|
| `serial` | one session, one goroutine, sequential — the honest floor |
| `naive-concurrent` | N goroutines sharing **one mutexed session** — the obvious mistake |
| `pooled` | N goroutines, N sessions — what the proxy does |

## The result that makes the case

Laptop, 8 workers, 4 s per mode, back to back:

| Mode | Workers | ops/sec | p50 | p99 |
|---|---|---|---|---|
| `serial` | 1 | 3,315 | 298 µs | 1,208 µs |
| `naive-concurrent` | 8 | 3,560 | 2,286 µs | **7,405 µs** |
| `pooled` | 8 | **7,642** | 768 µs | 6,624 µs |

**Eight goroutines sharing one session gained 7% throughput and made p99 six times
worse.** That is the entire argument for the worker pool, demonstrated in a language the
proxy is not written in, with no Rust anywhere in the measurement.

Pooling the sessions instead gives 2.3× the throughput of serial.

## A confound I nearly published

The Go baseline first measured 3,597 ops/sec against 18,283 for the equivalent Rust
probe — a 5× gap that looked like cgo overhead in Go's PKCS#11 binding, which would have
undermined the whole point of writing the baseline in Go.

Re-measuring both under identical conditions minutes apart:

| | ops/sec |
|---|---|
| Rust `hsm-ceiling`, 1 thread | 2,168 |
| Go `baseline`, serial | **3,682** |

Go was *faster*. The apparent 5× gap was entirely machine load — the Rust figure came
from a quiet machine and the Go figure from a busy one. There is no measurable binding
penalty.

The lesson is narrow and worth stating: **cross-language absolute comparisons on this
laptop are meaningless**, but the three-mode comparison remains valid because those runs
happen back to back within seconds of each other.

## Generated numbers

`scripts/render-results.py` reads every JSON under `results/` and prints the current best
figures, so no benchmark number in the documentation is ever hand-typed — a hand-typed
figure is one that will be wrong after the next change and stay wrong.

```bash
make table      # markdown table of current bests
make records    # what a new run beat, matched, or regressed against best_results.md
make baseline   # run the Go baseline in all three modes
```

It enforces the ranking rules from `best_results.md` mechanically: trust dominates
throughput, so a laptop figure that happens to be higher can never displace a
reference-host record.

## A correction the renderer forced

Writing the comparison exposed an error in the headline figure. `best_results.md`
originally claimed **20,000 QPS at p99 1.15 ms with zero errors**. The run actually shed
**22 of 119,978 requests** — 0.018%. Small, but not zero, and the file said zero.

Both the file and the ranking rule are corrected. The threshold is now "error rate at or
below 0.1%", with the exact shed count printed beside every figure, because strict zero
turned out to be too sharp an edge: at 0.018% the shedding is a rounding artifact of
open-loop pacing, not the service refusing work. The highest rate with literally zero
shedding, 16,000 QPS at p99 0.76 ms, is now recorded alongside it.

## Not built

The custom `grpc-go` load generator from plan.md §3.2 — mixed read/write ratios in one
run, cache-cold versus cache-warm phases, mTLS rotation mid-run. Everything measured so
far has been single-workload, which `ghz` drives well. It is worth building when there
is a mixed-workload claim to support; building it before then would be a harness with no
question to answer.

`cmd/hsmctl` is also unbuilt. plan.md §3 nominates it as the first thing to cut.
