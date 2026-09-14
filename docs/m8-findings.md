# M8 — the Go baseline and generated result tables

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

