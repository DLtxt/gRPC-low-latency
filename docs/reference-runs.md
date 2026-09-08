# Reference benchmarks — ARM and x86

Both pinned reference hosts, same commit, same protocol. Raw results with full host
stamps are in `results/reference/`.

| | ARM reference | x86 reference |
|---|---|---|
| Instance | `c7g.2xlarge` | `c7i.2xlarge` |
| CPU | Graviton3 (Neoverse-V1) | Xeon Platinum 8488C (Sapphire Rapids) |
| vCPU / physical cores | 8 / **8** | 8 / **4** (hyperthreaded) |
| OS | Ubuntu 24.04.4 | Ubuntu 24.04.4 |
| Commit | `f9afbfd`, clean | `f9afbfd`, clean |

Protocol: median of 3 runs per cell, plaintext, loopback, zero errors required.

## Headline: the design holds across architectures

Maximum sustained throughput with **p99 below 2 ms** — one run satisfying both
constraints, not a peak quoted beside a tail measured elsewhere.

| Workload | ARM (c7g) | x86 (c7i) | Spread |
|---|---|---|---|
| ECDSA sign, single session | 4,590 | 5,675 | 24% |
| **ECDSA sign, worker pool** | **11,915** | **11,538** | **3.3%** |
| **ECDSA verify, cached** | **17,260** | **15,827** | **9.1%** |
| RSA-2048 sign, single session | 536 | 761 | 42% |
| RSA-2048 sign, worker pool | 1,083 | 629 | — |

**The two architectures agree to within 3.3% on the project's headline workload.** That
agreement is the result: it is evidence about the design rather than about one machine,
which is precisely what a single-host benchmark cannot give you.

Project headline: **~11,500–11,900 QPS of ECDSA signing at p99 < 2 ms**, and **~15,800–17,300
QPS** for cached verification where the public key cache keeps the token out of the path.

## Scaling tracks physical cores, not vCPUs

Token ceiling, raw PKCS#11, no gRPC in the path. This is where the two machines diverge,
and the divergence turns out to be simple.

| Threads | ECDSA c7g | ECDSA c7i | RSA c7g | RSA c7i |
|---|---|---|---|---|
| 1 | 1.00× | 1.00× | 1.00× | 1.00× |
| 2 | 1.68× | 1.38× | 1.99× | 1.85× |
| 4 | **2.53×** | **1.51×** | 3.98× | 3.78× |
| 8 | 2.37× | 1.02× | **7.93×** | **4.32×** |
| 16 | 2.29× | 1.17× | 6.77× | 4.00× |

RSA scaling lines up almost exactly with the number of *full-performance physical cores*:

| Machine | Full-performance cores | RSA scaling at 8 threads |
|---|---|---|
| Apple M2 | ~4 (4 performance + 4 efficiency) | 3.69× |
| `c7i.2xlarge` | 4 physical (8 vCPU via SMT) | 4.32× |
| `c7g.2xlarge` | 8 physical | **7.93×** |

Cryptographic work saturates the integer and vector execution units, so a hyperthread
sibling has nothing left to use. `c7g.2xlarge` gives eight real cores where
`c7i.2xlarge` gives four plus SMT, and the scaling curve simply reports that.

This retires the open question from M3. That milestone measured 3.69× on the laptop and
attributed the ceiling to SoftHSM2. It was never a property of the token — it was the
core count. On eight real cores the same code reaches 7.93×, which is close to linear.

## Per-operation costs

Single-threaded, no gRPC in the path.

| Operation | M2 laptop | c7g (ARM) | c7i (x86) |
|---|---|---|---|
| ECDSA sign (token) | 89–91 µs | 71.1 µs | **53.0 µs** |
| ECDSA verify (token, OpenSSL) | 142–182 µs | 115.0 µs | **96.5 µs** |
| ECDSA verify (in-process, `p256`) | 327–335 µs | 310.0 µs | 222.7 µs |
| **ECDSA verify (in-process, `ring`)** | 76–80 µs | 67.5 µs | **62.8 µs** |
| RSA-2048 sign (token) | 836 µs | 1,487 µs | **725 µs** |

Two things follow.

**The M5 `ring` decision holds on every machine tested.** `ring` beats the portable
RustCrypto implementation by 3.5–4.6× and the token's own OpenSSL by 1.5–1.7×. Had
`p256` shipped, `Verify` would have been slower than leaving the work on the HSM
everywhere, not just on the laptop.

**RSA per-operation cost varies by 2× across machines** — 725 µs on Sapphire Rapids
against 1,487 µs on Graviton3. RSA leans on wide integer multiply, where Intel's wider
multipliers win decisively. At 1.5 ms per signature on ARM, one RSA operation consumes
three quarters of the entire 2 ms budget, which is why the ARM RSA figures look so
constrained.

## Why RSA under the budget looks strange

The RSA pool numbers (1,083 ARM, 629 x86) are far below what those machines can actually
do — the pool reaches 3,957 QPS on ARM and 4,353 on x86 at higher concurrency. They are
low because RSA-2048 costs 0.7–1.5 ms per signature, so a single operation eats most of
the 2 ms budget and almost no queueing fits underneath it.

On x86 the pool at concurrency 1 (629 QPS) is actually *worse* than the single-session
baseline at concurrency 1 (761 QPS). That is not noise: at concurrency 1 the pool's
channel send and oneshot receive are pure added latency with no parallelism to offset
them. The pool wins from concurrency 2 upward and is far ahead by concurrency 4, but the
crossover is real and worth stating rather than hiding.

**RSA-2048 is the wrong algorithm for a sub-2 ms budget on this token.** ECDSA is the
right one, and the headline reflects that.

## What is settled

1. **The 2 ms budget is met on both reference architectures**, with the two agreeing to
   3.3% on ECDSA signing through the pool.
2. **The worker pool's value is proven, and its ceiling explained.** RSA scales 7.93× on
   eight real cores; the earlier 3.69× was a core-count artifact, not a SoftHSM2 limit.
3. **ECDSA remains gRPC-bound.** The pool delivers ~11,500–11,900 QPS against token
   ceilings of ~28,000–35,000, so most remaining headroom is in the proxy.
4. **Laptop figures should not be quoted.** They were wrong in magnitude and, for RSA,
   in direction. `docs/m3-findings.md` through `docs/m5-findings.md` remain valid as
   laptop measurements and are labelled as such.

## Reproducing

See [`running-reference-benchmarks.md`](running-reference-benchmarks.md). Both runs
together took about 27 minutes of instance time and cost roughly $0.15.
