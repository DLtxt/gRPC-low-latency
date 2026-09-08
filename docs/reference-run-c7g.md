# Reference run — c7g.2xlarge (Graviton3)

First benchmark on pinned reference hardware. Every figure below is reproducible: the
result files in `results/reference/` carry the instance type, CPU model, kernel, toolchain
versions, and the commit they were taken at.

| | |
|---|---|
| Instance | `c7g.2xlarge`, us-east-1 |
| CPU | Graviton3 (Neoverse-V1), 8 cores |
| OS / kernel | Ubuntu 24.04.4, 7.0.0-1012-aws |
| Rust / SoftHSM | 1.98.1 / 2.6.1 |
| Commit | `f9afbfd`, clean tree |
| Protocol | median of 3 runs per cell, plaintext, loopback |

## Headline: the 2 ms budget holds

| Workload | Baseline (1 session) | Worker pool | Gain |
|---|---|---|---|
| **ECDSA P-256 sign** | 4,590 QPS | **11,915 QPS** | **2.60×** |
| **ECDSA verify (cached)** | — | **17,260 QPS** | — |
| RSA-2048 sign | 536 QPS | 1,083 QPS | 2.02× |

All figures are the maximum sustained throughput at which **p99 stayed below 2 ms with
zero errors** — one run satisfying both constraints, not a peak throughput quoted beside a
tail measured somewhere else.

The headline number for the project is **11,915 QPS of ECDSA signing at p99 < 2 ms**, or
**17,260 QPS** when the workload is verification and the public key cache keeps the token
out of the path entirely.

## Laptop figures were wrong in both directions

The provisional numbers taken during M3–M5 on an Apple M2 did not merely differ in
magnitude; for RSA they pointed the wrong way.

| Workload at p99 < 2 ms | M2 laptop | c7g.2xlarge | |
|---|---|---|---|
| ECDSA sign, baseline | 3,302 | 4,590 | reference 39% faster |
| ECDSA sign, pool | ~10,400 | 11,915 | reference 15% faster |
| ECDSA verify, cached | 7,505 | 17,260 | reference 2.3× faster |
| RSA sign, baseline | 789 | 536 | **reference 32% slower** |
| RSA sign, pool | 3,503 | 1,083 | **reference 69% slower** |

### Why RSA inverted

Graviton3 is markedly slower than an M2 core at RSA-2048: 1,487 µs per signature against
836 µs. RSA leans on wide integer multiply, where Apple's cores are unusually strong. At
nearly 1.5 ms of pure computation, a single RSA signature consumes three quarters of the
2 ms budget by itself, so almost no concurrency fits underneath it — hence 1,083 QPS at
concurrency 2.

That is not a defect in the proxy. It is the token's cost, and the ceiling probe shows the
proxy extracting essentially all of it.

### The scaling story reverses, and the laptop was the misleading one

Token ceiling, raw PKCS#11, no gRPC in the path:

| Threads | ECDSA (M2) | ECDSA (c7g) | RSA (M2) | RSA (c7g) |
|---|---|---|---|---|
| 1 | 1.00× | 1.00× | 1.00× | 1.00× |
| 2 | 1.82× | 1.68× | 1.89× | 1.99× |
| 4 | 1.82× | 2.53× | 2.94× | 3.98× |
| 8 | 1.71× | 2.37× | 3.69× | **7.93×** |
| 16 | 1.75× | 2.29× | 3.72× | 6.77× |

**RSA scales almost perfectly linearly to 8 threads on Graviton3 — 7.93× — against 3.69×
on the M2.** The laptop's asymmetric cores (four performance, four efficiency) were
capping the curve, and M3 read that cap as a property of SoftHSM2. It was a property of
the laptop.

ECDSA still walls, but higher and later: ~35,400 ops/s at 4 threads on Graviton3 versus
~34,200 at 2 threads on the M2. The serialized section inside the module is real on both
machines; only its size changes.

This is exactly why plan.md §7 pins two architectures instead of one. A scaling curve
measured on a single machine is a fact about that machine.

## Verification costs, single-threaded

| Operation | M2 | c7g.2xlarge |
|---|---|---|
| sign (token) | 89–91 µs | 71 µs |
| verify (token, OpenSSL) | 142–182 µs | 115 µs |
| verify (in-process, RustCrypto `p256`) | 327–335 µs | 310 µs |
| **verify (in-process, `ring`)** | **76–80 µs** | **67.5 µs** |

The M5 finding holds on reference hardware: `ring` beats both the portable Rust
implementation (4.6×) and the token's own OpenSSL (1.7×). Choosing `p256` here would still
make `Verify` slower than leaving the work on the HSM.

## What this settles

1. **The budget is met on real server hardware**, with margin — the pool reaches
   11,915 QPS with p99 at 1.75 ms, and stays under 2 ms up to concurrency 12.
2. **ECDSA remains gRPC-bound.** The pool delivers 11,915 QPS against a token ceiling of
   ~35,400, so roughly two thirds of the remaining headroom is in the proxy, not the HSM.
3. **RSA is token-bound and now provably so.** The pool tracks the token's own ceiling
   closely, and the near-linear 7.93× scaling shows the worker pool doing exactly what it
   was designed to do once the hardware stops interfering.
4. **The M2 laptop is a poor proxy for server hardware** — not by a constant factor, but
   directionally, for RSA. Provisional figures in `docs/m3-findings.md` through
   `docs/m5-findings.md` should be read as laptop measurements only.

## Operational notes

Two things worth recording for the next run.

The AWS account needed its plan upgraded before any of this could run: new accounts sit on
a Free Tier plan that blocks non-free-tier instance types at launch, and `--dry-run` does
not detect the restriction — it returns `DryRunOperation` regardless, so only a real launch
attempt reveals it. Immediately after upgrading, the account entered `PendingVerification`
for a short period during which launches also fail. Both failures create no resources and
cost nothing.

`bench-reference.sh` did not include the cached-`Verify` sweep, which is M5's headline
workload. It was run manually on the instance and the result is in `results/reference/`;
the script should be extended before the next run so the suite covers it. Producing the
signature for that sweep also required `grpcurl` on the host, since `ghz` does not return
response bodies — the bootstrap does not install it.

## Superseded

`c7i.2xlarge` has since been run. See [`reference-runs.md`](reference-runs.md) for the
two-architecture comparison, which explains the RSA scaling ceiling this document could
only describe: it tracks physical core count, not SoftHSM2.
