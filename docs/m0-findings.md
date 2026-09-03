# M0 findings — the spike, and what it means for plan.md

Status: **M0 exit criterion met.** `proxy/src/bin/spike.rs` loads `libsofthsm2.so` via
`cryptoki`, logs in, generates an ECDSA P-256 key pair, signs a SHA-256 digest, verifies
it through the token, and rejects a tampered digest. It runs both natively on macOS and
inside `linux/arm64` Docker.

`cryptoki` gave no friction, which retires the top risk in plan.md §9.

## Measurements

Single session, single thread, sequential. 5,000 iterations after a 100-iteration warm-up.

| Workload | Native macOS (M2, SoftHSM 2.7) | Docker linux/arm64 (SoftHSM 2.6) |
|---|---|---|
| ECDSA P-256 sign, handle cached | 18,283 /s (54.7 µs) | 24,792 /s (40.3 µs) |
| ECDSA P-256 sign, `C_FindObjects` every call | 8,944 /s (111.8 µs) | 18,194 /s (55.0 µs) |
| RSA-2048 sign (SHA256-RSA-PKCS), handle cached | 1,195 /s (836.5 µs) | 1,221 /s (819.1 µs) |

Hardware: Apple M2, 8 cores, 8 GB. Docker Desktop 29.6.2, 8 vCPU / 8 GB VM.

## What this does to the plan

**1. The "400 → 8,000 QPS" headline in §2 does not survive contact with the data.**
One session on one thread, doing the naive thing the plan holds up as the cautionary
example, already signs ~8,900 ECDSA/sec natively and ~18,200/sec in Docker. The plan's
"before" figure is off by roughly 20×. No honest baseline written against this token will
produce 400 QPS for ECDSA.

**2. Success criteria S1 and S2 are already met by a single thread.**
S1 asks for ≥ 4,000 QPS ECDSA sign; one session does 4.5× that. S2 asks for ≥ 8,000 QPS
cached verify, which is an in-process operation and will be faster still. As written these
are not targets, they are floors.

**3. The per-worker handle cache is a 1.4–2.0× win, not "a large part of the speedup".**
plan.md §4.3 is directionally right that `C_FindObjects` per request is waste, but at this
scale it is a modest constant factor, not the dominant term.

**4. The real bottleneck will be gRPC, TLS, and the runtime — not the HSM.**
At 40–55 µs per signature, eight worker threads have a theoretical ceiling around
150,000 signs/sec. Nothing in the network path on this hardware will feed that. For ECDSA
the proxy is therefore not removing a bottleneck; it *is* the bottleneck. That inverts the
project's narrative from "the HSM is slow, pool it" to "the HSM is fast, don't squander it."

**5. RSA-2048 is the one workload where the pool story is genuinely true.**
At ~1,200 signs/sec per session, the HSM really is the constraint. Eight workers should
approach ~9,500/sec — a real, defensible ~8× that has the same shape as the number the
plan originally wanted to claim, but with data behind it.

## Open decision

The benchmark framing in §2 and the success criteria in §1 need recalibrating before M8,
and arguably before M3, since the worker-pool milestone is where the headline curve gets
produced. Deferred to the maintainer.
