# M4 findings — what mTLS and authorization cost

Status: **M4 exit criterion met.** Three client certificates, one denied for
`demo-rsa-2048`, with the counter incrementing.

## Enforcement

| Caller | Operation | Result |
|---|---|---|
| no certificate | anything | rejected during the TLS handshake — never reaches a handler |
| `payments` | sign `demo-rsa-2048` | allowed |
| `batch` | sign `demo-ec-p256` | allowed |
| `batch` | sign `demo-rsa-2048` | `PermissionDenied` |
| `reporting` | sign `demo-ec-p256` | `PermissionDenied` (read-only workload) |
| `reporting` | `GetPublicKey demo-ec-p256` | allowed |

Counters after that run: `allowed=3 denied=2 unauthenticated=0`. Denials log `identity`,
`key_label`, and `op` as structured fields, which is what M7 exports as
`hsm_authz_denied_total{identity, key_label, op}`.

## What it costs

Back to back on an otherwise quiet machine, ECDSA P-256, pool with 4 workers, median of
three runs per cell:

| Concurrency | Plaintext QPS | mTLS QPS | Delta |
|---|---|---|---|
| 4 | 5,909 | 5,143 | −13.0% |
| 8 | 7,004 | 6,865 | −2.0% |
| 12 | 7,799 | 7,440 | −4.6% |
| 16 | 8,058 | 7,910 | −1.8% |

| Metric at concurrency 4 | Plaintext | mTLS |
|---|---|---|
| Max QPS at p99 < 2 ms | 5,909 | **5,143** |
| p50 | 0.520 ms | 0.570 ms |
| p99 (median of 3) | 1.010 ms | 1.610 ms |

**mTLS costs roughly 13% of sustainable throughput inside the 2 ms budget, and about
50 µs of median latency.** The budget still holds: 5,143 QPS with full mutual
authentication and per-key authorization, p99 under 2 ms, zero errors.

Handshakes are not the story. `ghz` opens its connections once and reuses them across
15,000 requests, so the recurring cost is symmetric record encryption and framing, not
asymmetric key exchange. A workload that opens a connection per request would look far
worse, and that is a client design problem rather than a proxy one.

Authorization itself is close to free. Identity extraction memoizes on the leaf
certificate DER, so the X.509 parse happens once per distinct certificate rather than
once per request, and the policy check is two hash probes and a set membership test.

## A measurement caveat, and how it was caught

The first attempt at this comparison produced 4,987 QPS for a configuration that had
measured about 10,000 QPS earlier. The cause was not the code: a VS Code GitHub Copilot
Chat extension process was running `git add -A` over the entire home directory — a git
repository containing every untracked cache on the machine — and had been pinned at 97%
of a core for more than sixteen minutes. Load average was 9.45 on 8 cores.

The A/B was deferred until that process finished and the table above was taken with load
average near 2.9 and no saturated core.

Two things follow. First, the **ratio** is the trustworthy part of this result; the
absolute figures remain provisional until the reference hosts run, because this machine is
never truly idle. Second, a benchmark harness needs to record the conditions it ran under,
not just its own configuration — see `results/REFERENCE.md`.
