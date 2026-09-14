# M5 — the public key cache and in-process verification

Status: **M5 delivered**, but the exit criterion as written is not met and could not be.
plan.md predicted verify QPS would "jump by ~an order of magnitude". It rose about 28%
inside the latency budget and 61% at peak. The reason is structural and was flagged before
the work started: M3 established that gRPC, not the token, is the binding constraint for
ECDSA, so removing a ~140 µs operation from a request that costs several hundred
microseconds cannot produce 10×.

## What was built

`moka` cache over public keys, keyed by label:

- **Single-flight** via `try_get_with`, so a cold key under concurrent load produces one
  token lookup rather than one per in-flight request.
- **Per-outcome TTLs** — 5 minutes for a real key, 30 seconds for a negative result. A
  single cache-wide TTL would force one of the two to be wrong.
- **Negative caching**, verified: five consecutive requests for a nonexistent label
  produced **one** pool submission and four negative hits.
- Positive path verified: `served_from_cache` goes false → true → true, hit ratio and
  entry count exported.

Nothing derived from a private key is cached — no signatures, no plaintext, no decrypt
results, no PINs.

## Results

ECDSA P-256, pool with 4 workers, plaintext, median of three runs per cell:

| Workload | Max QPS at p99 < 2 ms | Peak QPS | p50 at concurrency 4 |
|---|---|---|---|
| Sign (HSM every request) | 5,876 | 7,636 | 0.520 ms |
| **Verify (cached key + `ring`)** | **7,505** | **12,327** | **0.440 ms** |
| Verify (cached key + `p256`) — rejected | 4,076 | 6,534 | 0.830 ms |

Verify is now genuinely cheaper than Sign, which is the correct ordering: it does no
token work at all, and an ECDSA verification in `ring` costs less than an ECDSA signature
in SoftHSM2.

## Correctness

Signatures produced by the token verify in-process across every mechanism and both input
forms, and tampered signatures are rejected as `valid: false` rather than as errors:

| Mechanism | message input | digest input | tampered |
|---|---|---|---|
| ECDSA-SHA256 | valid | valid | rejected |
| RSA-PKCS1-SHA256 | valid | valid | rejected |
| RSA-PSS-SHA256 | valid | valid | rejected |

Authorization runs before the cache, so an identity without a grant for a label never
reaches either the cache or the token — confirmed by a denied request for a nonexistent
key returning `PermissionDenied` rather than `NotFound`.
