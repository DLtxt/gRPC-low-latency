# M5 findings — the cache, and a mistake it exposed

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

## The mistake

The first implementation verified in-process with RustCrypto's `p256`. That made `Verify`
**slower than leaving the work on the HSM**: 4,076 QPS against Sign's 5,780 inside the
budget. Removing the HSM had made things worse, which is a contradiction worth chasing
rather than shipping.

Measured single-threaded on an Apple M2, no gRPC in the path:

| Operation | Cost |
|---|---|
| sign (token) | 89–91 µs |
| verify (token, OpenSSL) | 142–182 µs |
| verify (in-process, RustCrypto `p256`) | 327–335 µs |
| **verify (in-process, `ring`)** | **76–80 µs** |

`ring` carries hand-written P-256 assembly; RustCrypto's `p256` is portable Rust. The
difference is 4.1×, and it is the difference between the cache being a win and a
regression.

plan.md §2 specified `ring` for exactly this path. It was substituted for `p256` because
`p256` was already a dependency for SPKI decoding and reusing it looked tidy. Tidiness
was the wrong criterion for the one operation on the hot path.

**One caveat carried by the fix:** `ring` exposes no prehash entry point for ECDSA, so a
caller that pre-hashes still pays for the portable implementation. Sending the message is
now the faster choice; pre-hashing is right only when the payload is large enough that
keeping it off the wire outweighs the slower verification. Both paths are tested and both
agree with the token.

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
