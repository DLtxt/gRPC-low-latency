# M2 findings — the single-session baseline, measured through gRPC

Status: **M2 exit criterion met.** `grpcurl` gets a real signature from the service, and
`docker compose up` brings up a healthy proxy serving `hsm.v1.HsmService` end to end.

All five RPCs are implemented against one PKCS#11 session behind a mutex — deliberately
the naive design, so the M3 worker pool has something real to be compared against.

## Correctness checks

| Check | Result |
|---|---|
| ECDSA P-256 sign → verify | round-trips |
| Tampered message | returns `valid:false`, **not** an error status |
| RSA PKCS#1 v1.5, message input vs. pre-hashed digest input | **byte-identical signatures** |
| Signature made from a digest, verified against the message | verifies |
| RSA-PSS sign → verify | round-trips |
| AES-GCM encrypt → decrypt | round-trips |
| AES-GCM decrypt with wrong AAD | rejected as `InvalidArgument` |
| `GetPublicKey` | returns valid DER SubjectPublicKeyInfo |

The byte-identical RSA result is the meaningful one. PKCS#1 v1.5 is deterministic, so it
proves the hand-rolled `DigestInfo` wrapper is exactly what `CKM_SHA256_RSA_PKCS` builds
internally. That path exists so callers can pre-hash and keep large payloads off the wire.

## Measurements

Native macOS (Apple M2, 8 cores), SoftHSM 2.7, `ghz` 0.121.0 over loopback, no TLS yet.

| Workload | Concurrency | QPS | avg | p99 |
|---|---|---|---|---|
| ECDSA P-256 sign | 1 | 2,396 | 0.38 ms | 0.54 ms |
| ECDSA P-256 sign | 8 | 2,867 | 2.75 ms | 3.00 ms |
| ECDSA P-256 sign | 50 | 2,893 | 17.14 ms | 17.76 ms |
| RSA-2048 sign | 8 | 937 | 8.49 ms | 8.82 ms |
| GetPublicKey | 8 | 2,211 | — | 3.83 ms |

## What this says

**1. The mutex is the bottleneck, exactly as designed.** ECDSA throughput is flat at
~2,900 QPS from concurrency 8 to 50. The extra 42 in-flight requests buy no throughput at
all and cost 5.9× the p99 latency (3.00 ms → 17.76 ms). That is a textbook serialized
resource: load arrives, queues, and waits. This is the "before" picture M3 has to fix.

**2. For ECDSA, the proxy costs more than the crypto does.** M0 measured a raw
single-session ECDSA sign at 54.7 µs. Through gRPC and the mutex it is 346 µs — so roughly
**290 µs per request is proxy overhead**, 5.3× the cost of the signature itself. That is
gRPC framing, protobuf encode/decode, Tokio scheduling, and the blocking call stalling a
runtime worker.

**3. RSA is barely affected, which confirms the M0 framing decision.** Raw RSA was
1,195/sec; through the proxy it is 937/sec, only a 22% loss, because RSA's 836 µs of
computation dwarfs the ~290 µs of overhead. The HSM genuinely is the bottleneck for RSA
and genuinely is not for ECDSA — which is precisely why plan.md §2 now reports RSA as the
pooling headline and ECDSA as an overhead study.

**4. Expect the M3 pool to help RSA far more than ECDSA.** RSA should scale with worker
count until CPU saturates. ECDSA will hit the gRPC layer's ceiling long before eight
workers are busy, so the M3 curve should be read as a measurement of the *proxy*, not the
token.

## Implementation note

`cryptoki::Mechanism` holds raw pointers for its parameterized variants, so it is `!Send`
and cannot be held across an `.await`. Mechanism *selection* is therefore modelled as a
plain `SignAlgorithm` enum and the `Mechanism` is constructed on the thread that calls
into the module. M3 needs the same property for a different reason: jobs sent down the
worker channel must be `Send`.
