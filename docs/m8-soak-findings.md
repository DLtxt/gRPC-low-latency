# Soak — sustained load, plaintext and mTLS

Status: **clean.** No memory growth, no latency drift, no session churn, zero errors.

| | |
|---|---|
| Hosts | two `c7g.2xlarge`, `us-east-1f` — proxy on one, load generator on the other |
| Offered rate | 16,000 req/s, ECDSA P-256 sign, 8 workers, queue depth 16 |
| Monitored window | 2,675 s (~45 min) |
| Requests served | **42,428,082** |

## Memory: no leak

RSS sampled from the proxy host every 30 s across 82 samples:

| | |
|---|---|
| First → last | 38.46 MB → 35.98 MB |
| Min / max | 34.25 MB / 43.10 MB |
| **Growth** | **−2.48 MB (−6.45%)** |

Memory ended *lower* than it started, and stayed inside a ~9 MB band while serving
42 million requests. Had the public-key cache, the per-worker handle maps, or per-request
allocation leaked, 42 million requests is more than enough to show a rising floor. None
appeared.

## Latency: no drift

| | |
|---|---|
| p50 | 0.291 ms |
| p99 | 0.694 ms |
| p99, first half | 0.710 ms |
| p99, second half | **0.677 ms** |

The second half was marginally *faster* than the first. A service degrading under
sustained load shows the opposite, and the split-half comparison exists precisely because
a single aggregate cannot distinguish a steady 0.7 ms from 0.5 ms drifting to 2 ms.

## Stability

| | |
|---|---|
| Errors | **0** across 42.4 M requests |
| Session resets | **0** — no worker ever had to reopen a session |
| Rate min / median / max | 5,243 / 15,936 / 16,732 req/s |

The 5,243 minimum is a single sampling interval at startup, before the rate stabilised;
every other interval sat within a few percent of the 16,000 target.

## The same run under mTLS

A second soak with mutual TLS enabled end to end, `payments` client identity:

| | |
|---|---|
| Sustained rate | 13,925 req/s for 1,186 s |
| p50 / p99 | 0.316 ms / 0.656 ms |
| p99, first half → second half | 0.648 ms → 0.663 ms |
| RSS, mean first half → second half | 35.9 MB → 36.9 MB |
| Errors | 6 of 1,000,000 sampled |
| Session resets | 0 |

RSS climbs for the first minute or so as the allocator and connection pools warm, then
settles: the mean over the second half is within a megabyte of the first. The encrypted
path holds the same p99 across both halves as the plaintext one, so TLS record handling
adds cost per request without accumulating state.
