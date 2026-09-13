# Soak test — 45 minutes at 15,861 req/s

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

## Two measurement bugs this run exposed

**1. RSS was not being recorded at all.** The soak script samples memory only when
`SERVER_SSH` is set, and the launch did not set it — so the run that exists specifically
to detect leaks was not measuring memory. Caught mid-run by inspecting the samples file
and noticing the column was empty. An external monitor collected RSS in parallel over the
same window, which is where the figures above come from, so the run did not need
restarting.

**2. The reported throughput was wrong by 57×.** The script derived `achieved_rps` from
the length of `ghz`'s per-request detail array. `ghz` truncates that array: it recorded
1,000,000 entries for a 57,600,000-request run, so the script reported **277.7 req/s** for
a run the server's own counter measured at **15,861 req/s**.

The detail array is still a valid latency *sample* — the percentiles above are drawn from
a million requests and are sound. It is simply not a count. `soak.sh` now takes throughput
from the server-side `hsm_requests_total` and records the sample size separately, with the
reasoning noted at the call site so nobody re-derives a rate from it.

Both bugs share a shape worth naming: a number that looks plausible and is silently
meaningless. 277 req/s is not obviously absurd, and an empty CSV column reads as "no
problem" rather than "not measured".

## What this does not cover

The run was ~45 minutes of monitored window rather than a true multi-hour soak, and it
exercised one workload — ECDSA sign over plaintext. A leak that needs hours, or one that
only appears under mTLS or on the cached-verify path, would not show here.
