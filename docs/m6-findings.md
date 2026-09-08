# M6 findings — resiliency, and a measurement I could not make

Status: **implementation complete, unit-tested, and measured on two hosts.** The exit
criterion is partly met: error rate is bounded and accepted throughput is preserved under
overload, but accepted p99 does not stay flat. See "The overload measurement, settled on
two hosts" for the numbers and why.

## What was built

**Circuit breaker** (`resilience/breaker.rs`), hand-rolled rather than taken from a crate:
`tower-circuit-breaker` is unmaintained, and a rolling-window state machine is small
enough that owning it beats carrying a dependency. Closed → open on a failure ratio over
a rolling window → half-open probe after a cooldown → closed on consecutive successes.

Two design points worth stating:

- **A minimum request count gates the ratio.** Without it the first failed request is a
  100% failure rate and trips the circuit on noise.
- **Only failures that implicate the token count.** A bad key label or a malformed
  request is the caller's fault; counting those would let one misbehaving client trip the
  circuit for everyone. `RESOURCE_EXHAUSTED` is likewise excluded — overload is a capacity
  signal, not a health signal, and tripping on it converts a busy service into an
  unavailable one.

**Per-identity rate limiting** (`resilience/ratelimit.rs`), a token bucket per workload
identity rather than per connection, because the thing worth protecting is fair share
between callers — one client opening fifty connections is still one workload.

**Transport-level admission control** in `main.rs`: `max_concurrent_streams`,
`concurrency_limit_per_connection`, and `load_shed`, all optional and configured by
environment.

Admission runs in a deliberate order: breaker (one atomic load), then authorization, then
rate limit. Cheapest rejection first, so we pay least for requests we are about to refuse.
The rate limit is checked *after* authorization so an unauthenticated caller cannot
consume a legitimate identity's tokens.

## What is verified

| Behaviour | Evidence |
|---|---|
| Breaker state machine | 6 unit tests: trips on ratio, ignores below minimum count, recovers through half-open, re-opens on failed probe, never trips while healthy |
| Rate limit accuracy | 200 rapid requests against `burst=3` → **exactly 3 OK, 197 `ResourceExhausted`** |
| Per-identity isolation | With `payments` fully throttled, `batch` served normally on the live server |
| Load shedding occurs | Shed fraction rises with offered load; rejections return `RESOURCE_EXHAUSTED` |
| Nothing regressed | All 17 unit tests pass |

## Where overload latency actually comes from

This is the useful finding, and it survives the measurement problems below because it
comes from the server's own instrumentation rather than from the load generator.

With the pool's bounded queue as the only defence, under heavy closed-loop load:

| Measurement | Value |
|---|---|
| Pool queue wait (mean) | 308 µs |
| HSM service time (mean) | 259 µs |
| p99 of **accepted** requests | ~9,000 µs |

**Roughly 97% of the latency accrued before the request reached the shedding point** — in
HTTP/2 stream handling and Tokio scheduling under contention. Queue depth barely mattered:
1 versus 64 produced 8.85 ms and 13.02 ms respectively, a 64× change in depth for a 1.5×
change in tail.

The lesson is that shedding at the pool queue protects *the pool*, not the tail. To
protect the tail the refusal has to happen upstream, before a request becomes a scheduled
task. That is what the transport-level limits are for, and they help — `max_concurrent_
streams=4` moved accepted p99 from 13.55 ms to 9.17 ms — but they do not make it flat.

## The overload measurement, settled on two hosts

The single-host attempt was abandoned: with `ghz` beside the proxy, changing only client
concurrency swung accepted p99 between 0.65 ms and 105 ms, and `mean_service_us` — pure
HSM time inside a worker, with no queueing — rose from 259 to 500 µs purely from CPU
starvation. Closed-loop load made it worse still, because fast rejections free a slot
immediately and the client simply sends more, so "capacity" becomes an artifact of how
quickly the server says no.

The numbers below come from two `c7g.2xlarge` instances in the same availability zone:
proxy on one, load generator on the other, open-loop at a fixed offered rate, 8 workers,
queue depth 16.

### Below capacity, the tail is flat

| Offered | Achieved | Shed | Accepted p50 | Accepted p99 |
|---|---|---|---|---|
| 4,000 | 3,999 | 0% | 0.29 ms | 0.48 ms |
| 8,000 | 7,999 | 0% | 0.29 ms | 0.49 ms |
| 12,000 | 11,998 | 0% | 0.31 ms | 0.56 ms |
| 16,000 | 15,997 | 0% | 0.34 ms | 0.76 ms |
| 20,000 | 19,995 | 0% | 0.42 ms | 1.15 ms |

**Capacity is ~22,000 QPS with p99 under 2 ms** — nearly double the ~11,900 measured when
the load generator shared the host. The single-host figure was measuring contention, not
the proxy.

### Above capacity, throughput plateaus and the tail degrades gracefully

| Offered | × capacity | Shed | Accepted throughput | Accepted p99 |
|---|---|---|---|---|
| 25,000 | 1.1× | 9% | ~22,700 QPS | 2.13 ms |
| 30,000 | 1.4× | 27% | ~21,900 QPS | 3.38 ms |
| 35,000 | 1.6× | 39% | ~21,300 QPS | 5.13 ms |
| 40,000 | 1.8× | 46% | ~21,700 QPS | 6.80 ms |
| 50,000 | 2.3× | 57% | ~21,500 QPS | 17.04 ms |

**Accepted throughput holds at ~21,000–22,000 QPS across a 2× range of offered load.**
That is the load shedding working: the service does not collapse, it refuses the excess
and keeps serving its capacity. Error counts are bounded and proportionate rather than
runaway.

### The exit criterion, judged honestly

plan.md asks for accepted p99 to stay *flat* at 3× capacity. It does not. It rises from
1.15 ms at capacity to 17 ms at 2.3×.

The reason is that rejection is cheap but not free. At 2.3× offered load the server is
handling ~46,000 admission decisions per second to serve ~21,500 requests; the HTTP/2
decode, task spawn, and rejection path for the other 24,500 consume CPU that accepted
requests would otherwise have. Flat accepted latency under unbounded offered load would
require rejection to cost nothing, which no in-process admission check can achieve — it
would need to happen at a load balancer or in the kernel.

So: **the first half of the criterion is met and the second is not.** Error rate is
bounded and accepted throughput is preserved, which is the property that matters
operationally. Accepted latency degrades, gradually and predictably, and stays within
2 ms only up to about 1.1× capacity.

A fair restatement for a service with this shape would be: *at 2× offered load, accepted
throughput stays within 5% of capacity and the error rate is proportionate.* That is
demonstrably true here, and it is the promise a caller actually depends on.

## Two harness bugs worth recording

`pkill -f release/proxy` matches the shell whose own command line contains that string, so
the restart loop killed itself before it could start anything, and every subsequent
measurement read 100% shed at 0.02 ms — which is what "connection refused" looks like if
you are not reading the status column carefully. Fixed by matching the process name
exactly (`pkill -x proxy`).

Running `bootstrap-linux.sh` over a foreground SSH session is fragile: a dropped
connection sends SIGHUP and kills the build midway, leaving a host that looks provisioned
but is not. The AWS security group also pins SSH to a single address, and a dynamic IP
that changes mid-run locks you out of your own instances. Long remote work should be
started with `nohup setsid`.
