# M6 findings — resiliency, and a measurement I could not make

Status: **implementation complete and unit-tested. The headline overload claim is not
verified**, because this laptop cannot measure it. See "What could not be measured".

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

## What could not be measured

plan.md's exit criterion is "at 3× capacity, accepted-request p99 stays flat while
rejections rise." I could not establish whether that holds, and the reason is
methodological rather than incidental.

**The load generator shares eight cores with the proxy.** Under overload `ghz` is itself
a heavy CPU consumer, so the experiment measures the two processes competing rather than
the server's behaviour. The evidence that this dominates:

- Changing only client concurrency, with the server configuration identical, moved
  accepted p99 between 0.65 ms and 105 ms across runs.
- `mean_service_us` — pure HSM time inside the worker, with no queueing — rose from 259 µs
  to 500 µs as client concurrency increased. The token did not get slower; the server was
  being starved of CPU by the client.
- Closed-loop and open-loop load produced contradictory pictures of the same server.
  Closed-loop is actively misleading here: fast rejections return quickly, so `ghz`
  immediately sends more, and the measured "capacity" collapses to an artifact.

One open-loop sweep did show the desired shape — accepted p99 flat at 0.65–1.22 ms from
1× to 3× offered load while shedding rose — but a neighbouring sweep with different client
concurrency showed the opposite, so it is not a result, it is a coincidence pending
confirmation.

**This also qualifies the reference runs.** Those measured throughput at p99 below
saturation, where client contention is modest and the ARM/x86 agreement to 3.3% suggests
it was not distorting them. But every reference figure was likewise produced with `ghz` on
the proxy's own host, and no overload figure from that setup should be trusted.

## What is needed to finish M6

A two-host benchmark: proxy on one instance, load generator on another, in the same
placement group so network latency stays low and predictable. Until then the resiliency
mechanisms are verified as *correct* — they trip, shed, limit, and isolate exactly as
specified — but their effect on tail latency under overload is unquantified.

`scripts/bench-sweep.sh` assumes it starts the proxy itself, so this needs a
client-and-server split rather than a new flag. That is the next piece of harness work.
