# plan.md — `gRPC-low-latency`

A stateless gRPC cryptographic proxy in front of a PKCS#11 HSM (SoftHSM2), with mTLS
workload authentication, a blocking-safe session worker pool, in-memory caching, and
load-shedding. Runs entirely locally at zero cost.

**Primary language: Rust.** Go is used for the benchmark harness, the direct-PKCS#11
baseline, and an admin CLI (details in §3).

---

## 1. Goals and non-goals

### Goals

1. Serve `Sign`, `Verify`, `Encrypt`, `Decrypt`, and `GetPublicKey` over gRPC, backed by
   PKCS#11.
2. Never block the Tokio reactor on a synchronous C call.
3. Authenticate every caller with mTLS and authorize per-key based on the client
   certificate identity.
4. Degrade gracefully under overload: bounded queues, rate limiting, circuit breaking,
   explicit `RESOURCE_EXHAUSTED` instead of unbounded latency growth.
5. Produce a reproducible benchmark comparing a naive direct-PKCS#11 client against the
   proxy, with a Grafana dashboard and a committed methodology.
6. `git clone && docker compose up` gives a working system with a populated dashboard.

### Non-goals

- Production key management, backup, or attestation. SoftHSM2 is a software token; it is
  not a real HSM and the README must say so plainly.
- Multi-node clustering or replication. The proxy is stateless; scale is horizontal and
  out of scope for the demo.
- Custom crypto. Every primitive comes from the PKCS#11 module or `rustls`.

### Success criteria

| # | Criterion |
|---|---|
| S1 | ECDSA P-256 sign sustained ≥ 4,000 QPS, p99 ≤ 5 ms, 0 errors, 5 min soak |
| S2 | Cached verify sustained ≥ 8,000 QPS, p99 ≤ 2 ms, 0 errors, 5 min soak |
| S3 | At 2× saturation, error rate is bounded and p99 of *accepted* requests stays flat |
| S4 | Baseline harness reproduces the "naive" number on the same hardware |
| S5 | `docker compose up` → Grafana dashboard with live data, no manual steps |
| S6 | CI runs `cargo test`, `cargo clippy -D warnings`, `go test ./...`, and a smoke bench |

---

## 2. Honest benchmarking policy (read this before writing the README)

The headline "400 → 8,000 QPS" is achievable, but only if the comparison is stated
precisely. Two effects are being conflated, and a reviewer who knows this domain will
notice immediately.

- **Pooling and concurrency** is a real, defensible speedup. A single-session,
  single-threaded PKCS#11 client serializes on one session; a pool of N sessions on N
  threads scales close to linearly until SoftHSM2's CPU cost per operation dominates.
- **Caching public keys** converts `Verify` from an HSM round trip into an in-process
  `ring`/`rustls` verification. That is a genuine architectural win, but it is not the HSM
  going faster — it is the HSM being removed from the path.

**Therefore the README reports three workloads separately, never a single blended number:**

| Workload | HSM in path? | What it demonstrates |
|---|---|---|
| `sign` (ECDSA P-256) | Yes, every request | Worker pool throughput and queueing |
| `verify` (cached pubkey) | No, after first fetch | Cache effectiveness |
| `mixed` 70/30 verify/sign | Partially | Realistic service profile |

A blended number may appear *in addition*, labeled as such. Private key material is never
cached — it never leaves the token, and `Sign` always hits the HSM. State this in the
README; it is the single most important credibility sentence in the whole repo.

**Benchmark table template** (fill after §7; delete placeholder rows):

| Metric | Direct PKCS#11 (1 session, serial) | Proxy — sign | Proxy — verify (cached) |
|---|---|---|---|
| Throughput | _TBD_ QPS | _TBD_ QPS | _TBD_ QPS |
| p50 latency | _TBD_ | _TBD_ | _TBD_ |
| p99 latency | _TBD_ | _TBD_ | _TBD_ |
| Concurrency model | Single session, blocking | N-session pool + async gRPC | Pool + in-process verify |
| Error rate at 1× | _TBD_ | _TBD_ | _TBD_ |

Record hardware, kernel, Docker version, CPU count, SoftHSM2 version, and the exact `ghz`
invocation alongside every table. Benchmarks without a methodology section are noise.

---

## 3. Language split

Rust owns the service. Go earns its place by doing work Rust would do worse or redundantly.

**Rust — `proxy/`**
- gRPC server (`tonic`), async runtime (`tokio`), PKCS#11 FFI (`cryptoki`), cache (`moka`),
  middleware (`tower`), metrics (`metrics` + `metrics-exporter-prometheus`).

**Go — `bench/`, `baseline/`, `cmd/hsmctl/`**
1. **`baseline/`** — the "before" number. A Go program using `github.com/miekg/pkcs11`
   that opens one session and signs in a loop. This is deliberately naive and deliberately
   *not* Rust: writing the baseline in a different language kills the objection that the
   comparison is really "bad Rust vs good Rust."
2. **`bench/`** — `ghz` is the primary driver (it is itself Go). A custom `grpc-go` client
   covers what `ghz` cannot: mixed read/write ratios in one run, cache-cold vs cache-warm
   phases, mTLS cert rotation mid-run, and slow-drain shutdown behavior.
3. **`cmd/hsmctl/`** — a small `cobra` CLI for provisioning: create key pairs, list labels,
   export public keys, exercise the admin RPCs. Useful in demos and CI setup scripts.

If time is short, cut `hsmctl` first. Keep `baseline/` — it is load-bearing for the story.

---

## 4. Architecture

### 4.1 The SoftHSM2 container: a correction to the obvious design

PKCS#11 is an **in-process C API**. There is no network protocol and SoftHSM2 ships no
daemon. The proxy cannot "connect to a SoftHSM container" — it must `dlopen`
`libsofthsm2.so` inside its own address space.

The resolution:

- A `softhsm-init` container builds the token: `softhsm2-util --init-token --free --label
  grpc-low-latency --so-pin ... --pin ...`, then generates the demo keys and exits.
- The token directory lives on a named Docker volume (`softhsm-tokens`).
- The **proxy image also installs `libsofthsm2.so`** and mounts the same volume at
  `/var/lib/softhsm/tokens`. The proxy loads the module directly.
- `softhsm-init` uses `restart: "no"`; the proxy has `depends_on: { condition:
  service_completed_successfully }`.

**Only one runtime process may write the token dir.** SoftHSM2 uses file locking, but
concurrent multi-container writers are a good way to corrupt a token. The proxy is the
only runtime user; `hsmctl` talks to the proxy over gRPC, not to the token directly.

Document this in the README with a diagram. Explaining *why* the naive design does not work
is exactly the kind of detail that separates a portfolio piece from a tutorial.

> Rejected alternative: `pkcs11-proxy` (Nitrokey) exposes PKCS#11 over TCP and would allow a
> true network-separated HSM container. It is effectively unmaintained and adds an
> unencrypted-by-default hop. Note it in the README as considered-and-rejected; that
> paragraph is worth more than the feature.

### 4.2 Request path

```
client ──mTLS──▶ tonic server
                    │
                    ├─ AuthN layer: verify chain, extract SPIFFE-style URI SAN
                    ├─ AuthZ layer: (identity, key_label, operation) → allow/deny
                    ├─ RateLimit layer: per-identity token bucket (governor)
                    ├─ CircuitBreaker layer: trip on pool timeouts / HSM errors
                    ├─ Concurrency limit: bounded in-flight, load-shed on full
                    │
                    ├─▶ CACHE HIT (moka) ─── verify / get_public_key ──▶ respond
                    │
                    └─▶ dispatch: mpsc ──▶ [worker 0..N] each owning one CK_SESSION_HANDLE
                                              │  blocking C_Sign / C_Decrypt
                                              └─ oneshot ──▶ respond
```

### 4.3 The worker pool (the core of the project)

**Do not use `tokio::task::spawn_blocking`.** Its pool is unbounded-ish, threads are not
pinned, and a PKCS#11 session handle cannot safely migrate between threads under concurrent
use. Backpressure is also invisible to you, which defeats the point.

Design:

- N dedicated OS threads (`std::thread::spawn`), N ≈ `num_cpus`, tunable. Each thread owns
  exactly one `cryptoki::session::Session` for its entire life. The session never moves.
- A single bounded `flume` (or `crossbeam-channel`) MPMC channel of `Job { req,
  responder: oneshot::Sender<Result<Resp>> }`. All workers receive from it. Bounded depth
  is the backpressure signal.
- Async handler: `tx.try_send(job)` → on `Full`, immediately return
  `Status::resource_exhausted`. Then `.await` the oneshot with a timeout.
- Initialize once at startup: `C_Initialize` with `CKF_OS_LOCKING_OK`. Log in once —
  PKCS#11 login state is per-token for the application, not per-session, so a single
  `C_Login(CKU_USER)` covers all workers. Verify this against SoftHSM2's behavior in an
  integration test; do not assume it.
- **Object handles are session-scoped.** Each worker keeps its own
  `HashMap<KeyLabel, ObjectHandle>` populated lazily via `C_FindObjects`. Do not share
  handles across sessions. This per-worker handle cache is a large part of the speedup —
  `C_FindObjects` on every request is a common and expensive mistake.
- Health: a worker that hits `CKR_DEVICE_ERROR` or `CKR_SESSION_HANDLE_INVALID` closes and
  reopens its session, re-logs in if needed, clears its handle map, and reports to the
  circuit breaker.
- Graceful shutdown: close the channel, drain in-flight, `C_Logout`, `C_CloseAllSessions`,
  `C_Finalize`.

Instrument: queue depth, queue wait time, per-op HSM service time, worker utilization.
Queue wait vs. service time is the graph that makes the whole design legible on a dashboard.

### 4.4 Cache

`moka::future::Cache`, keyed by `(key_label, artifact_kind)`.

| Cached | TTL | Notes |
|---|---|---|
| Public keys (SPKI DER) | 5 min | Enables in-process verify |
| X.509 certs | 5 min | Parsed and pre-validated |
| Key handle → attributes | 5 min | Mechanism list, key size |
| Negative lookups (label not found) | 30 s | Stops cache-miss stampedes on bad input |

Never cached: private keys, signatures, plaintext, decrypt results, PINs.

Use `try_get_with` for single-flight so a cold key under 5,000 QPS produces one HSM lookup,
not 5,000. Demonstrating the stampede fix (with a benchmark of cache-cold ramp) is a strong
detail.

Expose `hsm_cache_hits_total` / `hsm_cache_misses_total` / `hsm_cache_entries` and put hit
ratio on the dashboard.

### 4.5 mTLS and authorization

- `mkcert` generates a local CA, one server cert (`localhost`, `grpc-low-latency`), and per-client
  certs. Certs are generated by `scripts/gen-certs.sh` into `certs/` and **gitignored** —
  commit the script, never the keys. CI regenerates them.
- `tonic` server configured with `ServerTlsConfig::client_ca_root(...)`, requiring client
  auth. Reject unauthenticated connections at the TLS layer, not in the handler.
- Identity extraction: pull the peer cert from `request.extensions()`, parse with `x509-parser`,
  read the URI SAN (`spiffe://local/ns/default/sa/payments`). Fall back to CN with a warning.
- Authorization: a TOML policy file mapping identity → allowed `(key_label, operation)`
  pairs. Hot-reload with `notify` is a nice-to-have; startup-load is sufficient.
- Emit `hsm_authz_denied_total{identity, key_label, op}`.

This is the "microservice security" part of the pitch. A policy file with three workloads,
one of which is denied in the demo script, sells it better than a paragraph of prose.

### 4.6 Resiliency

- **Rate limiting**: `tower_governor` or `governor` directly, per-identity keyed. Returns
  `RESOURCE_EXHAUSTED` with a `retry-after` trailer.
- **Concurrency limit**: `tower::limit::ConcurrencyLimitLayer` plus
  `tower::load_shed::LoadShedLayer`. Shed, do not queue. Unbounded queueing is the classic
  p99 killer and you should say so in the README.
- **Circuit breaker**: `tower-circuit-breaker` is unmaintained; prefer `failsafe` or a
  ~120-line `tower::Layer` you own. Rolling-window failure ratio → open → half-open probe →
  closed. Writing it yourself is better portfolio material and removes a dependency risk.
- **Timeouts**: per-request deadline honored from gRPC metadata; independent worker-job
  timeout. Never wait forever on a oneshot.
- **Retries**: none on `Sign`. Signing is not idempotent in a way you can reason about
  under partial failure. Retry only `GetPublicKey`. Say why.

---

## 5. Repository layout

```
gRPC-low-latency/
├── README.md                  # architecture, benchmarks + methodology, quickstart
├── plan.md
├── docker-compose.yml
├── Makefile                   # make certs / up / bench / dash / clean
├── proto/
│   └── hsm/v1/hsm.proto
├── proxy/                     # Rust
│   ├── Cargo.toml
│   ├── build.rs               # tonic-build
│   └── src/
│       ├── main.rs
│       ├── config.rs          # figment/config + clap
│       ├── grpc/{mod.rs,service.rs,interceptors.rs}
│       ├── pkcs11/{mod.rs,pool.rs,worker.rs,session.rs,errors.rs}
│       ├── cache/mod.rs
│       ├── authz/{mod.rs,policy.rs,identity.rs}
│       ├── resilience/{breaker.rs,ratelimit.rs}
│       └── telemetry/{metrics.rs,tracing.rs}
├── baseline/                  # Go: naive direct-PKCS#11 client
│   ├── main.go
│   └── go.mod
├── bench/                     # Go: custom load generator + ghz configs
│   ├── main.go
│   ├── scenarios/{sign.json,verify.json,mixed.json}
│   └── run.sh
├── cmd/hsmctl/                # Go: admin CLI
├── docker/
│   ├── softhsm-init/{Dockerfile,init-token.sh}
│   └── proxy/Dockerfile       # multi-stage; runtime installs libsofthsm2
├── deploy/
│   ├── prometheus/prometheus.yml
│   └── grafana/provisioning/{datasources,dashboards}/
├── scripts/gen-certs.sh
├── policy/authz.toml
└── .github/workflows/ci.yml
```

---

## 6. Milestones

Estimates assume focused evening/weekend work. Each milestone ends with something
demonstrable — resist the urge to build the whole thing before running it once.

### M0 — Spike (~half a day)
Prove the risky part first: a Rust binary that loads `libsofthsm2.so` via `cryptoki`, logs
in, and signs once. If `cryptoki` fights you on your platform, you want to know now, not in
week three.
- **Exit:** one successful ECDSA signature printed to stdout.

### M1 — SoftHSM in Docker + provisioning (~1 day)
`softhsm-init` image, token volume, key generation for `demo-rsa-2048`, `demo-ec-p256`,
`demo-aes-256`. Proxy container proves it can open the shared token read-write.
- **Exit:** `docker compose up softhsm-init` is idempotent and reproducible from scratch.

### M2 — Proto + gRPC skeleton (~1 day)
Define the service; implement handlers that call a single session behind a `Mutex`. Slow
and correct. This is your first honest datapoint.
- **Exit:** `grpcurl` gets a real signature. Record the QPS — this is the "single session"
  column.

### M3 — Worker pool (~2 days)
Replace the mutex with the N-thread/N-session pool, bounded channel, per-worker handle
cache, health checks, graceful shutdown.
- **Exit:** throughput scales with N on `ghz`; publish a QPS-vs-workers curve. That curve
  is one of the best figures in the repo — it shows where SoftHSM2's own CPU cost takes
  over.

### M4 — mTLS + authorization (~1.5 days)
`gen-certs.sh`, tonic TLS config, identity extraction, policy file, denied-workload demo.
- **Exit:** three client certs; one is denied for `demo-rsa-2048` and the metric increments.

### M5 — Cache (~1 day)
`moka` with single-flight, TTLs, negative caching, in-process verify path, cache metrics.
- **Exit:** verify QPS jumps by ~an order of magnitude; hit ratio visible on the dashboard.

### M6 — Resiliency (~1.5 days)
Rate limiter, concurrency limit + load shed, hand-rolled circuit breaker, deadlines.
- **Exit:** at 3× capacity, accepted-request p99 stays flat while rejections rise. Chart it.

### M7 — Observability (~1 day)
Prometheus exporter, histogram buckets tuned to sub-ms, `tracing` spans, provisioned
Grafana dashboard committed as JSON.
- **Exit:** `docker compose up` → dashboard renders with live data, zero clicks.

### M8 — Benchmarks + baseline (~2 days)
Go baseline, `ghz` scenarios, `bench/run.sh` writing CSV/JSON to `results/`, a small script
that renders the README table so numbers are never hand-typed.
- **Exit:** `make bench` regenerates every number in the README.

### M9 — Polish (~1.5 days)
Architecture diagram, methodology section, threat-model note, SoftHSM-is-not-an-HSM
disclaimer, CI, screenshots, 90-second demo GIF.
- **Exit:** a stranger can understand and run the project in five minutes.

**Total: ~13–14 focused days.** Ship M0–M5 as v0.1 if time runs out; that alone is a
credible project.

---

## 7. Benchmark protocol

Run everything on one machine, all containers pinned, nothing else running.

**Setup**
- Record: CPU model, physical core count, RAM, kernel, Docker version, SoftHSM2 version,
  Rust and Go versions.
- Pin CPUs in compose (`cpuset`) so the load generator cannot starve the proxy. Give the
  proxy N cores and the generator its own. Note the split in the README — an unpinned
  benchmark on a laptop is not reproducible.
- 30-second warm-up discarded. 5-minute measurement window. Three runs; report median and
  spread, not the best run.

**Scenarios**

| Name | Driver | Description |
|---|---|---|
| `baseline-serial` | Go `baseline/` | 1 session, 1 goroutine, sequential ECDSA sign |
| `baseline-naive-concurrent` | Go `baseline/` | 50 goroutines sharing 1 mutexed session |
| `proxy-sign` | `ghz` | ECDSA P-256 sign, concurrency sweep 1→512 |
| `proxy-sign-rsa` | `ghz` | RSA-2048 sign (expect much lower — report it anyway) |
| `proxy-verify-warm` | `ghz` | Cached public key verify |
| `proxy-verify-cold` | `bench/` | Cache-cold ramp, shows single-flight working |
| `proxy-mixed` | `bench/` | 70/30 verify/sign |
| `proxy-overload` | `ghz` | 3× capacity, measures shed behavior |
| `soak` | `bench/` | 60 min at 80% capacity, watch RSS and p99 drift |

Include `baseline-naive-concurrent`. It is the most intellectually honest comparison — it
shows that adding threads to a single session does not help, which is precisely the problem
the pool solves.

**Reporting**
- p50 / p90 / p99 / p99.9 and max. Never mean alone.
- Error counts by gRPC status code.
- Proxy CPU and RSS during the run.
- The concurrency sweep as a chart (throughput and p99 vs. concurrency), so the knee is visible.

---

## 8. Testing

- **Unit (Rust)**: policy evaluation, cache key derivation, circuit breaker state machine
  (drive it with a fake clock), identity parsing from synthetic certs.
- **Integration (Rust)**: `#[tokio::test]` against a real SoftHSM token created in a
  `tempdir` fixture — no mock PKCS#11. Cover pool saturation, session recovery after forced
  invalidation, graceful shutdown mid-flight, and TLS rejection of an unknown CA.
- **Property**: sign→verify round-trip across mechanisms and payload sizes (`proptest`).
- **Go**: baseline and bench have `go test ./...`; keep them honest with a smoke test that
  runs 100 requests in CI.
- **CI**: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo deny check`,
  `go vet`, `go test`, then `docker compose up -d && ghz --total 1000` as a smoke bench.

---

## 9. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| `cryptoki` API friction or build issues | Blocks everything | M0 spike first; fallback to the `pkcs11` crate or thin `bindgen` wrapper |
| SoftHSM2 CPU cost caps sign throughput below target | Headline number misses | Lead with ECDSA not RSA; report both; be explicit that the cap is the software token, and show the QPS-vs-workers curve flattening |
| Login/session semantics differ from spec reading | Subtle runtime bugs | Integration test asserts actual behavior at startup |
| Shared token volume corruption | Data loss, flaky demos | Single runtime writer; init container exits before proxy starts |
| Benchmark reads as dishonest | Undermines the whole piece | §2 policy; separate workloads; commit raw results and the exact commands |
| Scope creep (OTel, k8s, multi-HSM) | Never ships | Stretch-goals section stays a section |
| Committed certs or PINs | Security embarrassment on a *security* project | `.gitignore` + `gitleaks` in CI; PIN via env/Docker secret, never in compose defaults |

---

## 10. Stretch goals (only after M9)

- OpenTelemetry traces with spans across queue wait and HSM service time; Tempo in compose.
- `ristretto` cache variant in a Go port of the proxy, benchmarked head-to-head. This is the
  cleanest way to add more Go without diluting the Rust core, and a Rust-vs-Go writeup on
  the same workload is genuinely interesting.
- Key rotation with versioned labels and a zero-downtime cutover demo.
- SPIFFE/SPIRE instead of static mkcert identities.
- `k6` or `vegeta` cross-check to confirm `ghz` is not the bottleneck at high QPS — worth
  doing if you ever measure above ~10k QPS from a single generator.

---

## 11. Definition of done

- [ ] `git clone && make certs && docker compose up` works on a clean machine
- [ ] README has an architecture diagram, the three-workload benchmark table, and a full
      methodology section
- [ ] README states clearly that SoftHSM2 is a software token, not an HSM
- [ ] README explains why `Sign` is never cached and why the SoftHSM container is not a
      network service
- [ ] Grafana dashboard committed as provisioned JSON, populated on first boot
- [ ] `make bench` regenerates every number in the README from raw results
- [ ] CI green: fmt, clippy, tests, `cargo deny`, `go vet`, `go test`, smoke bench
- [ ] No secrets, PINs, or certificates in git history
