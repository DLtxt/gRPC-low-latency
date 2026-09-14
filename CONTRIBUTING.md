# Working in this repository

Conventions that are easy to get wrong here, and what they exist to prevent.

## Scripts anchor themselves to the repository root

Every script under `scripts/` resolves the repository root from its own location before
doing anything, rather than trusting the caller's working directory:

```bash
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
```

```python
REPO = pathlib.Path(__file__).resolve().parent.parent
```

The reason is that relative paths fail *quietly* in this repository, in a way that looks
like a different problem entirely.

The tree has a Rust crate in `proxy/`, a Go module in `baseline/`, and shared assets at
the root — `certs/`, `results/`, `proto/`, `docs/`. Ordinary work moves between them
constantly, because `cargo` wants `proxy/` and `go` wants `baseline/` while the benchmark
harness and the proto definitions live at the top. A shell that is one directory away from
where a script assumes it is will:

- write `.env` into `proxy/`, after which `docker compose` reports the PINs as unset;
- render the demo GIF to `proxy/docs/demo.gif`, leaving the README's image stale with no
  error anywhere;
- report `certs/` and `scripts/` as missing, which reads exactly like a deleted directory
  rather than a mislocated shell.

That last failure mode is the one worth guarding against. A missing-file error is
indistinguishable from a real problem, so the wrong diagnosis is the natural one: you go
looking for what deleted the directory instead of noticing you are standing in the wrong
place. Anchoring removes the class of bug rather than requiring everyone to remember.

Two exceptions, both deliberate:

- `scripts/lib-common.sh` is sourced, not executed, so it inherits the caller's directory
  by design.
- `docker/*/­*.sh` run inside containers against absolute paths that the image controls.

When adding a script, anchor it. When running one ad hoc, prefer an absolute path over
assuming where the last command left you.

## Benchmark results are only meaningful with their conditions

Anything under `results/` carries the host that produced it: CPU model, core count,
kernel, toolchain versions, the commit, and whether the tree was dirty. Results from the
pinned reference instances land in `results/reference/` and are tracked; everything else
goes to `results/local/` and is ignored.

`best_results.md` is the running record. After a benchmark run, compare against it with
`make records` and update anything beaten. A figure only replaces a record if it was
measured under conditions at least as trustworthy — the ranking rules are in that file.

## One PKCS#11 pool per process

`C_Initialize` and `C_Finalize` are process-global. Two live `Pool` instances tear down
each other's module state, and the survivor then uses handles that `C_Finalize` has
already invalidated, which surfaces as a segfault rather than an error. The proxy binary
creates exactly one pool; the integration tests serialise construction behind a mutex.

Relatedly, `cryptoki::Session` is `Send` but deliberately not `Sync`: a session permits
one active operation at a time. Share one through a `Mutex`, never through an
`unsafe impl Sync`.

## Tests

```bash
cd proxy && cargo test          # unit, integration, and property tests
cd baseline && go test ./...    # baseline
```

Integration and property tests build a disposable SoftHSM token in a temporary directory
and skip with a message when SoftHSM2 is not installed, so `cargo test` stays usable
without it.

## Before pushing

```bash
cd proxy && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cd baseline && go vet ./... && go test ./...
```

CI runs these plus `cargo-deny`, `gitleaks`, and two smoke tests — one that drives 1,000
requests through the real gRPC stack, and one that asserts an under-privileged identity is
*denied*. The second matters: a smoke test that only checks the happy path would not
notice authorization silently failing open.

Never commit `certs/`, `.env`, or anything under `.local/`. All three are gitignored, and
CI fails on tracked key material.
