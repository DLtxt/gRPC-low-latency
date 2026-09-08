# syntax=docker/dockerfile:1
# The proxy image. PKCS#11 is an in-process C API with no network protocol, so
# libsofthsm2.so must be installed in the *runtime* image and loaded into the
# proxy's own address space -- the proxy cannot "connect to a SoftHSM container".
# It shares the token directory with softhsm-init via a named volume (plan.md 4.1).

FROM rust:1-bookworm AS build
WORKDIR /app
COPY proto ./proto
COPY proxy/Cargo.toml proxy/Cargo.lock ./proxy/
COPY proxy/build.rs ./proxy/
COPY proxy/src ./proxy/src
WORKDIR /app/proxy
# Cap codegen parallelism. The default is one job per core, and eight concurrent rustc
# processes linking ring, rsa, axum and tower exhaust the memory Docker Desktop gives
# its VM, which surfaces as "frontend grpc server closed unexpectedly" -- a BuildKit
# crash rather than a compile error, so it reads like an infrastructure fault.
#
# Four is the compromise: eight exhausts the VM, two takes over forty minutes.
ENV CARGO_BUILD_JOBS=4
# Cache mounts so the dependency tree is compiled once rather than on every image
# build. Without them a one-line source change recompiles ring, rsa and hyper.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/proxy/target,sharing=locked \
    cargo build --release --locked --bins \
 && mkdir -p /out \
 && cp target/release/proxy target/release/token-check target/release/provision /out/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*

# Copied from /out rather than target/, because target/ is a cache mount and its
# contents are not present in the layer once the RUN step ends.
COPY --from=build /out/proxy /usr/local/bin/proxy
COPY --from=build /out/token-check /usr/local/bin/token-check
COPY --from=build /out/provision /usr/local/bin/provision

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    LISTEN_ADDR=0.0.0.0:50051 \
    RUST_LOG=info

EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/proxy"]
