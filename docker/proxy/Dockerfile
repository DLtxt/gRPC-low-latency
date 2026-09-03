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
RUN cargo build --release --locked --bins

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/proxy/target/release/proxy /usr/local/bin/proxy
COPY --from=build /app/proxy/target/release/token-check /usr/local/bin/token-check
COPY --from=build /app/proxy/target/release/provision /usr/local/bin/provision

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    LISTEN_ADDR=0.0.0.0:50051 \
    RUST_LOG=info

EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/proxy"]
