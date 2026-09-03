# syntax=docker/dockerfile:1
# The proxy image. PKCS#11 is an in-process C API with no network protocol, so
# libsofthsm2.so must be installed in the *runtime* image and loaded into the
# proxy's own address space -- the proxy cannot "connect to a SoftHSM container".
# It shares the token directory with softhsm-init via a named volume (plan.md 4.1).

FROM rust:1-bookworm AS build
WORKDIR /app/proxy
COPY proxy/Cargo.toml proxy/Cargo.lock ./
COPY proxy/src ./src
RUN cargo build --release --locked --bins

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*

# Run unprivileged. The token volume is chowned by the compose entrypoint ordering;
# softhsm-init runs as root and leaves the tokens group-readable via umask 0077,
# so the proxy runs as root for now and drops privileges once M2 fixes ownership.
COPY --from=build /app/proxy/target/release/token-check /usr/local/bin/token-check

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

ENTRYPOINT ["/usr/local/bin/token-check"]
