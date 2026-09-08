# syntax=docker/dockerfile:1
# Provisioning container: creates the SoftHSM2 token and the demo keys, then exits.
# Runs to completion before the proxy starts (service_completed_successfully).
#
# Key generation uses the project's own `provision` binary rather than OpenSC's
# pkcs11-tool, so the container token and the native development token are created by
# identical code. Two provisioning paths would drift on CKA_SENSITIVE and
# CKA_EXTRACTABLE -- the attributes this project can least afford to get wrong in one
# place and right in the other.

FROM rust:1-bookworm AS build
WORKDIR /app
COPY proto ./proto
COPY proxy/Cargo.toml proxy/Cargo.lock ./proxy/
COPY proxy/build.rs ./proxy/
COPY proxy/src ./proxy/src
WORKDIR /app/proxy
ENV CARGO_BUILD_JOBS=4
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/proxy/target,sharing=locked \
    cargo build --release --locked --bin provision \
 && mkdir -p /out && cp target/release/provision /out/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/provision /usr/local/bin/provision
COPY docker/softhsm-init/init-token.sh /usr/local/bin/init-token.sh
RUN chmod +x /usr/local/bin/init-token.sh

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    TOKEN_DIR=/var/lib/softhsm/tokens

ENTRYPOINT ["/usr/local/bin/init-token.sh"]
