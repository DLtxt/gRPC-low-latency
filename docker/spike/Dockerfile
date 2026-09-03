# syntax=docker/dockerfile:1
# M0 spike image: builds the cryptoki spike and runs it against a freshly
# initialized SoftHSM2 token in the same container.
#
# PKCS#11 is an in-process C API, so libsofthsm2.so must live in the *runtime*
# image, loaded into the spike's own address space (see plan.md 4.1).

FROM rust:1-bookworm AS build
WORKDIR /app/proxy
COPY proxy/Cargo.toml proxy/Cargo.lock ./
COPY proxy/src ./src
RUN cargo build --release --locked --bin spike

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/proxy/target/release/spike /usr/local/bin/spike
COPY docker/spike/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    TOKEN_LABEL=grpc-low-latency \
    SO_PIN=0000 \
    SPIKE_ITERATIONS=5000 \
    USER_PIN=1234

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
