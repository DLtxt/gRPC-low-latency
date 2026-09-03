# syntax=docker/dockerfile:1
# Provisioning container: creates the SoftHSM2 token and the demo keys, then exits.
# Runs to completion before the proxy starts (docker-compose service_completed_successfully).
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc \
 && rm -rf /var/lib/apt/lists/*

COPY docker/softhsm-init/init-token.sh /usr/local/bin/init-token.sh
RUN chmod +x /usr/local/bin/init-token.sh

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    TOKEN_DIR=/var/lib/softhsm/tokens

ENTRYPOINT ["/usr/local/bin/init-token.sh"]
