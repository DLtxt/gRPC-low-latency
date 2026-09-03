#!/bin/sh
# Initialize the SoftHSM2 token if it does not exist yet, then run the spike.
# Idempotent: re-running the container reuses the existing token.
set -eu

TOKEN_LABEL="${TOKEN_LABEL:-grpc-low-latency}"
SO_PIN="${SO_PIN:-0000}"
USER_PIN="${USER_PIN:-1234}"

mkdir -p /var/lib/softhsm/tokens

# Labels are space-padded to 32 chars, so strip trailing whitespace before matching.
if softhsm2-util --show-slots 2>/dev/null \
    | sed -n 's/^[[:space:]]*Label:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p' \
    | grep -Fxq "${TOKEN_LABEL}"; then
    echo "token '${TOKEN_LABEL}' already initialized"
else
    echo "initializing token '${TOKEN_LABEL}'"
    softhsm2-util --init-token --free \
        --label "${TOKEN_LABEL}" \
        --so-pin "${SO_PIN}" \
        --pin "${USER_PIN}"
fi

exec spike
