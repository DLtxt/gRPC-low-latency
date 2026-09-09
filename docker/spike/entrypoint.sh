#!/bin/sh
# Initialize the SoftHSM2 token if it does not exist yet, then run the spike.
# Idempotent: re-running the container reuses the existing token.
set -eu

TOKEN_LABEL="${TOKEN_LABEL:-grpc-low-latency}"

# Generated per container rather than baked into the image. The token here is a
# throwaway created inside the container and discarded with it, so the PIN protects
# nothing -- but a literal PIN in a tracked file is a pattern worth not teaching, and
# a project about key protection is the last place to ship one.
rand_pin() { LC_ALL=C tr -dc '0-9' < /dev/urandom | head -c 8; }
SO_PIN="${SO_PIN:-$(rand_pin)}"
USER_PIN="${USER_PIN:-$(rand_pin)}"
export USER_PIN

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
