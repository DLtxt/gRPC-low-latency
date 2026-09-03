#!/usr/bin/env bash
# The full reference benchmark suite: every workload and backend that produces a
# published figure, in one pass, so a reference run is a single command and cannot
# drift from what the README claims.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPS="${REPS:-3}"
export REPS

run() {
    echo
    echo "############ $1 ############"
    shift
    env "$@" ./scripts/bench-sweep.sh
}

# ECDSA: the overhead study. The proxy, not the token, is the constraint here.
run "ECDSA - single-session baseline" \
    MODE=single KEY=demo-ec-p256 MECHANISM=SIGNATURE_MECHANISM_ECDSA_SHA256 \
    CONCURRENCIES="1 2 4 8 12 16 24"

run "ECDSA - worker pool" \
    MODE=pool KEY=demo-ec-p256 MECHANISM=SIGNATURE_MECHANISM_ECDSA_SHA256 \
    CONCURRENCIES="1 2 4 8 12 16 24 32 48"

# RSA: the pooling headline. The token is genuinely the constraint.
run "RSA-2048 - single-session baseline" \
    MODE=single KEY=demo-rsa-2048 MECHANISM=SIGNATURE_MECHANISM_RSA_PKCS_SHA256 \
    REQUESTS=4000 CONCURRENCIES="1 2 4 8 16"

run "RSA-2048 - worker pool" \
    MODE=pool KEY=demo-rsa-2048 MECHANISM=SIGNATURE_MECHANISM_RSA_PKCS_SHA256 \
    REQUESTS=8000 CONCURRENCIES="1 2 4 8 12 16 24 32"

# The token's own ceiling, with no gRPC in the path, so proxy overhead and token
# limits are never confused for one another.
echo
echo "############ token ceiling (no gRPC) ############"
./proxy/target/release/hsm-ceiling | tee "results/$(./scripts/host-info.sh | awk -F'"' '/host_kind/{print $4}')/ceiling-$(date -u +%Y%m%dT%H%M%SZ).txt"

echo
echo "reference suite complete. Results in results/"
