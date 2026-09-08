#!/usr/bin/env bash
# The full reference benchmark suite: every workload and backend that produces a
# published figure, in one pass, so a reference run is a single command and cannot
# drift from what the README claims.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPS="${REPS:-3}"
export REPS

# hsm-ceiling talks to the token directly, so it needs the module path resolved the
# same way the sweep resolves it -- the built-in default is Debian's and is wrong on
# Amazon Linux, which uses lib64.
. ./scripts/lib-common.sh
PKCS11_MODULE="$(find_pkcs11_module)"
export PKCS11_MODULE

HOST_KIND="$(./scripts/host-info.sh | awk -F'"' '/host_kind/{print $4}')"
mkdir -p "results/${HOST_KIND}"

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

# Cached verify: M5's headline workload, and the only one where the token is absent
# from the path entirely. Needs a valid signature first, which means grpcurl -- ghz
# reports statuses but not response bodies, so it cannot mint one itself.
if command -v grpcurl >/dev/null 2>&1; then
    echo
    echo "############ ECDSA verify - cached public key ############"
    PAYLOAD="$(printf 'benchmark payload' | base64)"
    PROBE_PORT=50052

    PROXY_TLS=off PROXY_MODE=pool HSM_WORKERS=4 LISTEN_ADDR="127.0.0.1:${PROBE_PORT}" \
        ./proxy/target/release/proxy >/tmp/gll-signer.log 2>&1 &
    SIGNER_PID=$!
    sleep 3

    SIG="$(grpcurl -plaintext \
        -d "{\"keyLabel\":\"demo-ec-p256\",\"mechanism\":\"SIGNATURE_MECHANISM_ECDSA_SHA256\",\"input\":{\"message\":\"${PAYLOAD}\"}}" \
        "127.0.0.1:${PROBE_PORT}" hsm.v1.HsmService/Sign 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["signature"])')"

    kill "${SIGNER_PID}" 2>/dev/null || true
    wait "${SIGNER_PID}" 2>/dev/null || true

    if [ -n "${SIG}" ]; then
        MODE=pool HSM_WORKERS=4 REQUESTS=20000 \
        CALL=hsm.v1.HsmService/Verify \
        CONCURRENCIES="4 8 12 16 24 32 48" \
        DATA="{\"key_label\":\"demo-ec-p256\",\"mechanism\":\"SIGNATURE_MECHANISM_ECDSA_SHA256\",\"input\":{\"message\":\"${PAYLOAD}\"},\"signature\":\"${SIG}\"}" \
            ./scripts/bench-sweep.sh
    else
        echo "SKIPPED: could not obtain a signature to verify against"
    fi
else
    echo
    echo "############ ECDSA verify - SKIPPED (grpcurl not installed) ############"
    echo "install grpcurl to include M5's cached-verify workload in the suite"
fi

# The token's own ceiling, with no gRPC in the path, so proxy overhead and token
# limits are never confused for one another.
echo
echo "############ token ceiling (no gRPC) ############"
./proxy/target/release/hsm-ceiling \
    | tee "results/${HOST_KIND}/ceiling-$(date -u +%Y%m%dT%H%M%SZ).txt"

echo
echo "reference suite complete. Results in results/"
