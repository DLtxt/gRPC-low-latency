#!/usr/bin/env bash
# Run the proxy in the foreground for a two-host benchmark.
#
# Exists so the server host runs exactly the configuration the client is measuring
# against, with nothing else competing for CPU -- no load generator, no build.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. ./scripts/lib-common.sh

export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$PWD/.local/softhsm/softhsm2.conf}"
export PKCS11_MODULE="$(find_pkcs11_module)"
export PATH="$HOME/.cargo/bin:$PATH"

# Listen on all interfaces so the client host can reach it.
export LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:50051}"
export PROXY_MODE="${PROXY_MODE:-pool}"
export PROXY_TLS="${PROXY_TLS:-off}"
export HSM_WORKERS="${HSM_WORKERS:-8}"
export HSM_QUEUE_DEPTH="${HSM_QUEUE_DEPTH:-16}"
export RUST_LOG="${RUST_LOG:-info}"

if [ -f ./.env ]; then
    set -a; . ./.env; set +a
fi

echo "[server] workers=${HSM_WORKERS} queue_depth=${HSM_QUEUE_DEPTH} tls=${PROXY_TLS}"
exec ./proxy/target/release/proxy
