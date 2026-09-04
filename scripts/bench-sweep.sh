#!/usr/bin/env bash
# Sweep offered concurrency against one proxy backend and report the throughput at
# which p99 is still under the latency budget.
#
# That budget is the project's actual goal, and it cannot be read off a peak-QPS
# number: throughput is bought with concurrency, concurrency queues requests, and
# queueing destroys the tail. The number that matters is the highest sustained
# throughput whose p99 still fits, so this script reports exactly that.
#
# Refuses to run against a server it did not start, because benchmarking a stale
# process on the same port silently produces numbers for the wrong binary.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

MODE="${MODE:-pool}"
WORKERS="${HSM_WORKERS:-8}"
QUEUE_DEPTH="${HSM_QUEUE_DEPTH:-64}"
KEY="${KEY:-demo-ec-p256}"
MECHANISM="${MECHANISM:-SIGNATURE_MECHANISM_ECDSA_SHA256}"
REQUESTS="${REQUESTS:-20000}"
CONCURRENCIES="${CONCURRENCIES:-1 2 4 8 12 16 24 32 48 64 128}"
BUDGET_MS="${BUDGET_MS:-2.0}"
# p99 near the budget boundary flips between runs, so a single sample decides the
# headline number by coin toss. plan.md 7 asks for three runs and a median; this is
# that, applied per cell rather than only to the final figure.
REPS="${REPS:-3}"
PORT="${PORT:-50051}"
CONNECTIONS="${CONNECTIONS:-8}"
# TLS is part of the measurement, not a detail: mTLS lands in the hot path, so its cost
# comes out of the same 2 ms budget as everything else.
TLS="${TLS:-off}"
CLIENT_IDENTITY="${CLIENT_IDENTITY:-payments}"
# Which RPC to drive. Defaults to Sign; CALL and DATA let the same harness measure
# Verify, whose whole point after M5 is that it never reaches the token.
CALL="${CALL:-hsm.v1.HsmService/Sign}"

. ./scripts/lib-common.sh
PKCS11_MODULE="$(find_pkcs11_module)"
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-${REPO}/.local/softhsm/softhsm2.conf}"

if port_in_use "${PORT}"; then
    echo "ERROR: something is already listening on port ${PORT}." >&2
    echo "       Refusing to benchmark a server this script did not start." >&2
    exit 1
fi

# BSD mktemp accepts a bare prefix after -t; GNU requires X's in the template.
# Spell the template out so this works on macOS and Linux alike.
LOG="$(mktemp "${TMPDIR:-/tmp}/bench-proxy.XXXXXX")"
PKCS11_MODULE="${PKCS11_MODULE}" \
TOKEN_LABEL="${TOKEN_LABEL:-grpc-low-latency}" \
USER_PIN="${USER_PIN:-1234}" \
LISTEN_ADDR="0.0.0.0:${PORT}" \
PROXY_MODE="${MODE}" \
PROXY_TLS="${TLS}" \
HSM_WORKERS="${WORKERS}" \
HSM_QUEUE_DEPTH="${QUEUE_DEPTH}" \
RUST_LOG="${RUST_LOG:-info}" \
    ./proxy/target/release/proxy > "${LOG}" 2>&1 &
PROXY_PID=$!

cleanup() {
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 50); do
    port_in_use "${PORT}" && break
    kill -0 "${PROXY_PID}" 2>/dev/null || { echo "proxy died on startup:"; cat "${LOG}"; exit 1; }
    sleep 0.2
done

HOST_JSON="$(./scripts/host-info.sh)"
HOST_KIND="$(printf '%s' "${HOST_JSON}" | awk -F'"' '/host_kind/{print $4}')"
INSTANCE="$(printf '%s' "${HOST_JSON}" | awk -F'"' '/instance_type/{print $4}')"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="results/${HOST_KIND}"
RESULT_FILE="${RESULT_DIR}/${STAMP}-${MODE}-w${WORKERS}-tls${TLS}-${CALL##*/}-${KEY}.json"
mkdir -p "${RESULT_DIR}"

echo "mode=${MODE} workers=${WORKERS} queue_depth=${QUEUE_DEPTH} key=${KEY} tls=${TLS} call=${CALL##*/}"
echo "host: ${HOST_KIND}${INSTANCE:+ (${INSTANCE})}"
echo "budget: p99 < ${BUDGET_MS} ms   (median of ${REPS} runs per cell)"
# Errors are shown, not just tested. A shed request is answered fast, so a run that
# rejects most of its load reports a *higher* QPS than one that serves it -- an error
# column is the only thing that stops that reading as a win.
printf '%-6s %-12s %-11s %-11s %-11s %-13s %-9s %-8s\n' \
    conc QPS p50 p95 "p99(med)" "p99 min-max" errors within
printf '%.0s-' {1..90}; echo

if [ "${TLS}" = "on" ]; then
    GHZ_TRANSPORT=(--cacert certs/ca.crt
                   --cert "certs/${CLIENT_IDENTITY}.crt"
                   --key "certs/${CLIENT_IDENTITY}.key"
                   --cname localhost)
else
    GHZ_TRANSPORT=(--insecure)
fi

median() { printf '%s\n' "$@" | sort -g | awk '{v[NR]=$1} END{print v[int((NR+1)/2)]}'; }
spread() { printf '%s\n' "$@" | sort -g | awk '{v[NR]=$1} END{printf "%s-%s", v[1], v[NR]}'; }

PAYLOAD="$(printf 'benchmark payload' | base64)"
# Built with an explicit conditional rather than ${DATA:-...}: the default is JSON,
# and the first closing brace inside it would terminate the parameter expansion.
if [ -z "${DATA:-}" ]; then
    DATA="{\"key_label\":\"${KEY}\",\"mechanism\":\"${MECHANISM}\",\"input\":{\"message\":\"${PAYLOAD}\"}}"
fi
BEST_QPS=0
BEST_CONC=0
ROWS=""

for CONC in ${CONCURRENCIES}; do
    # ghz refuses --connections greater than --concurrency.
    CONNS=$(( CONNECTIONS < CONC ? CONNECTIONS : CONC ))

    QPS_SAMPLES=(); P50_SAMPLES=(); P95_SAMPLES=(); P99_SAMPLES=(); ERR_TOTAL=0

  for _rep in $(seq 1 "${REPS}"); do
    OUT="$(ghz "${GHZ_TRANSPORT[@]}" \
        --proto proto/hsm/v1/hsm.proto --import-paths proto \
        --call "${CALL}" -d "${DATA}" \
        -c "${CONC}" -n "${REQUESTS}" --connections "${CONNS}" \
        "127.0.0.1:${PORT}" 2>&1)"

    # ghz prints latencies in whatever unit fits; normalise to milliseconds.
    read -r QPS P50 P95 P99 ERRORS <<<"$(printf '%s' "${OUT}" | awk '
        function ms(v, u) { return (u == "us") ? v/1000 : (u == "s") ? v*1000 : v }
        /Requests\/sec:/ { qps = $2 }
        /^  50 %/       { p50 = ms($4, $5) }
        /^  95 %/       { p95 = ms($4, $5) }
        /^  99 %/       { p99 = ms($4, $5) }
        /^  \[/         { if ($1 != "[OK]") errs += $2 }
        END { printf "%.0f %.3f %.3f %.3f %d", qps, p50, p95, p99, errs+0 }')"

    QPS_SAMPLES+=("${QPS}"); P50_SAMPLES+=("${P50}")
    P95_SAMPLES+=("${P95}"); P99_SAMPLES+=("${P99}")
    ERR_TOTAL=$(( ERR_TOTAL + ERRORS ))
  done

    QPS="$(median "${QPS_SAMPLES[@]}")"
    P50="$(median "${P50_SAMPLES[@]}")"
    P95="$(median "${P95_SAMPLES[@]}")"
    P99="$(median "${P99_SAMPLES[@]}")"
    P99_SPREAD="$(spread "${P99_SAMPLES[@]}")"
    ERRORS="${ERR_TOTAL}"

    WITHIN=no
    if awk "BEGIN{exit !(${P99} < ${BUDGET_MS})}" && [ "${ERRORS}" -eq 0 ]; then
        WITHIN=yes
        if awk "BEGIN{exit !(${QPS} > ${BEST_QPS})}"; then
            BEST_QPS="${QPS}"; BEST_CONC="${CONC}"
        fi
    fi

    printf '%-6s %-12s %-11s %-11s %-11s %-13s %-9s %-8s\n' \
        "${CONC}" "${QPS}" "${P50}ms" "${P95}ms" "${P99}ms" "${P99_SPREAD}" "${ERRORS}" "${WITHIN}"

    ROWS="${ROWS}${ROWS:+,}
    {\"concurrency\": ${CONC}, \"qps\": ${QPS}, \"p50_ms\": ${P50}, \"p95_ms\": ${P95},
     \"p99_ms\": ${P99}, \"p99_spread_ms\": \"${P99_SPREAD}\", \"errors\": ${ERRORS},
     \"within_budget\": ${WITHIN/yes/true}}"
done

ROWS="${ROWS//no\}/false\}}"

cat > "${RESULT_FILE}" <<JSON
{
  "host": ${HOST_JSON},
  "run": {
    "mode": "${MODE}",
    "tls": "${TLS}",
    "workers": ${WORKERS},
    "queue_depth": ${QUEUE_DEPTH},
    "call": "${CALL}",
    "key_label": "${KEY}",
    "mechanism": "${MECHANISM}",
    "requests_per_cell": ${REQUESTS},
    "repetitions_per_cell": ${REPS},
    "budget_p99_ms": ${BUDGET_MS},
    "ghz_command": "ghz --insecure --proto proto/hsm/v1/hsm.proto --import-paths proto --call hsm.v1.HsmService/Sign -c <conc> -n ${REQUESTS} --connections <min(${CONNECTIONS},conc)> 127.0.0.1:${PORT}"
  },
  "rows": [${ROWS}
  ],
  "result": {
    "max_qps_within_budget": ${BEST_QPS},
    "at_concurrency": ${BEST_CONC}
  }
}
JSON

echo
if [ "${BEST_CONC}" -eq 0 ]; then
    echo "RESULT: never met p99 < ${BUDGET_MS} ms at any tested concurrency."
else
    echo "RESULT: ${BEST_QPS} QPS sustained with p99 < ${BUDGET_MS} ms (at concurrency ${BEST_CONC})"
fi
echo "saved:  ${RESULT_FILE}"
if [ "${HOST_KIND}" != "reference" ]; then
    echo "NOTE:   local host -- not eligible for published figures (see results/REFERENCE.md)"
fi
