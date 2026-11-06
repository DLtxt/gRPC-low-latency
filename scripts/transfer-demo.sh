#!/usr/bin/env bash
# M10 demo: a key that signs only transfers it has checked.
#
# Starts its own proxy (mTLS on, fresh in-memory limits) on a spare port against the
# native token, then plays both sides: a payments service requesting transfers, and
# treasury approvers reviewing the ones that are held. Every step asserts its outcome,
# so this is also the CI check that the transfer path works end to end and that each
# refusal is still a refusal.
#
#   make transfer-demo
#
# Needs the release binaries (cd proxy && cargo build --release --bins), a provisioned
# native token, and .env. Certificates and approver keys are created if missing.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. ./scripts/lib-common.sh

if [ -f ./.env ]; then
    set -a; . ./.env; set +a
fi
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$PWD/.local/softhsm/softhsm2.conf}"
export PKCS11_MODULE="$(find_pkcs11_module)"
export CERT_DIR="${CERT_DIR:-$PWD/certs}"
export APPROVER_KEY_DIR="${APPROVER_KEY_DIR:-$PWD/.local/approvers}"

BIN="${BIN_DIR:-proxy/target/release}"
PORT="${DEMO_PORT:-50071}"
METRICS_PORT="${DEMO_METRICS_PORT:-9471}"
export PROXY_ADDR="https://localhost:${PORT}"

for binary in proxy transfer provision; do
    if [ ! -x "${BIN}/${binary}" ]; then
        echo "missing ${BIN}/${binary}: run (cd proxy && cargo build --release --bins)" >&2
        exit 1
    fi
done
for port in "${PORT}" "${METRICS_PORT}"; do
    if port_in_use "${port}"; then
        echo "port ${port} is in use; set DEMO_PORT / DEMO_METRICS_PORT" >&2
        exit 1
    fi
done

./scripts/gen-certs.sh >/dev/null
"${BIN}/provision" >/dev/null

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gll-transfer-demo.XXXXXX")"
LOG="${WORK}/proxy.log"
PROXY_PID=
stop() {
    if [ -n "${PROXY_PID}" ]; then
        kill "${PROXY_PID}" 2>/dev/null || true
        wait "${PROXY_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORK}"
}
trap stop EXIT

# NO_COLOR keeps the log greppable; the audit lines are pulled out of it at the end.
# exec, so that when this runs in the background, $! is the proxy itself rather than
# a subshell that would leave the proxy running when killed.
start_proxy() {
    exec env PROXY_TLS=on PROXY_MODE=pool HSM_WORKERS=2 NO_COLOR=1 RUST_LOG=info \
        TRANSFER_POLICY=policy/transfers.toml "$@" "${BIN}/proxy"
}

start_proxy LISTEN_ADDR="127.0.0.1:${PORT}" METRICS_ADDR="127.0.0.1:${METRICS_PORT}" \
    AUTHZ_POLICY=policy/authz.toml >"${LOG}" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 30); do
    port_in_use "${PORT}" && break
    if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
        echo "the proxy exited during startup:" >&2
        cat "${LOG}" >&2
        exit 1
    fi
    sleep 0.5
done

KEY=demo-transfer-key
RESERVE=0xc01dc01dc01dc01dc01dc01dc01dc01dc01dc01d
ATTACKER=0xbadbadbadbadbadbadbadbadbadbadbadbadbad0
FAILED=0

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# expect STATUS PATTERN -- CLI ARGS...
# Run the CLI, show what it printed, and check both its exit status and its output.
# The output is kept in LAST for steps that need a value from it.
expect() {
    local want_status="$1" pattern="$2"
    shift 3
    local status=0
    LAST="$("${BIN}/transfer" "$@" 2>&1)" || status=$?
    printf '%s\n' "${LAST}" | sed 's/^/    /'
    if [ "${status}" = "${want_status}" ] && printf '%s' "${LAST}" | grep -qE "${pattern}"; then
        printf '    \033[32m✓\033[0m %s\n' "${pattern}"
    else
        printf '    \033[31m✗ expected exit %s and /%s/, got exit %s\033[0m\n' \
            "${want_status}" "${pattern}" "${status}"
        FAILED=$((FAILED + 1))
    fi
}

sign() { expect "$1" "$2" -- --as payments sign --key "${KEY}" --chain devnet --asset ETH "${@:3}"; }
approve() { expect "$1" "$2" -- --as treasury approve --key "${KEY}" --digest "${DIGEST}" --yes "${@:3}"; }

step "1. A compromised caller asks the transfer key to sign a digest it made up"
# Refused by authorization first: nothing is granted 'sign' on a transfer key. Under
# that, the token marks the key transfer-only and the workers refuse a blind signature
# whatever the policy says (tests/purpose_keys.rs covers that layer directly).
expect 1 "PermissionDenied" -- --as payments raw-sign --key "${KEY}" \
    --digest "$(printf 'attacker-chosen' | openssl dgst -sha256 -r | cut -d' ' -f1)"

step "1b. Nor can a policy grant it: the proxy will not start with one that tries"
sed 's/operations = \["sign_transfer", /operations = ["sign", "sign_transfer", /' \
    policy/authz.toml >"${WORK}/loosened.toml"
grep -q '"sign", "sign_transfer"' "${WORK}/loosened.toml"
start_proxy LISTEN_ADDR="127.0.0.1:$((PORT + 1))" METRICS_ADDR="127.0.0.1:$((METRICS_PORT + 1))" \
    AUTHZ_POLICY="${WORK}/loosened.toml" >"${WORK}/loosened.log" 2>&1 &
LOOSENED_PID=$!
for _ in $(seq 1 20); do
    kill -0 "${LOOSENED_PID}" 2>/dev/null || break
    sleep 0.25
done
if kill -0 "${LOOSENED_PID}" 2>/dev/null; then
    kill "${LOOSENED_PID}"
    wait "${LOOSENED_PID}" 2>/dev/null || true
    printf '    \033[31m✗ the proxy started with sign granted on a transfer key\033[0m\n'
    FAILED=$((FAILED + 1))
elif grep -q "granted 'sign' on transfer key" "${WORK}/loosened.log"; then
    grep -E "Error|granted" "${WORK}/loosened.log" | sed 's/^ */    /'
    printf '    \033[32m✓\033[0m refused to start\n'
else
    sed 's/^/    /' "${WORK}/loosened.log"
    printf '    \033[31m✗ the proxy exited, but not for the expected reason\033[0m\n'
    FAILED=$((FAILED + 1))
fi

step "2. A small transfer to an allowlisted account signs at once"
sign 0 "status +SIGNED" --to "${RESERVE}" --amount 1.5 --nonce 1

step "3. Any address off the allowlist is refused, whatever the amount"
sign 1 "PermissionDenied.*not on the allowlist" --to "${ATTACKER}" --amount 0.01 --nonce 2

step "4. Above the per-transfer cap is refused outright; approval cannot lift it"
sign 1 "PermissionDenied.*per-transfer cap" --to "${RESERVE}" --amount 300 --nonce 3

step "5. A large transfer is held for two approvers"
sign 2 "PENDING_APPROVAL" --to "${RESERVE}" --amount 25 --nonce 4
DIGEST="$(printf '%s\n' "${LAST}" | awk '$1 == "digest" { print $2 }')"

step "6. The requester cannot approve its own transfer"
expect 1 "PermissionDenied" -- --as payments approve --key "${KEY}" --digest "${DIGEST}" \
    --approver alice --yes

step "7. An approval signed with the wrong key does not count"
approve 1 "PermissionDenied.*does not verify" --approver alice \
    --approver-key "${APPROVER_KEY_DIR}/bob.key"

step "8. Alice approves; one approval is not a quorum"
approve 0 "approved +as alice: 1 of 2" --approver alice
sign 2 "approvals +1 of 2" --to "${RESERVE}" --amount 25 --nonce 4

step "9. Bob approves, and the requester collects the signature"
approve 0 "quorum reached" --approver bob
sign 0 "approvals +2 of 2 required" --to "${RESERVE}" --amount 25 --nonce 4

step "10. Approvals are spent: the same transfer again starts from zero"
sign 2 "approvals +0 of 2" --to "${RESERVE}" --amount 25 --nonce 4

step "11. Small transfers that add up are held once the hour's budget would pass"
# 1.5 + 25 have been signed this hour; the auto-sign budget is 50 ETH.
sign 0 "status +SIGNED" --to "${RESERVE}" --amount 9 --nonce 5
sign 0 "status +SIGNED" --to "${RESERVE}" --amount 9 --nonce 6
sign 2 "auto-sign budget" --to "${RESERVE}" --amount 9 --nonce 7

step "12. What the proxy recorded"
sleep 1.2 # the outflow gauge is sampled once a second
curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" \
    | grep -E '^hsm_(transfers_total|transfers_pending|transfer_outflow_last_hour|approvals_total)' \
    | sed 's/^/    /'
echo
grep -E ' audit: ' "${LOG}" | sed -E 's/^[^ ]+ +//; s/^/    /' | cut -c1-200

echo
if [ "${FAILED}" -gt 0 ]; then
    printf '\033[31m%s step(s) did not behave as expected\033[0m\n' "${FAILED}"
    exit 1
fi
printf '\033[32mall transfer checks passed\033[0m\n'
