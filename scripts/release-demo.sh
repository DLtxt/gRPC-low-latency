#!/usr/bin/env bash
# M11 demo: a key that signs only software releases it has checked.
#
# Starts its own proxy (mTLS on, fresh in-memory limits) on a spare port against the
# native token, then plays every side: a build system requesting release signatures,
# approvers who check the build for themselves before a stable release is signed, and a
# user verifying a download. Every step asserts its outcome, so this is also the CI
# check that the release path works end to end and that each refusal is still a refusal.
#
#   make release-demo
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
PORT="${DEMO_PORT:-50073}"
METRICS_PORT="${DEMO_METRICS_PORT:-9473}"
export PROXY_ADDR="https://localhost:${PORT}"

for binary in proxy release provision; do
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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gll-release-demo.XXXXXX")"
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
        RELEASE_POLICY=policy/releases.toml "$@" "${BIN}/proxy"
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

KEY=demo-release-key
FAILED=0

# The builds. Stand-ins for real binaries: what is signed is their SHA-256, so any
# bytes do. The tampered copy is one byte longer -- the kind of change nobody sees.
RC="${WORK}/gll-proxy-1.4.0-rc.1"
STABLE="${WORK}/gll-proxy-1.4.0"
TAMPERED="${WORK}/gll-proxy-1.4.0-tampered"
printf 'gll-proxy 1.4.0-rc.1 linux-amd64\n' >"${RC}"
printf 'gll-proxy 1.4.0 linux-amd64\n' >"${STABLE}"
{ cat "${STABLE}"; printf '\0'; } >"${TAMPERED}"

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# expect STATUS PATTERN -- CLI ARGS...
# Run the CLI, show what it printed, and check both its exit status and its output.
# The output is kept in LAST for steps that need a value from it.
expect() {
    local want_status="$1" pattern="$2"
    shift 3
    local status=0
    LAST="$("${BIN}/release" "$@" 2>&1)" || status=$?
    printf '%s\n' "${LAST}" | sed 's/^/    /'
    if [ "${status}" = "${want_status}" ] && printf '%s' "${LAST}" | grep -qE "${pattern}"; then
        printf '    \033[32m✓\033[0m %s\n' "${pattern}"
    else
        printf '    \033[31m✗ expected exit %s and /%s/, got exit %s\033[0m\n' \
            "${want_status}" "${pattern}" "${status}"
        FAILED=$((FAILED + 1))
    fi
}

field() { printf '%s\n' "${LAST}" | awk -v name="$1" '$1 == name { print $2 }'; }

sign() { expect "$1" "$2" -- --as ci sign --key "${KEY}" "${@:3}"; }
approve() { expect "$1" "$2" -- --as release-review approve --key "${KEY}" --digest "${DIGEST}" --yes "${@:3}"; }
verify() { expect "$1" "$2" -- --as ci verify --key "${KEY}" --artifact gll-proxy "${@:3}"; }

step "1. A compromised build system asks the release key to sign a digest it made up"
# Refused by authorization first: nothing is granted 'sign' on a release key. Under
# that, the token marks the key release-only and the workers refuse a blind signature
# whatever the policy says (tests/purpose_keys.rs covers that layer directly).
expect 1 "PermissionDenied" -- --as ci raw-sign --key "${KEY}" \
    --digest "$(printf 'attacker-chosen' | openssl dgst -sha256 -r | cut -d' ' -f1)"

step "1b. Nor can a policy grant it: the proxy will not start with one that tries"
sed 's/operations = \["sign_release", /operations = ["sign", "sign_release", /' \
    policy/authz.toml >"${WORK}/loosened.toml"
grep -q '"sign", "sign_release"' "${WORK}/loosened.toml"
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
    printf '    \033[31m✗ the proxy started with sign granted on a release key\033[0m\n'
    FAILED=$((FAILED + 1))
elif grep -q "granted 'sign' on release key" "${WORK}/loosened.log"; then
    grep -E "Error|granted" "${WORK}/loosened.log" | sed 's/^ */    /'
    printf '    \033[32m✓\033[0m refused to start\n'
else
    sed 's/^/    /' "${WORK}/loosened.log"
    printf '    \033[31m✗ the proxy exited, but not for the expected reason\033[0m\n'
    FAILED=$((FAILED + 1))
fi

step "2. A beta build signs at once, and the build system checks the signature itself"
sign 0 "verified +locally" --artifact gll-proxy --version 1.4.0-rc.1 --channel beta --file "${RC}"
RC_SIGNATURE="$(field signature)"

step "3. An artifact this key does not release is refused"
sign 1 "PermissionDenied.*not one this key releases" \
    --artifact evil-tool --version 1.0.0 --channel beta --file "${RC}"

step "4. So is a channel it does not publish to"
sign 1 "PermissionDenied.*not one this key publishes to" \
    --artifact gll-proxy --version 1.4.0-rc.1 --channel hotfix --file "${RC}"

step "5. A version names one file: 1.4.0-rc.1 cannot be re-signed as something else"
sign 1 "PermissionDenied.*already signed for a different file" \
    --artifact gll-proxy --version 1.4.0-rc.1 --channel beta --file "${TAMPERED}"

step "6. A user checks a download, with nothing but the public key"
verify 0 "^valid" --version 1.4.0-rc.1 --channel beta --file "${RC}" --signature "${RC_SIGNATURE}"
verify 1 "^invalid" --version 1.4.0-rc.1 --channel beta --file "${TAMPERED}" --signature "${RC_SIGNATURE}"
# The channel is signed too, so a beta build cannot pass as a stable one.
verify 1 "^invalid" --version 1.4.0-rc.1 --channel stable --file "${RC}" --signature "${RC_SIGNATURE}"

step "7. A stable release is held for two approvers, however routine"
sign 2 "PENDING_APPROVAL" --artifact gll-proxy --version 1.4.0 --channel stable --file "${STABLE}"
DIGEST="$(field digest)"

step "8. The build system cannot approve its own release"
expect 1 "PermissionDenied" -- --as ci approve --key "${KEY}" --digest "${DIGEST}" \
    --approver alice --file "${STABLE}" --yes

step "9. An approver whose copy of the build differs will not sign"
# Carol fetched the build independently. Her tool hashes her copy and compares it with
# the file the held release names, before anything is signed.
approve 1 "mismatch" --approver carol --file "${TAMPERED}"

step "10. Alice's copy matches, and she approves; one approval is not a quorum"
approve 0 "approved +as alice: 1 of 2" --approver alice --file "${STABLE}"
sign 2 "approvals +1 of 2" --artifact gll-proxy --version 1.4.0 --channel stable --file "${STABLE}"

step "11. Bob approves, and the build system collects the signature"
approve 0 "quorum reached" --approver bob --file "${STABLE}"
sign 0 "approvals +2 of 2 required" --artifact gll-proxy --version 1.4.0 --channel stable --file "${STABLE}"
verify 0 "^valid" --version 1.4.0 --channel stable --file "${STABLE}" --signature "$(field signature)"

step "12. A build system minting fresh versions runs into the hourly cap"
# Two signatures so far this hour (rc.1 and 1.4.0); the cap is 6, approved or not.
for n in 1 2 3 4; do
    printf 'gll-proxy 1.5.0-nightly.%s\n' "${n}" >"${WORK}/nightly"
    sign 0 "status +SIGNED" --artifact gll-proxy --version "1.5.0-nightly.${n}" --channel nightly --file "${WORK}/nightly"
done
printf 'gll-proxy 1.5.0-nightly.5\n' >"${WORK}/nightly"
sign 1 "ResourceExhausted.*6 releases in the last hour" \
    --artifact gll-proxy --version 1.5.0-nightly.5 --channel nightly --file "${WORK}/nightly"

step "13. What the proxy recorded"
sleep 1.2 # the pending gauge is sampled once a second
curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" \
    | grep -E '^hsm_(releases_total|releases_pending|approvals_total)' \
    | sed 's/^/    /'
echo
grep -E ' audit: ' "${LOG}" | sed -E 's/^[^ ]+ +//; s/^/    /' | cut -c1-200

echo
if [ "${FAILED}" -gt 0 ]; then
    printf '\033[31m%s step(s) did not behave as expected\033[0m\n' "${FAILED}"
    exit 1
fi
printf '\033[32mall release checks passed\033[0m\n'
